/*
// Copyright (c) 2022 Intel Corporation
//
// This software and the related documents are Intel copyrighted
// materials, and your use of them is governed by the express license
// under which they were provided to you ("License"). Unless the
// License provides otherwise, you may not use, modify, copy, publish,
// distribute, disclose or transmit this software or the related
// documents without Intel's prior written permission.
//
// This software and the related documents are provided as is, with no
// express or implied warranties, other than those that are expressly
// stated in the License.
*/

#include "spdmapplib.hpp"
#include "spdmtransport_mctp.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <iostream>
#include <unordered_set>

extern spdm_app_lib::SPDMConfiguration getConfigurationFromEntityManager(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationName);

static std::shared_ptr<boost::asio::io_context> ioc =
    std::make_shared<boost::asio::io_context>();
static std::shared_ptr<sdbusplus::asio::connection> conn =
    std::make_shared<sdbusplus::asio::connection>(*ioc);
static auto trans = std::make_shared<spdm_transport::SPDMTransportMCTP>(
    ioc, conn, mctpw::BindingType::mctpOverSmBus);
static spdm_app_lib::SPDMConfiguration spdmResponderCfg{};
static boost::asio::steady_timer interfaceCheckTimer(*ioc);
static bool bResponderStarted = false;
static bool bCheckTimerStarted = false;

using ConfigurationField =
    std::variant<bool, uint64_t, std::string, std::vector<uint64_t>>;

using ConfigurationMap = std::unordered_map<std::string, ConfigurationField>;

static const std::string spdmTypeName =
    "xyz.openbmc_project.Configuration.SPDMConfiguration";

static const std::string ifcTypeName = "xyz.openbmc_project.MCTP.Binding.SMBus";

static std::unordered_set<std::string> startedUnits;
/**
 * @brief find if required dbus interface has created
 *
 * @return true : found, false : not found
 */

static bool
    findRequiredMCTPInterface(std::shared_ptr<sdbusplus::asio::connection> conn,
                              mctpw::BindingType mediaType)
{
    std::map<mctpw::BindingType, const std::string> supportInterfaceTable = {
        {mctpw::BindingType::mctpOverSmBus,
         "xyz.openbmc_project.MCTP.Binding.SMBus"},
        {mctpw::BindingType::mctpOverPcieVdm,
         "xyz.openbmc_project.MCTP.Binding.PCIe"},
    };
    auto ifcItem = supportInterfaceTable.find(mediaType);

    if (ifcItem == supportInterfaceTable.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "findRequiredMCTPInterface error, not supported Type !");
        return false;
    }

    auto methodCall = conn->new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

    methodCall.append("/xyz/openbmc_project", 1,
                      std::array<std::string, 1>({ifcItem->second}));

    auto reply = conn->call(methodCall);
    std::vector<std::string> paths;
    reply.read(paths);
    return paths.size() > 0 ? true : false;
}

/**
 * @brief get path of SPDM configuration in entitymanager
 *
 * @return vector of path
 */

static std::vector<std::string> getConfigurationPaths()
{
    auto methodCall = conn->new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

    methodCall.append("/xyz/openbmc_project/inventory/system/board", 2,
                      std::array<std::string, 1>({spdmTypeName}));

    auto reply = conn->call(methodCall);
    std::vector<std::string> paths;
    reply.read(paths);
    return paths;
}

/**
 * @brief read SPDM configuration from entitymanager when rule matched.
 *
 * @param spdmConfig Assigned configuration name.
 */

static void startReadingConfigurations(std::string& spdmConfig)
{
    if (spdmResponderCfg.version)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "startReadingConfigurations: SPDM responder configuration has loaded.");
        return;
    }
    std::vector<std::string> configurationPaths;
    try
    {
        configurationPaths = getConfigurationPaths();
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Could not retrieve existing configurations: ") +
             e.what())
                .c_str());
        return;
    }

    for (const auto& objectPath : configurationPaths)
    {
        if (startedUnits.count(objectPath) != 0)
        {
            continue;
        }
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            (std::string("Found config: ") + objectPath).c_str());

        if (objectPath.find(spdmConfig) != objectPath.npos)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Matched : " + spdmConfig + "! Reading configuration from" +
                 objectPath)
                    .c_str());
            spdmResponderCfg =
                getConfigurationFromEntityManager(conn, spdmConfig);
            if (spdmResponderCfg.version)
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "startReadingConfigurations: SPDM responder configuration has loaded..");
                return;
            }
        }
    }
}

/**
 * @brief The SPDM responder initial function. When called will enter daemon
 * mode.
 *
 */

static void startSPDMResponder()
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Staring SPDM responder!!");
    bResponderStarted = true;
    static auto spdmResponder = std::make_shared<spdm_app_lib::SPDMResponder>(
        ioc, conn, trans, spdmResponderCfg);
    trans->initDiscovery([&](spdm_transport::TransportEndPoint eidPoint,
                             spdm_transport::Event event) {
        if (event == spdm_transport::Event::added)
        {
            /*
                Do not take any action here as a responder.
                When Asyc messages arrive, necessary action will be taken
                in spdmapplib
            */
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "SPDM device Added");
        }
        else if (event == spdm_transport::Event::removed)
        {
            spdmResponder->updateSPDMPool(eidPoint);
        }
    });
}

void startResponderWorker()
{
    if (bCheckTimerStarted)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "startResponderWorker: SPDM Responder checkTimer started!");
    }
    bCheckTimerStarted = true;
    if (bResponderStarted)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "startResponderWorker: SPDM Responder started!");
        return;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "startResponderWorker!");
    if (findRequiredMCTPInterface(conn, mctpw::BindingType::mctpOverSmBus))
    { // make sure interface is ready
        startSPDMResponder();
    }
    else
    { // wait for another check.
        constexpr std::chrono::seconds retryInterval(1);
        interfaceCheckTimer.expires_after(retryInterval);
        interfaceCheckTimer.async_wait(
            [&](const boost::system::error_code& ec) {
                if (ec == boost::asio::error::operation_aborted)
                {
                    return; // we're being canceled
                }
                startResponderWorker();
            });
    }
}

int main(void)
{
    std::string responderConfigName{"SPDM_responder"};

    spdmResponderCfg.version = 0x10;
    spdmResponderCfg.certPath = "/usr/share/spdmd/sample_keys";
    spdmResponderCfg.capability = 0x001afbf7;
    spdmResponderCfg.hash = 0x00000002;
    spdmResponderCfg.asym = 0x00000090;
    spdmResponderCfg.measHash = 0x00000008;
    spdmResponderCfg.reqasym = 0x0000000f;
    spdmResponderCfg.dhe = 0x0000001b;
    spdmResponderCfg.aead = 0x00000006;
    spdmResponderCfg.slotcount = 0x3;

    phosphor::logging::log<phosphor::logging::level::INFO>("Use DEBUG config.");

    std::vector<std::string> units;
    startReadingConfigurations(responderConfigName);

    if (spdmResponderCfg.version)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "SPDM responder configuration got!");
        startResponderWorker();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDM responder configuration not found!!");
    }

    namespace rules = sdbusplus::bus::match::rules;
    auto match = std::make_unique<sdbusplus::bus::match::match>(
        *conn,
        "type='signal',member='InterfacesAdded',sender='" +
            std::string("xyz.openbmc_project.EntityManager") + "'",
        [&units, &responderConfigName](sdbusplus::message::message& message) {
            if (message.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Callback method error");
                return;
            }
            if (bResponderStarted)
            {
                return;
            }
            sdbusplus::message::object_path unitPath;
            std::unordered_map<std::string, ConfigurationMap> interfacesAdded;
            try
            {
                message.read(unitPath, interfacesAdded);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Message read error");
                return;
            }

            for (const auto& interface : interfacesAdded)
            {
                if (bResponderStarted)
                {
                    return;
                }
                if (interface.first != spdmTypeName)
                {
                    continue;
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Config found by match rule! startReadingConfigurations ...");
                startReadingConfigurations(responderConfigName);
                if (spdmResponderCfg.version)
                {
                    if (bCheckTimerStarted == false)
                    {
                        phosphor::logging::log<phosphor::logging::level::DEBUG>(
                            "Execute startResponderWorker() in match rule.");
                        startResponderWorker();
                    }
                }
            }
        });

    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&](const boost::system::error_code&, const int&) { ioc->stop(); });

    ioc->run();
    return 0;
}
