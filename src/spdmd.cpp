/**
 * Copyright © 2022 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitation
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
static bool bResponderStarted = false;

using ConfigurationField =
    std::variant<bool, uint64_t, std::string, std::vector<uint64_t>>;

using ConfigurationMap = std::unordered_map<std::string, ConfigurationField>;

static const std::string spdmTypeName =
    "xyz.openbmc_project.Configuration.SPDMConfiguration";

static const std::string ifcTypeName = "xyz.openbmc_project.MCTP.Binding.SMBus";

static std::unordered_set<std::string> startedUnits;

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

        if (spdmResponderCfg.version)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "startReadingConfigurations, SPDM responder configuration had loaded.");
            return;
        }
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
                    "SPDM responder configuration has loaded.");
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
    phosphor::logging::log<phosphor::logging::level::ERR>(
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

int main(void)
{
    std::string responderConfigName{"SPDM_responder"};

    std::vector<std::string> units;
    startReadingConfigurations(responderConfigName);

    if (spdmResponderCfg.version)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "SPDM responder configuration got!");
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDM responder configuration not found!!");
    }

    namespace rules = sdbusplus::bus::match::rules;
    auto match = std::make_unique<sdbusplus::bus::match::match>(
        *conn,
        rules::interfacesAdded() + rules::path_namespace("/") +
            rules::sender("xyz.openbmc_project.EntityManager"),
        [&units, &responderConfigName](sdbusplus::message::message& message) {
            if (message.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Callback method error");
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
                if (interface.first != spdmTypeName)
                {
                    continue;
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Config found by match rule!");
                if (spdmResponderCfg.version)
                {
                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        "SPDM responder confiruation has loaded before.");
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        "Reading SPDM responder configuration.");
                    startReadingConfigurations(responderConfigName);
                }
            }
        });

    static const std::string matchRule =
        "type='signal',member='InterfacesAdded',interface='org.freedesktop."
        "DBus.ObjectManager',path='/xyz/openbmc_project/"
        "mctp'";
    auto mctpInterfacesAddedMatch = std::make_unique<
        sdbusplus::bus::match::match>(
        *conn, matchRule,
        [&responderConfigName](sdbusplus::message::message& message) {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Callback of new MCTP services match rule");
            if (message.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "mctpInterfacesAddedMatch Callback method error");
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
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    ("interfacesAdded: " + interface.first).c_str());
                if (interface.first != ifcTypeName)
                {
                    continue;
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Found matcher interface: " + interface.first).c_str());
                if (spdmResponderCfg.version && !bResponderStarted)
                {
                    startSPDMResponder();
                }
                else
                {
                    startReadingConfigurations(responderConfigName);
                }
            }
        });

    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&](const boost::system::error_code&, const int&) { ioc->stop(); });

    ioc->run();
    return 0;
}
