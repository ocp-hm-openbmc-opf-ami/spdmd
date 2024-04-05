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

#include "spdm_config_reader.hpp"
#include "spdmapplib.hpp"
#include "spdmtransport_mctp.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <iostream>

int main(void)
{
    std::shared_ptr<boost::asio::io_context> ioc =
        std::make_shared<boost::asio::io_context>();
    std::shared_ptr<sdbusplus::asio::connection> conn =
        std::make_shared<sdbusplus::asio::connection>(*ioc);
    spdm_app_lib::SPDMConfiguration spdmConfig{};
    try
    {
        SPDMConfigReader spdmConfigFetcher(spdmConfig);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Could not retrieve existing configurations: ") +
             e.what())
                .c_str());
    }
    auto trans = std::make_shared<spdm_transport::SPDMTransportMCTP>(
        ioc, conn, mctpw::BindingType::mctpOverSmBus, true);
    auto spdmResponder = std::make_shared<spdm_app_lib::SPDMResponder>(
        ioc, conn, trans, spdmConfig);
    trans->initDiscovery([&](spdm_transport::TransportEndPoint eidPoint,
                             spdm_transport::Event event) {
        if (event == spdm_transport::Event::added)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "SPDM device Added");
        }
        else if (event == spdm_transport::Event::removed)
        {
            spdmResponder->updateSPDMPool(eidPoint);
        }
    });

    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&](const boost::system::error_code&, const int&) { ioc->stop(); });

    ioc->run();
    return 0;
}
