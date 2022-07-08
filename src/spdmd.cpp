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

#include <iostream>

extern spdmapplib::spdmConfiguration getConfigurationFromEntityManager(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationName);

int main(void)
{

    auto ioc = std::make_shared<boost::asio::io_context>();
    auto conn = std::make_shared<sdbusplus::asio::connection>(*ioc);
    auto trans = std::make_shared<spdmtransport::spdmTransportMCTP>(
        spdmtransport::TransportIdentifier::mctpOverSMBus);
    auto pSpdmResponder = spdmapplib::createResponder();
    spdmapplib::spdmConfiguration spdmResponderCfg;
    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc->stop(); });
    do
    {
        spdmResponderCfg =
            getConfigurationFromEntityManager(conn, "SPDM_responder");
        if (spdmResponderCfg.version)
        {
            break;
        }
        else
        {
            std::cerr
                << "Can't get SPDM responder configuration from EntityManager. Wait for 1 second."
                << std::endl;
            sleep(1);
        }
    } while (true);
    std::cerr << "spdm_responder start init. " << std::endl;
    if (pSpdmResponder->initResponder(ioc, conn, trans, &spdmResponderCfg))
    {
        std::cerr << "spdm_responder start failed." << std::endl;
        return -1;
    }
    else
    {
        std::cerr << "spdm_responder started." << std::endl;
        ioc->run();
        return 0;
    }
}
