/**
 * Copyright © 2020 Intel Corporation
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
 * limitations under the License.
 */

#include "spdmapplib.hpp"

#include <boost/asio.hpp>

#include <iostream>
int main()
{

    boost::asio::io_context io;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait(
        [&io](const boost::system::error_code&, const int&) { io.stop(); });

    SPDMAPPLib applib(io, nullptr, nullptr);

    std::vector<mctpw::eid_t> result;

    uint32_t i;

    printf("Test function: GetEndpointMap \n");
    result = applib.getEndpointMap();
    printf("result:  \n");
    for (i = 0; i < result.size(); i++)
    {
        printf("EID : %x \n", result[i]);
        printf("     Status : %s\n",
               applib.getEndpointStatus(result[i]).c_str());
    }
    printf("\n");

    io.run();
    return 0;
}
