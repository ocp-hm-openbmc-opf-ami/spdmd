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

#pragma once
#include "mctp_wrapper.hpp"

#include <stdio.h>

#include <sdbusplus/asio/connection.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

class SPDMAPPLib
{
    using ReceiveCallback =
        std::function<void(boost::system::error_code, mctpw::ByteArray&)>;
    using SendCallback = std::function<void(boost::system::error_code, int)>;

  public:
    /**
     * @brief Construct a new SPDMAPPLib object
     *
     * @param ioContext boost io_context object. Usable if invoker is an sdbus
     * unaware app.
     * @param networkChangeCb Callback to be executed when a network change
     * occurs in the system. For example a new device is inserted or removed etc
     * @param rxCb Callback to be executed when new MCTP message is
     * received.
     */
    SPDMAPPLib(boost::asio::io_context& ioContext,
               const mctpw::ReconfigurationCallback& networkChangeCb,
               const mctpw::ReceiveMessageCallback& rxCb);
    /**
     * @brief Construct a new SPDMAPPLib object
     *
     * @param ioContext boost io_context object. Usable if invoker is an sdbus
     * unaware app.
     * @param networkChangeCb Callback to be executed when a network change
     * occurs in the system. For example a new device is inserted or removed etc
     * @param rxCb Callback to be executed when new MCTP message is
     * received.
     */
    SPDMAPPLib(std::shared_ptr<sdbusplus::asio::connection> conn,
               const mctpw::ReconfigurationCallback& networkChangeCb,
               const mctpw::ReceiveMessageCallback& rxCb);
    /**
     * @brief Get status EndpointMap
     *
     * @return std::string status
     */
    std::string getEndpointStatus(const mctpw::eid_t eid);
    /**
     * @brief Get a reference to internaly maintained EndpointMap
     *
     * @return std::vector<mctpw::eid_t>
     */
    std::vector<mctpw::eid_t> getEndpointMap();
    /**
     * @brief Send MCTP request to dstEId and receive status of send operation
     * in callback through SPDM
     *
     * @param callback Callback that will be invoked with status of send
     * operation
     * @param dstEId Destination MCTP Endpoint ID
     * @param msgTag MCTP message tag value
     * @param tagOwner MCTP tag owner bit. Identifies whether the message tag
     * was originated by the endpoint that is the source of the message
     * @param request MCTP request byte array
     */
    void sendAsync(const SendCallback& callback, const mctpw::eid_t dstEId,
                   const uint8_t msgTag, const bool tagOwner,
                   const mctpw::ByteArray& request);
    /**
     * @brief Send MCTP request to dstEId and receive status of send operation
     * through SPDM
     * @param yield boost yiled_context object to yield on dbus calls
     * @param dstEId Destination MCTP Endpoint ID
     * @param msgTag MCTP message tag value
     * @param tagOwner MCTP tag owner bit. Identifies whether the message tag
     * was originated by the endpoint that is the source of the message
     * @param request MCTP request byte array
     * @return std::pair<boost::system::error_code, int> Pair of boost
     * error_code and dbus send method call return value
     */
    std::pair<boost::system::error_code, int>
        sendYield(boost::asio::yield_context& yield, const mctpw::eid_t dstEId,
                  const uint8_t msgTag, const bool tagOwner,
                  const mctpw::ByteArray& request);
    /**
     * @brief Send request to dstEId and receive response asynchronously in
     * receiveCb through SPDM
     *
     * @param receiveCb Callback to be executed when response is ready
     * @param dstEId Destination MCTP Endpoint ID
     * @param request MCTP request byte array
     * @param timeout MCTP receive timeout
     */
    void sendReceiveAsync(ReceiveCallback receiveCb, mctpw::eid_t dstEId,
                          const mctpw::ByteArray& request,
                          std::chrono::milliseconds timeout);
    /**
     * @brief Send request to dstEId and receive response using yield_context
     *        throught SPDM
     * @param yield Boost yield_context to use on dbus call
     * @param dstEId Destination MCTP Endpoint ID
     * @param request MCTP request byte array
     * @param timeout MCTP receive timeout
     * @return std::pair<boost::system::error_code, ByteArray> Pair of boost
     * error code and response byte array
     */
    std::pair<boost::system::error_code, mctpw::ByteArray>
        sendReceiveYield(boost::asio::yield_context yield, mctpw::eid_t dstEId,
                         const mctpw::ByteArray& request,
                         std::chrono::milliseconds timeout);

  private:
    std::unique_ptr<mctpw::MCTPWrapper> mctpWrapper;
};
