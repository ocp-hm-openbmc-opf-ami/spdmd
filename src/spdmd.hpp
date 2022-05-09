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
#include <sys/select.h>
#include <sys/socket.h>

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/thread.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/sd_event.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdbusplus/timer.hpp>

#include <vector>
#define UNUSED(x) (void)(x)

using namespace sdbusplus;
namespace spdm
{
typedef struct
{

    void* pspdmContext;
    mctpw::eid_t deviceEID;
    uint8_t useSlotId;
    uint32_t sessonId;
    uint32_t useVersion;
    uint16_t useReqAsymAlgo;
    uint32_t useMeasurementHashAlgo;
    uint32_t useAsymAlgo;
    uint32_t useHashAlgo;
    libspdm_connection_state_t connectStatus;
    std::vector<uint8_t> data;
    std::shared_ptr<sdbusplus::asio::dbus_interface> endpointIntf;
} spdmItem;

typedef struct
{
    bool bRespnder;
    uint32_t version;
    uint32_t capability;
    uint32_t hash;
    uint32_t measHash;
    uint32_t asym;
    uint32_t dhe;
    uint32_t aead;
    uint32_t basicMutAuth;
    uint32_t mutAuth;
} configuration;

class spdmImp
{
  public:
    spdmImp(){};
    bool init(std::shared_ptr<sdbusplus::asio::object_server> objServer,
              std::shared_ptr<sdbusplus::asio::connection> conn,
              std::shared_ptr<boost::asio::io_service> io);
    bool addNewDevice(const mctpw::eid_t eid);
    bool removeDevice(const mctpw::eid_t eid);
    bool settingFromConfig(uint8_t ItemIndex);
    bool addData(const mctpw::eid_t eid, const std::vector<uint8_t>& data);
    bool processSPDMMessage();

    // register functions for libspdm
    return_status deviceSendMessageImp(void* spdmContext, uintn requestSize,
                                       const void* request, uint64_t timeout);
    return_status deviceReceiveMessageImp(void* spdmContext,
                                          uintn* responseSize, void* response,
                                          uint64_t timeout);
    void processConnectionStateImp(void* spdmContext,
                                   libspdm_connection_state_t connectionState);
    void processSessionStateImp(void* spdmContext, uint32_t sessionID,
                                libspdm_session_state_t sessionState);

  private:
    std::shared_ptr<sdbusplus::asio::object_server> pobjectServer;
    std::shared_ptr<boost::asio::io_service> pio;
    std::shared_ptr<sdbusplus::asio::connection> pconn;
    std::unique_ptr<mctpw::MCTPWrapper> mctpWrapper;

    uint8_t useSlotCount;
    uint8_t curIndex;
    configuration spdmResponderCfg;
    uint32_t useResponderCapabilityFlags;
    uint8_t useMutAuth;
    uint8_t useBasicMutAuth;
    std::vector<spdmItem> spdmPool;
};
using configurationField =
    std::variant<bool, uint64_t, std::string, std::vector<std::string>>;
using configurationMap = std::unordered_map<std::string, configurationField>;

configuration getConfigurationFromEntityManager(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationName);
} // namespace spdm
