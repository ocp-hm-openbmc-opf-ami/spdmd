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
 * limitation
 */
extern "C"
{
#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "spdm_device_secret_lib_internal.h"
}
#include "library/spdm_transport_none_lib.h"

#include "spdmd.hpp"

#include <cstdint>
#include <functional>
#include <iostream>

namespace spdm
{

spdmImp spdmd;

/*Callback functin for libspdm */
return_status deviceReceiveMessage(void* spdmContext, uintn* responseSize,
                                   void* response, uint64_t timeout)
{
    return spdmd.deviceReceiveMessageImp(spdmContext, responseSize, response,
                                         timeout);
}

return_status deviceSendMessage(void* spdmContext, uintn requestSize,
                                const void* request, uint64_t timeout)
{
    return spdmd.deviceSendMessageImp(spdmContext, requestSize, request,
                                      timeout);
}

void spdmServerConnectionStateCallback(
    void* spdmContext, libspdm_connection_state_t connectionState)
{
    return spdmd.processConnectionStateImp(spdmContext, connectionState);
}

void spdmServerSessionStateCallback(void* spdmContext, uint32_t sessionID,
                                    libspdm_session_state_t sessionState)
{
    return spdmd.processSessionStateImp(spdmContext, sessionID, sessionState);
}

/*Callback functin for IODevice  */
auto msgRecvCallback = [](void*, mctpw::eid_t srcEid, bool tagOwner,
                          uint8_t msgTag, const std::vector<uint8_t>& data,
                          int) {
    UNUSED(tagOwner);

    if (msgTag != 5)
        return; // skip not spdm packet

    spdmd.addData(srcEid, data);
    boost::asio::spawn([](boost::asio::yield_context yield) {
        UNUSED(yield);
        spdm::spdmd.processSPDMMessage();
    });
};

void onDeviceUpdate(void*, const mctpw::Event& evt,
                    boost::asio::yield_context yield)
{

    UNUSED(yield);
    switch (evt.type)
    {
        case mctpw::Event::EventType::deviceAdded:
            spdmd.addNewDevice(evt.eid);
            break;
        case mctpw::Event::EventType::deviceRemoved:
            spdmd.removeDevice(evt.eid);
        default:
            break;
    }
    return;
}

/*Implement SPDM deamon */

bool spdmImp::init(std::shared_ptr<sdbusplus::asio::object_server> objServer,
                   std::shared_ptr<sdbusplus::asio::connection> conn,
                   std::shared_ptr<boost::asio::io_service> io)
{

    curIndex = 0;
    useSlotCount = 3;
    pobjectServer = objServer;
    pconn = conn;
    pio = io;
    spdmResponderCfg =
        spdm::getConfigurationFromEntityManager(conn, "SPDM_responder");

    useBasicMutAuth = (uint8_t)spdmResponderCfg.basicMutAuth;

    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        pobjectServer->add_interface("/xyz/openbmc_project/SPDM",
                                     "xyz.openbmc_project.SPDM");

    iface->register_method("getEndpointMap", [this]() -> std::vector<uint8_t> {
        std::vector<uint8_t> data;
        uint8_t i;
        for (i = 0; i < curIndex; i++)
        {
            data.push_back(spdmPool[i].deviceEID);
        }
        return data;
    });
    iface->register_method(
        "getEndpointStatus", [this](uint8_t eid) -> std::string {
            uint8_t i;
            std::string ValueMap[] = {"NOT_STARTED",        "AFTER_VERSION",
                                      "AFTER_CAPABILITIES", "STATE_NEGOTIATED",
                                      "AFTER_DIGESTS",      "AFTER_CERTIFICATE",
                                      "AUTHENTICATED"};
            for (i = 0; i < curIndex; i++)
            {
                if (spdmPool[i].deviceEID == eid)
                    return ValueMap[spdmPool[i].connectStatus];
            }
            return "not available";
        });

    iface->initialize();

    mctpw::MCTPConfiguration config(mctpw::MessageType::spdm,
                                    mctpw::BindingType::mctpOverSmBus);
    mctpWrapper = std::make_unique<mctpw::MCTPWrapper>(
        spdm::spdmd.pconn, config, spdm::onDeviceUpdate, spdm::msgRecvCallback);

    boost::asio::spawn(*(io), [io, this](boost::asio::yield_context yield) {
        mctpWrapper->detectMctpEndpoints(yield);
        mctpw::MCTPWrapper::EndpointMap eidMap = mctpWrapper->getEndpointMap();
        for (auto& item : eidMap)
        {
            addNewDevice(item.first);
        }
    });
    return true;
}

bool spdmImp::removeDevice(const mctpw::eid_t eid)
{
    uint8_t i;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].deviceEID == eid)
            break;
    }
    if (i >= curIndex)
        return false;
    free(spdmPool[i].pspdmContext);
    spdmPool[i].pspdmContext = NULL;
    pobjectServer->remove_interface(spdmPool[i].endpointIntf);
    spdmPool.erase(spdmPool.begin() + i);
    curIndex = curIndex - 1;
    return true;
}

bool spdmImp::addNewDevice(const mctpw::eid_t eid)
{
    spdmItem newItem;
    uint8_t newIndex;
    newItem.pspdmContext = (void*)malloc(libspdm_get_context_size());
    if (newItem.pspdmContext == NULL)
    {
        return false;
    }
    newItem.deviceEID = eid;
    newItem.useSlotId = 0;
    newItem.sessonId = 0;
    newItem.useVersion = 0;
    newItem.useReqAsymAlgo = 0;
    newItem.useMeasurementHashAlgo = 0;
    newItem.useAsymAlgo = 0;
    newItem.useHashAlgo = 0;
    newItem.connectStatus = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    newItem.data.clear();
    spdmPool.push_back(newItem);
    newIndex = curIndex;
    curIndex++;
    libspdm_init_context(spdmPool[newIndex].pspdmContext);
    libspdm_register_device_io_func(spdmPool[newIndex].pspdmContext,
                                    deviceSendMessage, deviceReceiveMessage);
    libspdm_register_session_state_callback_func(
        spdmPool[newIndex].pspdmContext, spdmServerSessionStateCallback);
    libspdm_register_connection_state_callback_func(
        spdmPool[newIndex].pspdmContext, spdmServerConnectionStateCallback);

    libspdm_register_transport_layer_func(spdmPool[newIndex].pspdmContext,
                                          spdm_transport_none_encode_message,
                                          spdm_transport_none_decode_message);

    settingFromConfig(newIndex);

    if (spdmPool[newIndex].endpointIntf == NULL)
    {
        std::string DevObj =
            "/xyz/openbmc_project/SPDM/device/" + std::to_string(newIndex);
        spdmPool[newIndex].endpointIntf =
            pobjectServer->add_interface(DevObj, "xyz.openbmc_project.spdm");
        spdmPool[newIndex].endpointIntf->register_property("Status",
                                                           std::string("Init"));
        spdmPool[newIndex].endpointIntf->register_property(
            "EID", spdmPool[newIndex].deviceEID);
        spdmPool[newIndex].endpointIntf->initialize();
    }
    else
    {

        std::string ValueMap[] = {"NOT_STARTED",        "AFTER_VERSION",
                                  "AFTER_CAPABILITIES", "STATE_NEGOTIATED",
                                  "AFTER_DIGESTS",      "AFTER_CERTIFICATE",
                                  "AUTHENTICATED"};

        spdmPool[newIndex].endpointIntf->set_property(
            "Status", ValueMap[spdmPool[newIndex].connectStatus]);
    }

    return true;
}

bool spdmImp::settingFromConfig(uint8_t itemIndex)
{
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;   // Value that size is uint8_t
    uint16_t u16Value; // Value that size is uint16_t
    uint32_t u32Value; // Value that size is uint32_t

    memset(&parameter, 0, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    u8Value = 0;

    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &u8Value,
                     sizeof(u8Value));

    useResponderCapabilityFlags = spdmResponderCfg.capability;
    u32Value = useResponderCapabilityFlags;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &u32Value,
                     sizeof(u32Value));

    u8Value = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &u8Value,
                     sizeof(u8Value));

    u32Value = spdmResponderCfg.measHash;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &u32Value,
                     sizeof(u32Value));

    u32Value = spdmResponderCfg.asym;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &u32Value,
                     sizeof(u32Value));

    u32Value = spdmResponderCfg.hash;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &u32Value,
                     sizeof(u32Value));

    u16Value = (uint16_t)spdmResponderCfg.dhe;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &u16Value,
                     sizeof(u16Value));

    u16Value = (uint16_t)spdmResponderCfg.aead;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &u16Value,
                     sizeof(u16Value));

    u16Value = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &u16Value,
                     sizeof(u16Value));

    u8Value = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter, &u8Value,
                     sizeof(u8Value));

    return true;
}

bool spdmImp::addData(mctpw::eid_t srcEid, const std::vector<uint8_t>& data)
{
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].deviceEID == srcEid)
        {
            break;
        }
    }
    if (i >= curIndex)
        return false;

    spdmPool[i].data = data;
    return true;
}

bool spdmImp::processSPDMMessage()
{
    uint8_t i;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].data.size() > 0)
        {
            libspdm_responder_dispatch_message(spdmPool[i].pspdmContext);
        }
    }
    return true;
}

return_status spdmImp::deviceReceiveMessageImp(void* spdmContext,
                                               uintn* responseSize,
                                               void* response, uint64_t timeout)
{

    UNUSED(timeout);
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return RETURN_DEVICE_ERROR;

    if (spdmPool[i].data.size() <= 1)
        return RETURN_DEVICE_ERROR;
    *responseSize = spdmPool[i].data.size() - 1;
    std::copy(spdmPool[i].data.begin() + 1, spdmPool[i].data.end(),
              (uint8_t*)response);
    spdmPool[i].data.clear();
    return RETURN_SUCCESS;
}

return_status spdmImp::deviceSendMessageImp(void* spdmContext,
                                            uintn requestSize,
                                            const void* request,
                                            uint64_t timeout)
{
    UNUSED(timeout);
    uint8_t i;
    uint32_t j;
    std::vector<uint8_t> data;

    UNUSED(timeout);
    uint8_t* requestPayload = (uint8_t*)request;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return RETURN_DEVICE_ERROR;

    data.push_back(5);

    for (j = 0; j < requestSize; j++)
        data.push_back(*(requestPayload + j));

    mctpw::eid_t eid = spdmPool[i].deviceEID;

    boost::asio::spawn(
        *pio, [this, eid, data](boost::asio::yield_context yield) {
            mctpWrapper->sendYield(yield, eid, 0X05, false, data);
        });

    return RETURN_SUCCESS;
}

void spdmImp::processConnectionStateImp(
    void* spdmContext, libspdm_connection_state_t connectionState)
{
    bool res;
    void* data;
    uint32_t dataSize;
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;   // Value that size is uint8_t
    uint16_t u16Value; // Value that size is uint16_t
    uint32_t u32Value; // Value that size is uint32_t
    return_status status;
    void* hash;
    uint32_t hashSize;
    uint8_t* rootCert;
    uint32_t rootCertSize;
    uint8_t index;
    spdm_version_number_t spdmVersion;
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return;
    spdmPool[i].connectStatus = connectionState;
    switch (connectionState)
    {
        case LIBSPDM_CONNECTION_STATE_NOT_STARTED:
            /* clear perserved state*/
            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_VERSION:
            spdmPool[i].endpointIntf->set_property(
                "Status", std::string("AFTER_VERSION"));
            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES:
            spdmPool[i].endpointIntf->set_property(
                "Status", std::string("AFTER_CAPABILITIES"));
            break;

        case LIBSPDM_CONNECTION_STATE_NEGOTIATED:
            spdmPool[i].endpointIntf->set_property("Status",
                                                   std::string("NEGOTIATED"));
            if (spdmPool[i].useVersion == 0)
            {
                memset(&parameter, 0, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                dataSize = sizeof(spdmVersion);
                libspdm_get_data(spdmPool[i].pspdmContext,
                                 LIBSPDM_DATA_SPDM_VERSION, &parameter,
                                 &spdmVersion, &dataSize);
                spdmPool[i].useVersion =
                    (uint8_t)(spdmVersion >> SPDM_VERSION_NUMBER_SHIFT_BIT);
            }
            /* Provision new content*/
            memset(&parameter, 0, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

            dataSize = sizeof(u32Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                             &u32Value, &dataSize);
            spdmPool[i].useMeasurementHashAlgo = u32Value;
            dataSize = sizeof(u32Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &u32Value,
                             &dataSize);
            spdmPool[i].useAsymAlgo = u32Value;
            dataSize = sizeof(u32Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &u32Value,
                             &dataSize);
            spdmPool[i].useHashAlgo = u32Value;

            dataSize = sizeof(u16Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                             &u16Value, &dataSize);
            spdmPool[i].useReqAsymAlgo = u16Value;
            res = read_responder_public_certificate_chain(
                spdmPool[i].useHashAlgo, spdmPool[i].useAsymAlgo, &data,
                &dataSize, NULL, NULL);
            if (res)
            {
                memset(&parameter, 0, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                u8Value = useSlotCount;
                libspdm_set_data(spdmPool[i].pspdmContext,
                                 LIBSPDM_DATA_LOCAL_SLOT_COUNT, &parameter,
                                 &u8Value, sizeof(u8Value));

                for (index = 0; index < 3; index++)
                {
                    parameter.additional_data[0] = index;
                    libspdm_set_data(spdmPool[i].pspdmContext,
                                     LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                     &parameter, data, dataSize);
                }
                /* do not free it*/
            }
            if (spdmPool[i].useReqAsymAlgo != 0)
            {
                if ((spdmPool[i].useSlotId == 0xFF) ||
                    ((useResponderCapabilityFlags &
                      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP) !=
                     0))
                {
                    res = read_requester_public_certificate_chain(
                        spdmPool[i].useHashAlgo, spdmPool[i].useReqAsymAlgo,
                        &data, &dataSize, NULL, NULL);
                    if (res)
                    {
                        memset(&parameter, 0, sizeof(parameter));
                        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                        libspdm_set_data(spdmPool[i].pspdmContext,
                                         LIBSPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
                                         &parameter, data, dataSize);
                        /* Do not free it.*/
                    }
                }
                else
                {
                    res = read_requester_root_public_certificate(
                        spdmPool[i].useHashAlgo, spdmPool[i].useReqAsymAlgo,
                        &data, &dataSize, &hash, &hashSize);
                    x509_get_cert_from_cert_chain(
                        (uint8_t*)data + sizeof(spdm_cert_chain_t) + hashSize,
                        dataSize - sizeof(spdm_cert_chain_t) - hashSize, 0,
                        &rootCert, &rootCertSize);
                    if (res)
                    {
                        memset(&parameter, 0, sizeof(parameter));
                        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                        libspdm_set_data(spdmPool[i].pspdmContext,
                                         LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                                         &parameter, rootCert, rootCertSize);
                        /* Do not free it.*/
                    }
                }

                if (res)
                {
                    u8Value = useMutAuth;
                    parameter.additional_data[0] =
                        spdmPool[i].useSlotId; /* req_slot_id;*/
                    libspdm_set_data(spdmPool[i].pspdmContext,
                                     LIBSPDM_DATA_MUT_AUTH_REQUESTED,
                                     &parameter, &u8Value, sizeof(u8Value));

                    u8Value = useBasicMutAuth;
                    parameter.additional_data[0] =
                        spdmPool[i].useSlotId; /* req_slot_id;*/
                    libspdm_set_data(spdmPool[i].pspdmContext,
                                     LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
                                     &parameter, &u8Value, sizeof(u8Value));
                }
            }

            status = libspdm_set_data(
                spdmPool[i].pspdmContext, LIBSPDM_DATA_PSK_HINT, NULL,
                (void*)TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
            if (RETURN_ERROR(status))
            {
                printf("libspdm_set_data - %x\n", (uint32_t)status);
            }

            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS:
            spdmPool[i].endpointIntf->set_property(
                "Status", std::string("AFTER_DIGESTS"));
            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE:
            spdmPool[i].endpointIntf->set_property(
                "Status", std::string("AFTER_CERTIFICATE"));
            break;
        case LIBSPDM_CONNECTION_STATE_AUTHENTICATED:
            spdmPool[i].endpointIntf->set_property(
                "Status", std::string("AUTHENTICATED"));
            break;
        default:
            break;
    }

    return;
}

void spdmImp::processSessionStateImp(void* spdmContext, uint32_t sessionID,
                                     libspdm_session_state_t sessionState)
{
    uint32_t dataSize;
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return;

    switch (sessionState)
    {
        case LIBSPDM_SESSION_STATE_NOT_STARTED:
            break;

        case LIBSPDM_SESSION_STATE_HANDSHAKING:
            /* collect session policy*/
            spdmPool[i].sessonId = sessionID;
            if (spdmPool[i].useVersion >= SPDM_MESSAGE_VERSION_12)
            {
                memset(&parameter, 0, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
                *(uint32_t*)parameter.additional_data = sessionID;

                u8Value = 0;
                dataSize = sizeof(u8Value);
                libspdm_get_data(spdmPool[i].pspdmContext,
                                 LIBSPDM_DATA_SESSION_POLICY, &parameter,
                                 &u8Value, &dataSize);
                printf("session policy - %x\n", u8Value);
            }
            break;

        case LIBSPDM_SESSION_STATE_ESTABLISHED:
            /* no action*/
            break;

        default:
            ASSERT(false);
            break;
    }
    if (sessionState == LIBSPDM_SESSION_STATE_HANDSHAKING)
        spdmPool[i].endpointIntf->set_property(
            "Status", std::string("LIBSPDM_SESSION_STATE_HANDSHAKING"));
    else
    {
        if (sessionState == LIBSPDM_SESSION_STATE_ESTABLISHED)
            spdmPool[i].endpointIntf->set_property(
                "Status", std::string("LIBSPDM_SESSION_STATE_ESTABLISHED"));
    }
}

} // namespace spdm

int main(void)
{

    auto ioc = std::make_shared<boost::asio::io_context>();
    auto conn = std::make_shared<sdbusplus::asio::connection>(*ioc);
    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);
    conn->request_name("xyz.openbmc_project.spdm");

    spdm::spdmd.init(objectServer, conn, ioc);

    ioc->run();
    return 0;
}
