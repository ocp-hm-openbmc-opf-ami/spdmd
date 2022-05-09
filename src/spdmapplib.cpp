#include "spdmapplib.hpp"

#include <stdio.h>

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/sd_event.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/slot.hpp>
#include <sdbusplus/timer.hpp>
using namespace sdbusplus;
#define UNUSED(x) (void)(x)

/**
 * @brief Construct a new SPDMAPPLib object
 *
 * @param ioContext boost io_context object. Usable if invoker is an sdbus
 * unaware app.
 * @param networkChangeCb Callback to be executed when a network change
 * occurs in the system. For example a new device is inserted or removed etc
 * @param rxCb Callback to be executed when new MCTP message is
 */
SPDMAPPLib::SPDMAPPLib(boost::asio::io_context& ioContext,
                       const mctpw::ReconfigurationCallback& networkChangeCb,
                       const mctpw::ReceiveMessageCallback& rxCb)
{

    mctpw::MCTPConfiguration config(mctpw::MessageType::spdm,
                                    mctpw::BindingType::mctpOverSmBus);
    mctpWrapper = std::make_unique<mctpw::MCTPWrapper>(ioContext, config,
                                                       networkChangeCb, rxCb);
}

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
SPDMAPPLib::SPDMAPPLib(std::shared_ptr<sdbusplus::asio::connection> conn,
                       const mctpw::ReconfigurationCallback& networkChangeCb,
                       const mctpw::ReceiveMessageCallback& rxCb)
{

    mctpw::MCTPConfiguration config(mctpw::MessageType::spdm,
                                    mctpw::BindingType::mctpOverSmBus);
    mctpWrapper = std::make_unique<mctpw::MCTPWrapper>(conn, config,
                                                       networkChangeCb, rxCb);
}

/**
 * @brief Get a reference to internaly maintained EndpointMap
 *
 * @return std::vector<mctpw::eid_t>
 */
std::vector<mctpw::eid_t> SPDMAPPLib::getEndpointMap()
{
    auto bus = bus::new_default_system();
    auto msg = bus.new_method_call(
        "xyz.openbmc_project.spdm", "/xyz/openbmc_project/SPDM",
        "xyz.openbmc_project.SPDM", "getEndpointMap");

    auto reply = bus.call(msg);

    std::vector<mctpw::eid_t> result;
    reply.read(result);
    return result;
}

/**
 * @brief Get status EndpointMap
 *
 * @return std::string status
 */
std::string SPDMAPPLib::getEndpointStatus(const mctpw::eid_t eid)
{
    auto bus = bus::new_default_system();
    auto msg = bus.new_method_call(
        "xyz.openbmc_project.spdm", "/xyz/openbmc_project/SPDM",
        "xyz.openbmc_project.SPDM", "getEndpointStatus");

    msg.append(eid);
    auto reply = bus.call(msg);

    std::string result;
    reply.read(result);
    return result;
}

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
void SPDMAPPLib::sendAsync(const SendCallback& callback,
                           const mctpw::eid_t dstEId, const uint8_t msgTag,
                           const bool tagOwner, const mctpw::ByteArray& request)
{
    if (getEndpointStatus(dstEId) != "AUTHENTICATED")
        return;
    mctpWrapper->sendAsync(callback, dstEId, msgTag, tagOwner, request);
}

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
    SPDMAPPLib::sendYield(boost::asio::yield_context& yield,
                          const mctpw::eid_t dstEId, const uint8_t msgTag,
                          const bool tagOwner, const mctpw::ByteArray& request)
{
    if (getEndpointStatus(dstEId) != "AUTHENTICATED")
    {
        // Status error
        return std::make_pair(
            boost::system::errc::make_error_code(boost::system::errc::io_error),
            -1);
    }
    return mctpWrapper->sendYield(yield, dstEId, msgTag, tagOwner, request);
}

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
    SPDMAPPLib::sendReceiveYield(boost::asio::yield_context yield,
                                 mctpw::eid_t dstEId,
                                 const mctpw::ByteArray& request,
                                 std::chrono::milliseconds timeout)
{
    auto receiveResult = std::make_pair(
        boost::system::errc::make_error_code(boost::system::errc::success),
        mctpw::ByteArray());

    if (getEndpointStatus(dstEId) != "AUTHENTICATED")
    {
        receiveResult.first =
            boost::system::errc::make_error_code(boost::system::errc::io_error);
        return receiveResult;
    }
    return mctpWrapper->sendReceiveYield(yield, dstEId, request, timeout);
}

/**
 * @brief Send request to dstEId and receive response asynchronously in
 * receiveCb through SPDM
 *
 * @param receiveCb Callback to be executed when response is ready
 * @param dstEId Destination MCTP Endpoint ID
 * @param request MCTP request byte array
 * @param timeout MCTP receive timeout
 */
void SPDMAPPLib::sendReceiveAsync(ReceiveCallback callback, mctpw::eid_t dstEId,
                                  const mctpw::ByteArray& request,
                                  std::chrono::milliseconds timeout)
{
    if (getEndpointStatus(dstEId) != "AUTHENTICATED")
        return;
    mctpWrapper->sendReceiveAsync(callback, dstEId, request, timeout);
}
