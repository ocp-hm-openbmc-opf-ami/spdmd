cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# Set project name here
project (spdmd CXX)

option(BUILD_STANDALONE "Use outside of YOCTO depedencies system" OFF)

set (BUILD_SHARED_LIBRARIES ON)
set (CMAKE_CXX_STANDARD 17)

set (CMAKE_CXX_STANDARD_REQUIRED ON)


add_definitions(-DMCTP_ASTPCIE_RESPONSE_WA)


#SET(CMAKE_LINKER arm-openbmc-linux-gnueabi-gcc)
#SET(CMAKE_EXE_LINKER_FLAGS "$ENV{LDFLAGS} ${OBMCGCCOPTION} -Wno-error -no-pie" )
#SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,--start-group <LINK_LIBRARIES> -Wl,--end-group")
        

set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -Werror \
    -Wall \
    -Wextra \
    -Wshadow \
    -Wnon-virtual-dtor \
    -Wunused \
    -Woverloaded-virtual \
    -Wconversion \
    -Wnull-dereference \
    -Wdouble-promotion \
    -Wno-old-style-cast \
    -Wformat=2 \
    -Wno-write-strings  \
")
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})


# Add header and sources here
INCLUDE_DIRECTORIES(
                    ${PROJECT_SOURCE_DIR}/include 
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/include
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/include/hal/arm 
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/os_stub
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/os_stub/include
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/hal/arm
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/os_stub/spdm_device_secret_lib_sample
)



set(src_spdm_responder_emu
    ${PROJECT_SOURCE_DIR}/spdmd.cpp
    ${PROJECT_SOURCE_DIR}/util.cpp
    ${PROJECT_SOURCE_DIR}/library/spdm_transport_none_lib/common.cpp
    ${PROJECT_SOURCE_DIR}/library/spdm_transport_none_lib/none.cpp
)

ADD_EXECUTABLE(spdm_responder  ${src_spdm_responder_emu} )


add_library(spdmapplib SHARED ${PROJECT_SOURCE_DIR}/spdmapplib.cpp)
set_target_properties(spdmapplib PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(spdmapplib PROPERTIES PUBLIC_HEADER spdmapplib.hpp)

ADD_EXECUTABLE(spdmapplibtest ${PROJECT_SOURCE_DIR}/test.cpp)

target_link_libraries (
    spdmapplibtest
    spdmapplib
    sdbusplus
    systemd
    pthread
    phosphor_dbus
    mctpwplus
    boost_coroutine
    boost_system
)

if(ENABLE_BINARY_BUILD STREQUAL "1")
target_link_libraries (
    spdm_responder
    sdbusplus
    systemd
    pthread
    phosphor_dbus
    boost_coroutine
    boost_system
    mctpwplus
    spdm  
    crypto
    ssl
 )

else()
target_link_libraries (
    spdm_responder 
    sdbusplus
    systemd
    pthread
    phosphor_dbus
    boost_coroutine
    boost_system
    mctpwplus
    spdm  
)
 

endif()    
    
set(SERVICE_FILES
    ${PROJECT_SOURCE_DIR}/xyz.openbmc_project.spdmd.service )

install(TARGETS spdm_responder  DESTINATION bin)
install(FILES ${SERVICE_FILES} DESTINATION /lib/systemd/system/)
install(TARGETS spdmapplib spdmapplib)


