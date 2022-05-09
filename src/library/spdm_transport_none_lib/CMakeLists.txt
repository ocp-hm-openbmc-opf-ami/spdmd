cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES( $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/include
                    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/include/hal/arm 
                    ${PROJECT_SOURCE_DIR}/include
)

SET(src_spdm_transport_none_lib
    common.c
    none.c
)

ADD_LIBRARY(spdm_transport_none_lib STATIC ${src_spdm_transport_none_lib})
