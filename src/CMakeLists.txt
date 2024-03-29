cmake_minimum_required(VERSION 3.0)
project(s5proxy)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        defs.h
        listener.c
        main.c
        s5.c
        s5.h
        tunnel.c
        tunnel.h
        sockaddr_universal.c
        sockaddr_universal.h
        daemon_wrapper.c
        daemon_wrapper.h
        common.h
        dump_info.c
        dump_info.h
        udprelay.c
        udprelay.h
        web_request.c
        web_request.h
        svr_impl.c)

if ((UNIX) AND (NOT APPLE))
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -pthread")
endif()

if ((${CMAKE_SYSTEM_NAME} MATCHES "Linux") OR (${CMAKE_SYSTEM_NAME} MATCHES "Android"))
    add_definitions(--std=c99 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200112)
endif()

include_directories(${libuv_include_dirs})

IF(MSVC)
  include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../win32/include )
  LIST(APPEND SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt.c)
  LIST(APPEND SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt_long.c)
ENDIF(MSVC)

add_executable(s5proxy ${SOURCE_FILES})

set (s5_lib_common
        uv_a)

target_link_libraries(s5proxy
        ${s5_lib_common})

