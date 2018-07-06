cmake_minimum_required(VERSION 2.6)
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
        svr_impl.c)

if ((UNIX) AND (!APPLE))
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
endif()

include_directories(${libuv_include_dirs})

add_executable(s5proxy ${SOURCE_FILES})

set (s5_lib_common
        uv)

target_link_libraries(s5proxy
        ${s5_lib_common})
