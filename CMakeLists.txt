# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# Copyright © 2011-2015, RedJack, LLC.
# All rights reserved.
#
# Please see the COPYING file in this distribution for license details.
# ----------------------------------------------------------------------

set(CMAKE_LEGACY_CYGWIN_WIN32 0)

cmake_minimum_required(VERSION 2.6)
set(PROJECT_NAME s5proxy)
set(RELEASE_DATE 2015-09-03)
project(${PROJECT_NAME})

set(VERSION 2.5.6)

option(LIBUV_BUILD_TESTS "LIBUV_BUILD_TESTS" OFF)
option(LIBUV_BUILD_BENCH "LIBUV_BUILD_BENCH" OFF)
add_subdirectory(depends/libuv)
add_subdirectory(src)


include_directories( ${CMAKE_CURRENT_BINARY_DIR} )

