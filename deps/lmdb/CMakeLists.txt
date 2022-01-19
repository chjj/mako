# CMakeLists.txt - cmake build for lmdb
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

cmake_minimum_required(VERSION 3.4)
project(lmdb LANGUAGES C)

include(CheckTypeSize)

check_type_size("void*" LMDB_SIZEOF_VOID_P) # CMAKE_SIZEOF_VOID_P

set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Threads REQUIRED)

if(NOT WIN32 AND NOT CMAKE_USE_PTHREADS_INIT)
  message(FATAL_ERROR "pthread not found")
endif()

add_library(lmdb STATIC mdb.c midl.c)

if(LMDB_SIZEOF_VOID_P STREQUAL "4")
  # https://twitter.com/hyc_symas/status/678604015127683074
  target_compile_definitions(lmdb PUBLIC MDB_VL32)
endif()

if(MINGW)
  target_compile_options(lmdb PRIVATE -Wno-incompatible-pointer-types
                                      -Wno-return-local-addr)
endif()

target_include_directories(lmdb INTERFACE ${PROJECT_SOURCE_DIR})
target_link_libraries(lmdb PRIVATE Threads::Threads)
