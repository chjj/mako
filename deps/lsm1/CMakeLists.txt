# CMakeLists.txt - cmake build for sqlite/lsm1
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

cmake_minimum_required(VERSION 3.4)
project(lsm1 LANGUAGES C)

set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Threads)

set(lsm_sources lsm_ckpt.c
                lsm_file.c
                lsm_log.c
                lsm_main.c
                lsm_mem.c
                lsm_mutex.c
                lsm_shared.c
                lsm_sorted.c
                lsm_str.c
                lsm_tree.c
                lsm_varint.c)

if(WIN32)
  list(APPEND lsm_sources lsm_win32.c)
else()
  list(APPEND lsm_sources lsm_unix.c)
endif()

add_library(lsm1 STATIC ${lsm_sources})

target_compile_definitions(lsm1 PRIVATE NDEBUG)

if(WIN32)
  target_compile_definitions(lsm1 PRIVATE LSM_MUTEX_WIN32)
elseif(CMAKE_USE_PTHREADS_INIT AND NOT EMSCRIPTEN)
  target_compile_definitions(lsm1 PRIVATE LSM_MUTEX_PTHREADS)
  target_link_libraries(lsm1 PRIVATE Threads::Threads)
endif()

target_include_directories(lsm1 INTERFACE ${PROJECT_SOURCE_DIR})
