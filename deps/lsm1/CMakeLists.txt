cmake_minimum_required(VERSION 3.4)
project(lsm1 LANGUAGES C)

set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Threads REQUIRED)

if(NOT WIN32 AND NOT CMAKE_USE_PTHREADS_INIT)
  message(FATAL_ERROR "pthread not found")
endif()

add_library(lsm1 STATIC lsm_ckpt.c
                        lsm_file.c
                        lsm_log.c
                        lsm_main.c
                        lsm_mem.c
                        lsm_mutex.c
                        lsm_shared.c
                        lsm_sorted.c
                        lsm_str.c
                        lsm_tree.c
                        lsm_unix.c
                        lsm_varint.c
                        lsm_win32.c)

if(WIN32)
  target_compile_definitions(lsm1 PRIVATE LSM_MUTEX_WIN32=1)
else()
  target_compile_definitions(lsm1 PRIVATE LSM_MUTEX_PTHREADS=1)
endif()

target_include_directories(lsm1 INTERFACE ${PROJECT_SOURCE_DIR})
target_link_libraries(lsm1 PRIVATE Threads::Threads)
