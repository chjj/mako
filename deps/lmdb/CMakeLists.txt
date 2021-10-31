cmake_minimum_required(VERSION 3.4)
project(lmdb LANGUAGES C)

set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Threads REQUIRED)

if(NOT WIN32 AND NOT CMAKE_USE_PTHREADS_INIT)
  message(FATAL_ERROR "pthread not found")
endif()

add_library(lmdb STATIC mdb.c midl.c)

if(MINGW)
  target_compile_options(lmdb PRIVATE -Wno-incompatible-pointer-types
                                      -Wno-return-local-addr)
endif()

target_include_directories(lmdb INTERFACE ${PROJECT_SOURCE_DIR})
target_link_libraries(lmdb PRIVATE Threads::Threads)
