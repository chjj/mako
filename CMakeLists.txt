# CMakeLists.txt - cmake build for libsatoshi
# Copyright (c) 2020, Christopher Jeffrey (MIT License).

cmake_minimum_required(VERSION 3.4)
project(satoshi LANGUAGES C)

include(deps/torsion/cmake/AppendCCompilerFlag.cmake)

set(satoshi_cflags)
set(satoshi_defines)

if(MSVC)
  append_c_compiler_flag(satoshi_cflags /wd4244
                                        /wd4267)
else()
  append_c_compiler_flag(satoshi_cflags -Wall
                                        -Wextra
                                        -Wcast-align
                                        -Wshadow)
endif()

add_subdirectory(deps/torsion)

add_library(satoshi STATIC src/btc.c)
target_compile_definitions(satoshi PRIVATE ${satoshi_defines})
target_compile_options(satoshi PRIVATE ${satoshi_cflags})
target_link_libraries(satoshi INTERFACE torsion)
