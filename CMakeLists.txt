# CMakeLists.txt - cmake build for libsatoshi
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj/libsatoshi

cmake_minimum_required(VERSION 3.4)
project(satoshi LANGUAGES C)

set(satoshi_sources)
set(satoshi_defines)
set(satoshi_cflags)
set(satoshi_includes)
set(satoshi_ldflags)
set(satoshi_libs)

list(APPEND satoshi_sources src/address.c
                            src/block.c
                            src/buffer.c
                            src/coin.c
                            src/compact.c
                            src/crypto.c
                            src/entry.c
                            src/header.c
                            src/input.c
                            src/inpvec.c
                            src/internal.c
                            src/mine.c
                            src/outpoint.c
                            src/output.c
                            src/outvec.c
                            src/script.c
                            src/tx.c
                            src/undo.c
                            src/util.c
                            src/view.c)

if(MSVC)
  list(APPEND satoshi_cflags /wd4244
                             /wd4267)
else()
  list(APPEND satoshi_cflags -Wall
                             -Wextra
                             -Wcast-align
                             -Wshadow)
endif()

list(APPEND satoshi_includes ${PROJECT_SOURCE_DIR}/include
                             ${PROJECT_SOURCE_DIR}/deps/torsion/include)

# add_subdirectory(deps/torsion)
# list(APPEND satoshi_libs torsion)

add_library(satoshi STATIC ${satoshi_sources})
target_compile_definitions(satoshi PUBLIC ${satoshi_defines})
target_compile_options(satoshi PUBLIC ${satoshi_cflags})
target_include_directories(satoshi PUBLIC ${satoshi_includes})
target_link_options(satoshi INTERFACE ${satoshi_ldflags})
target_link_libraries(satoshi INTERFACE ${satoshi_libs})
