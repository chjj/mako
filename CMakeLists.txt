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

set(CMAKE_C_VISIBILITY_PRESET hidden)

list(APPEND satoshi_sources src/crypto/chacha20.c
                            src/crypto/drbg.c
                            src/crypto/hash160.c
                            src/crypto/hash256.c
                            src/crypto/rand.c
                            src/crypto/ripemd160.c
                            src/crypto/sha1.c
                            src/crypto/sha256.c
                            src/crypto/sys.c
                            src/address.c
                            src/base58.c
                            src/bech32.c
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
                            src/mainnet.c
                            src/murmur3.c
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

add_subdirectory(deps/torsion)
list(APPEND satoshi_libs torsion)

add_library(satoshi_static STATIC ${satoshi_sources})
target_compile_definitions(satoshi_static PUBLIC ${satoshi_defines})
target_compile_options(satoshi_static PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_static PUBLIC ${satoshi_includes})
target_link_options(satoshi_static INTERFACE ${satoshi_ldflags})
target_link_libraries(satoshi_static INTERFACE ${satoshi_libs})
set_property(TARGET satoshi_static PROPERTY OUTPUT_NAME satoshi)

add_library(satoshi_shared SHARED ${satoshi_sources})
target_compile_definitions(satoshi_shared PUBLIC ${satoshi_defines}
                                          PRIVATE BTC_EXPORT)
target_compile_options(satoshi_shared PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_shared PUBLIC ${satoshi_includes})
target_link_options(satoshi_shared PUBLIC ${satoshi_ldflags})
target_link_options(satoshi_shared PRIVATE -Wl,-z,now)
target_link_libraries(satoshi_shared PRIVATE ${satoshi_libs})
set_property(TARGET satoshi_shared PROPERTY OUTPUT_NAME satoshi)

add_executable(satoshi_test test/test.c)
target_link_options(satoshi_test PRIVATE -Wl,-z,now)
target_link_libraries(satoshi_test PRIVATE satoshi_shared)
