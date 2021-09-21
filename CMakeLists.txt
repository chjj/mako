# CMakeLists.txt - cmake build for libsatoshi
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj/libsatoshi

cmake_minimum_required(VERSION 3.4)
project(satoshi LANGUAGES C)

include(CTest)

set(satoshi_sources)
set(satoshi_defines)
set(satoshi_cflags)
set(satoshi_includes)
set(satoshi_ldflags)
set(satoshi_libs)
set(node_sources)

set(CMAKE_C_VISIBILITY_PRESET hidden)

list(APPEND satoshi_sources src/crypto/chacha20.c
                            src/crypto/drbg.c
                            src/crypto/ecc.c
                            src/crypto/hash160.c
                            src/crypto/hash256.c
                            src/crypto/merkle.c
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
                            src/consensus.c
                            src/entry.c
                            src/header.c
                            src/input.c
                            src/inpvec.c
                            src/internal.c
                            src/mainnet.c
                            src/mpi.c
                            src/murmur3.c
                            src/netaddr.c
                            src/netmsg.c
                            src/network.c
                            src/outpoint.c
                            src/output.c
                            src/outvec.c
                            src/policy.c
                            src/script.c
                            src/tx.c
                            src/undo.c
                            src/util.c
                            src/vector.c
                            src/view.c)

list(APPEND node_sources src/node/addrman.c
                         src/node/chain.c
                         src/node/chaindb.c
                         src/node/io.c
                         src/node/logger.c
                         src/node/loop.c
                         src/node/printf.c
                         src/node/resolve.c
                         src/node/timedata.c)

list(APPEND satoshi_defines BTC_HAVE_ASM)
list(APPEND satoshi_defines BTC_HAVE_INT128)
list(APPEND satoshi_defines BTC_TLS=__thread)

if(WIN32)
  string(REPLACE "/" "\\" srcdir "${PROJECT_SOURCE_DIR}")
  list(APPEND satoshi_defines BTC_PREFIX="${srcdir}\\tmp")
else()
  list(APPEND satoshi_defines BTC_PREFIX="${PROJECT_SOURCE_DIR}/tmp")
endif()

if(MSVC)
  list(APPEND satoshi_cflags /wd4244
                             /wd4267)
else()
  list(APPEND satoshi_cflags -Wall
                             -Wextra
                             -Wcast-align
                             -Wno-implicit-fallthrough
                             -Wshadow)
endif()

list(APPEND satoshi_includes ${PROJECT_SOURCE_DIR}/include)

add_subdirectory(deps/lmdb)

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

add_library(satoshi_node STATIC ${node_sources})
target_compile_definitions(satoshi_node PUBLIC ${satoshi_defines})
target_compile_options(satoshi_node PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_node PUBLIC ${satoshi_includes})
target_link_options(satoshi_node INTERFACE ${satoshi_ldflags})
target_link_libraries(satoshi_node PRIVATE lmdb)
set_property(TARGET satoshi_node PROPERTY OUTPUT_NAME node)

add_library(satoshi_tests STATIC test/tests.c)
target_compile_definitions(satoshi_tests PUBLIC ${satoshi_defines})
target_compile_options(satoshi_tests PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_tests PUBLIC ${satoshi_includes})
target_link_options(satoshi_tests INTERFACE ${satoshi_ldflags})
set_property(TARGET satoshi_tests PROPERTY OUTPUT_NAME tests)

foreach(name ecdsa bip340 sighash script tx chaindb chain)
  add_executable(t-${name} test/t-${name}.c)
  target_link_options(t-${name} PRIVATE -Wl,-z,now)
  target_link_libraries(t-${name} PRIVATE satoshi_tests
                                          satoshi_node
                                          satoshi_shared)
  add_test(NAME ${name} COMMAND t-${name})
endforeach()
