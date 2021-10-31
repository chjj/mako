# CMakeLists.txt - cmake build for libsatoshi
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj/libsatoshi

cmake_minimum_required(VERSION 3.4)
project(satoshi LANGUAGES C)

include(CTest)
include(TestBigEndian)

set(satoshi_sources)
set(satoshi_defines)
set(satoshi_cflags)
set(satoshi_includes)
set(satoshi_ldflags)
set(satoshi_libs)
set(io_sources)
set(node_sources)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED OFF)
set(CMAKE_C_VISIBILITY_PRESET hidden)

list(APPEND satoshi_sources src/crypto/chacha20.c
                            src/crypto/drbg.c
                            src/crypto/ecc.c
                            src/crypto/hash160.c
                            src/crypto/hash256.c
                            src/crypto/hmac256.c
                            src/crypto/hmac512.c
                            src/crypto/merkle.c
                            src/crypto/pbkdf256.c
                            src/crypto/pbkdf512.c
                            src/crypto/rand.c
                            src/crypto/ripemd160.c
                            src/crypto/sha1.c
                            src/crypto/sha256.c
                            src/crypto/sha512.c
                            src/crypto/siphash.c
                            src/crypto/sys.c
                            src/map/addrmap.c
                            src/map/hashmap.c
                            src/map/hashset.c
                            src/map/hashtab.c
                            src/map/intmap.c
                            src/map/longmap.c
                            src/map/longset.c
                            src/map/longtab.c
                            src/map/outmap.c
                            src/map/outset.c
                            src/address.c
                            src/amount.c
                            src/array.c
                            src/base16.c
                            src/base58.c
                            src/bech32.c
                            src/bip32.c
                            src/bip37.c
                            src/bip39.c
                            src/bip152.c
                            src/block.c
                            src/bloom.c
                            src/buffer.c
                            src/coin.c
                            src/compact.c
                            src/compress.c
                            src/consensus.c
                            src/entry.c
                            src/header.c
                            src/heap.c
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
                            src/printf.c
                            src/printf_core.c
                            src/script.c
                            src/sprintf.c
                            src/tx.c
                            src/undo.c
                            src/util.c
                            src/vector.c
                            src/view.c)

list(APPEND io_sources src/io/http/http_client.c
                       src/io/http/http_common.c
                       src/io/http/http_parser.c
                       src/io/http/http_server.c
                       src/io/addrinfo.c
                       src/io/core.c
                       src/io/loop.c
                       src/io/sockaddr.c
                       src/io/workers.c)

if(WIN32)
  list(APPEND io_sources src/io/win/fs.c
                         src/io/win/net.c
                         src/io/win/thread.c
                         src/io/win/time.c)
else()
  list(APPEND io_sources src/io/unix/fs.c
                         src/io/unix/net.c
                         src/io/unix/thread.c
                         src/io/unix/time.c)
endif()

list(APPEND node_sources src/node/addrman.c
                         src/node/chain.c
                         src/node/chaindb.c
                         src/node/logger.c
                         src/node/mempool.c
                         src/node/miner.c
                         src/node/node.c
                         src/node/pool.c
                         src/node/rpc.c
                         src/node/timedata.c)

if(WIN32)
  list(APPEND satoshi_defines _WIN32_WINNT=0x501)
endif()

if(WIN32 AND NOT MINGW)
  list(APPEND satoshi_defines "BTC_TLS=__declspec(thread)")
else()
  list(APPEND satoshi_defines BTC_HAVE_ASM)
  list(APPEND satoshi_defines BTC_HAVE_INT128)
  if(NOT MINGW)
    list(APPEND satoshi_defines BTC_TLS=__thread)
    list(APPEND satoshi_defines _GNU_SOURCE)
  endif()
endif()

test_big_endian(BTC_BIGENDIAN)

if(BTC_BIGENDIAN)
  list(APPEND satoshi_defines BTC_BIGENDIAN)
endif()

if(NOT CMAKE_CROSSCOMPILING)
  if(WIN32)
    string(REPLACE "/" "\\" srcdir "${PROJECT_SOURCE_DIR}")
    list(APPEND satoshi_defines BTC_PREFIX="${srcdir}\\tmp")
  else()
    list(APPEND satoshi_defines BTC_PREFIX="${PROJECT_SOURCE_DIR}/tmp")
  endif()
endif()

if(MSVC)
  list(APPEND satoshi_cflags /wd4244
                             /wd4267)
else()
  list(APPEND satoshi_cflags -pedantic
                             -Wall
                             -Wextra
                             -Wcast-align
                             -Wno-implicit-fallthrough
                             -Wno-long-long
                             -Wno-overlength-strings
                             -Wshadow)
endif()

list(APPEND satoshi_includes ${PROJECT_SOURCE_DIR}/include)

if(WIN32)
  list(APPEND satoshi_libs ws2_32)
else()
  list(APPEND satoshi_libs m)
endif()

add_subdirectory(deps/json)
add_subdirectory(deps/lmdb)

add_library(satoshi_static STATIC ${satoshi_sources})
target_compile_definitions(satoshi_static PUBLIC ${satoshi_defines})
target_compile_options(satoshi_static PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_static PUBLIC ${satoshi_includes})
target_link_options(satoshi_static INTERFACE ${satoshi_ldflags})
target_link_libraries(satoshi_static PRIVATE ${satoshi_libs})
set_property(TARGET satoshi_static PROPERTY OUTPUT_NAME satoshi)

# add_library(satoshi_shared SHARED ${satoshi_sources})
# target_compile_definitions(satoshi_shared PUBLIC ${satoshi_defines}
#                                           PRIVATE BTC_EXPORT)
# target_compile_options(satoshi_shared PUBLIC ${satoshi_cflags})
# target_include_directories(satoshi_shared PUBLIC ${satoshi_includes})
# target_link_options(satoshi_shared PUBLIC ${satoshi_ldflags})
# target_link_libraries(satoshi_shared PRIVATE ${satoshi_libs})
# set_property(TARGET satoshi_shared PROPERTY OUTPUT_NAME satoshi)

add_library(satoshi_io STATIC ${io_sources})
target_compile_definitions(satoshi_io PUBLIC ${satoshi_defines})
target_compile_options(satoshi_io PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_io PUBLIC ${satoshi_includes})
target_link_options(satoshi_io INTERFACE ${satoshi_ldflags})
target_link_libraries(satoshi_io PRIVATE pthread)
set_property(TARGET satoshi_io PROPERTY OUTPUT_NAME io)

add_library(satoshi_node STATIC ${node_sources})
target_compile_definitions(satoshi_node PUBLIC ${satoshi_defines})
target_compile_options(satoshi_node PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_node PUBLIC ${satoshi_includes})
target_link_options(satoshi_node INTERFACE ${satoshi_ldflags})
target_link_libraries(satoshi_node PRIVATE json lmdb)
set_property(TARGET satoshi_node PROPERTY OUTPUT_NAME node)

add_library(satoshi_tests STATIC test/lib/tests.c test/lib/clean.c)
target_compile_definitions(satoshi_tests PUBLIC ${satoshi_defines})
target_compile_options(satoshi_tests PUBLIC ${satoshi_cflags})
target_include_directories(satoshi_tests PUBLIC ${satoshi_includes})
target_link_options(satoshi_tests INTERFACE ${satoshi_ldflags})
set_property(TARGET satoshi_tests PROPERTY OUTPUT_NAME tests)

add_executable(satoshid src/node/main.c)
target_link_libraries(satoshid PRIVATE satoshi_node
                                       satoshi_io
                                       satoshi_static)

set(tests # crypto
          bip340
          chacha20
          drbg
          ecdsa
          hash160
          hash256
          hmac
          merkle
          pbkdf2
          rand
          ripemd160
          sha1
          sha256
          sha512
          siphash
          # lib
          address
          array
          base16
          base58
          bech32
          bip32
          bip37
          bip39
          bip152
          block
          bloom
          coin
          entry
          header
          heap
          input
          "list"
          map
          mpi
          murmur3
          netaddr
          netmsg
          outpoint
          output
          printf
          script
          sighash
          tx
          util
          vector
          view
          # io
          addrinfo
          sockaddr
          fs
          loop
          thread
          http_client
          workers
          # node
          addrman
          chaindb
          chain
          mempool
          miner
          rpc
          timedata)

foreach(name ${tests})
  add_executable(t-${name} test/t-${name}.c)
  target_link_libraries(t-${name} PRIVATE satoshi_tests
                                          satoshi_node
                                          satoshi_io
                                          satoshi_static)
  add_test(NAME ${name} COMMAND t-${name})
endforeach()

foreach(name http_server)
  add_executable(t-${name} test/t-${name}.c)
  target_link_libraries(t-${name} PRIVATE satoshi_tests
                                          satoshi_node
                                          satoshi_io
                                          satoshi_static)
endforeach()
