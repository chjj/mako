# CMakeLists.txt - cmake build for mako
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

cmake_minimum_required(VERSION 3.4)
project(mako LANGUAGES C)

include(CTest)
include(TestBigEndian)

set(mako_sources)
set(mako_defines)
set(mako_cflags)
set(mako_includes)
set(mako_ldflags)
set(mako_libs)
set(io_sources)
set(node_sources)
set(client_sources)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED OFF)
set(CMAKE_C_VISIBILITY_PRESET hidden)

list(APPEND mako_sources src/crypto/chacha20.c
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
                         src/crypto/sysrand.c
                         src/json/json_builder.c
                         src/json/json_extra.c
                         src/json/json_parser.c
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
                         src/config.c
                         src/consensus.c
                         src/entry.c
                         src/header.c
                         src/heap.c
                         src/input.c
                         src/inpvec.c
                         src/inspect.c
                         src/internal.c
                         src/json.c
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
                         src/regtest.c
                         src/script.c
                         src/signet.c
                         src/simnet.c
                         src/sprintf.c
                         src/testnet.c
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
                         src/io/win/ps.c
                         src/io/win/sys.c
                         src/io/win/thread.c
                         src/io/win/time.c)
else()
  list(APPEND io_sources src/io/unix/fs.c
                         src/io/unix/net.c
                         src/io/unix/ps.c
                         src/io/unix/sys.c
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

list(APPEND client_sources src/client/client.c)

if(WIN32)
  list(APPEND mako_defines _WIN32_WINNT=0x501)
endif()

if(WIN32 AND NOT MINGW)
  list(APPEND mako_defines "BTC_TLS=__declspec(thread)")
else()
  list(APPEND mako_defines BTC_HAVE_ASM)
  list(APPEND mako_defines BTC_HAVE_INT128)
  if(NOT MINGW)
    list(APPEND mako_defines BTC_HAVE_CLOCK)
    list(APPEND mako_defines BTC_HAVE_PTHREAD)
    list(APPEND mako_defines BTC_TLS=__thread)
    list(APPEND mako_defines _GNU_SOURCE)
  endif()
endif()

test_big_endian(BTC_BIGENDIAN)

if(BTC_BIGENDIAN)
  list(APPEND mako_defines BTC_BIGENDIAN)
endif()

if(NOT CMAKE_CROSSCOMPILING)
  if(WIN32)
    string(REPLACE "/" "\\" srcdir "${PROJECT_SOURCE_DIR}")
    list(APPEND mako_defines BTC_PREFIX="${srcdir}\\tmp")
  else()
    list(APPEND mako_defines BTC_PREFIX="${PROJECT_SOURCE_DIR}/tmp")
  endif()
endif()

if(MSVC)
  list(APPEND mako_cflags /wd4244
                             /wd4267)
else()
  list(APPEND mako_cflags -pedantic
                             -Wall
                             -Wextra
                             -Wcast-align
                             -Wno-implicit-fallthrough
                             -Wno-long-long
                             -Wno-overlength-strings
                             -Wshadow)
endif()

list(APPEND mako_includes ${PROJECT_SOURCE_DIR}/include)

if(WIN32)
  list(APPEND mako_libs shell32 userenv ws2_32)
else()
  list(APPEND mako_libs m)
endif()

add_subdirectory(deps/lmdb)
add_subdirectory(deps/lsm1)

add_library(mako_lib STATIC ${mako_sources})
target_compile_definitions(mako_lib PUBLIC ${mako_defines})
target_compile_options(mako_lib PUBLIC ${mako_cflags})
target_include_directories(mako_lib PUBLIC ${mako_includes})
target_link_options(mako_lib INTERFACE ${mako_ldflags})
target_link_libraries(mako_lib PRIVATE ${mako_libs})
set_property(TARGET mako_lib PROPERTY OUTPUT_NAME mako)

add_library(mako_io STATIC ${io_sources})
target_compile_definitions(mako_io PUBLIC ${mako_defines})
target_compile_options(mako_io PUBLIC ${mako_cflags})
target_include_directories(mako_io PUBLIC ${mako_includes})
target_link_options(mako_io INTERFACE ${mako_ldflags})
target_link_libraries(mako_io PRIVATE pthread)
set_property(TARGET mako_io PROPERTY OUTPUT_NAME io)

add_library(mako_node STATIC ${node_sources})
target_compile_definitions(mako_node PUBLIC ${mako_defines})
target_compile_options(mako_node PUBLIC ${mako_cflags})
target_include_directories(mako_node PUBLIC ${mako_includes})
target_link_options(mako_node INTERFACE ${mako_ldflags})
target_link_libraries(mako_node PRIVATE lmdb lsm1)
set_property(TARGET mako_node PROPERTY OUTPUT_NAME node)

add_library(mako_client STATIC ${client_sources})
target_compile_definitions(mako_client PUBLIC ${mako_defines})
target_compile_options(mako_client PUBLIC ${mako_cflags})
target_include_directories(mako_client PUBLIC ${mako_includes})
target_link_options(mako_client INTERFACE ${mako_ldflags})
set_property(TARGET mako_client PROPERTY OUTPUT_NAME client)

add_library(mako_tests STATIC test/lib/tests.c test/lib/clean.c)
target_compile_definitions(mako_tests PUBLIC ${mako_defines})
target_compile_options(mako_tests PUBLIC ${mako_cflags})
target_include_directories(mako_tests PUBLIC ${mako_includes})
target_link_options(mako_tests INTERFACE ${mako_ldflags})
set_property(TARGET mako_tests PROPERTY OUTPUT_NAME tests)

add_executable(makod src/node/main.c)
target_link_libraries(makod PRIVATE mako_node
                                       mako_io
                                       mako_lib)

add_executable(mako src/client/main.c)
target_link_libraries(mako PRIVATE mako_client
                                      mako_io
                                      mako_lib)

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
          config
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
  target_link_libraries(t-${name} PRIVATE mako_tests
                                          mako_node
                                          mako_client
                                          mako_io
                                          mako_lib)
  add_test(NAME ${name} COMMAND t-${name})
endforeach()

foreach(name http_server)
  add_executable(t-${name} test/t-${name}.c)
  target_link_libraries(t-${name} PRIVATE mako_tests
                                          mako_node
                                          mako_client
                                          mako_io
                                          mako_lib)
endforeach()
