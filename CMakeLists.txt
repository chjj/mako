# CMakeLists.txt - cmake build for mako
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

set(MAKO_PKG_VERSION 0.0.0)
set(MAKO_ABI_VERSION 0:0:0)

#
# Initialization
#

cmake_minimum_required(VERSION 3.4)
project(mako VERSION ${MAKO_PKG_VERSION} LANGUAGES C)

#
# Toolchain/Platform Fixes
#

if(WASI)
  # No idea why this isn't set.
  set(CMAKE_EXECUTABLE_SUFFIX ".wasm")
endif()

if(EMSCRIPTEN)
  # CMAKE_CROSSCOMPILING_EMULATOR is mistakenly quoted by emcmake.
  string(REPLACE "\"" "" CMAKE_CROSSCOMPILING_EMULATOR
         "${CMAKE_CROSSCOMPILING_EMULATOR}")
endif()

#
# Includes
#

include(cmake/AppendCCompilerFlag.cmake)
include(cmake/FindPthread.cmake)
include(cmake/LibtoolEmulator.cmake)
include(cmake/TargetLinkOptions.cmake)
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CTest)
include(GNUInstallDirs)
include(TestBigEndian)

#
# Options
#

option(MAKO_ASM "Use inline assembly if available" ON)
option(MAKO_COVERAGE "Enable coverage" OFF)
option(MAKO_INT128 "Use __int128 if available" ON)
option(MAKO_LEVELDB "Use leveldb" OFF)
option(MAKO_NODE "Build the fullnode" ON)
option(MAKO_PIC "Enable PIC" OFF)
option(MAKO_PORTABLE "Be as portable as possible" OFF)
option(MAKO_PTHREAD "Use pthread" ON)
option(MAKO_SHARED "Build shared library" OFF)
option(MAKO_TESTS "Build tests" ON)

#
# Variables
#

set(mako_sources)
set(mako_cflags)
set(mako_defines)
set(mako_includes)
set(mako_ldflags)
set(mako_libs)

set(io_sources)
set(base_sources)
set(node_sources)
set(wallet_sources)
set(client_sources)
set(test_sources)
set(test_libs)

#
# Global Flags
#

if(NOT PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
  unset(CMAKE_C_STANDARD_REQUIRED)
  unset(CMAKE_C_EXTENSIONS)
  unset(CMAKE_C_STANDARD)
  unset(CMAKE_C_VISIBILITY_PRESET)
  unset(CMAKE_OSX_DEPLOYMENT_TARGET)
endif()

check_symbol_exists(__GLIBC__ "limits.h" MAKO_GLIBC)

if(MAKO_GLIBC)
  set(CMAKE_C_STANDARD 90)
  set(CMAKE_C_EXTENSIONS OFF)
  set(CMAKE_C_STANDARD_REQUIRED OFF)
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)

if(APPLE)
  set(CMAKE_OSX_DEPLOYMENT_TARGET 10.7)
endif()

#
# Feature Test Macros
#

if(WIN32)
  list(APPEND mako_defines _WIN32_WINNT=0x501)
endif()

if(MAKO_GLIBC)
  list(APPEND mako_defines _GNU_SOURCE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  list(APPEND mako_defines _TS_ERRNO)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
  list(APPEND mako_defines _THREAD_SAFE_ERRNO)
endif()

#
# System Libraries
#

if(WIN32)
  list(APPEND mako_libs kernel32 advapi32 ws2_32)
else()
  check_c_source_compiles([=[
#   include <math.h>
    int main(int argc, char **argv) {
      return (int)sqrt((double)argc);
    }
  ]=] MAKO_LIBC_MATH)

  if(NOT MAKO_LIBC_MATH)
    list(APPEND mako_libs m)
  endif()

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    check_c_source_compiles([=[
#     include <time.h>
      int main(int argc, char **argv) {
        return clock_gettime(argc, 0);
      }
    ]=] MAKO_LIBC_RT)

    if (NOT MAKO_LIBC_RT)
      list(APPEND mako_libs rt)
    endif()
  endif()

  if(MAKO_PTHREAD)
    find_pthread(_found _cflags _libs)

    if(_found)
      list(APPEND mako_cflags ${_cflags})
      list(APPEND mako_libs ${_libs})
      list(APPEND mako_defines BTC_PTHREAD)
    endif()
  endif()

  if(CMAKE_SYSTEM_NAME STREQUAL "Haiku")
    list(APPEND mako_libs network)
  endif()

  if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    list(APPEND mako_libs socket)
    list(APPEND mako_libs nsl)
  endif()
endif()

#
# Feature Testing
#

if(MAKO_ASM)
  check_c_source_compiles([=[
    int main(void) {
      unsigned long z = 953;
      unsigned long x = 109;
      unsigned long y = 577;
      unsigned long c;
      __asm__ __volatile__ (
#   if defined(__amd64__) || defined(__amd64)
        "movq $0, %q1\\n"
#   elif defined(__x86_64__) || defined(__x86_64)
        "movq $0, %q1\\n"
#   elif defined(__i386__) || defined(__i386) || defined(i386)
        "movl $0, %k1\\n"
#   else
        ""
#   endif
        : "+r" (z), "=&r" (c)
#   if defined(__wasm__) || defined(__EMSCRIPTEN__)
        :
#   elif defined(__TINYC__)
        : "rm" (x), "rm" (y)
#   else
        : "%rm" (x), "rm" (y)
#   endif
        : "cc", "memory"
      );
      return z & 0x7f;
    }
  ]=] MAKO_HAVE_ASM)
else()
  set(MAKO_HAVE_ASM)
endif()

test_big_endian(MAKO_BIGENDIAN)

if(MAKO_PORTABLE)
  set(MAKO_HAVE_CLOCK 0)
  set(MAKO_HAVE_GETHOSTNAME ${WIN32})
  set(MAKO_HAVE_GETIFADDRS 0)
  set(MAKO_HAVE_RFC3493 0)
elseif(WIN32)
  set(MAKO_HAVE_CLOCK 0)
  set(MAKO_HAVE_GETHOSTNAME 1)
  set(MAKO_HAVE_GETIFADDRS 0)
  set(MAKO_HAVE_RFC3493 1)
else()
  set(CMAKE_REQUIRED_LIBRARIES "${mako_libs}")

  check_c_source_compiles([=[
#   include <time.h>
    int main(void) {
      struct timespec ts;
      (void)clock_gettime((clockid_t)CLOCK_REALTIME, &ts);
      (void)clock_gettime((clockid_t)CLOCK_MONOTONIC, &ts);
      return ts.tv_sec & ts.tv_nsec & 0x7f;
    }
  ]=] MAKO_HAVE_CLOCK)

  check_c_source_compiles([=[
#   include <unistd.h>
    int main(void) {
      char name[256];
      return gethostname(name, sizeof(name));
    }
  ]=] MAKO_HAVE_GETHOSTNAME)

  check_c_source_compiles([=[
#   include <sys/types.h>
#   include <ifaddrs.h>
#   include <net/if.h>
    int main(void) {
      struct ifaddrs *addrs;
      return getifaddrs(&addrs);
    }
  ]=] MAKO_HAVE_GETIFADDRS)

  check_c_source_compiles([=[
#   include <stddef.h>
#   include <sys/types.h>
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <netdb.h>
    int main(void) {
      struct sockaddr_storage storage;
      struct sockaddr_in6 sai6;
      struct addrinfo *info;
      return getaddrinfo("localhost", NULL, NULL, &info);
    }
  ]=] MAKO_HAVE_RFC3493)

  unset(CMAKE_REQUIRED_LIBRARIES)
endif()

if(MAKO_INT128)
  check_c_source_compiles([=[
    typedef signed __int128 xint128_t;
    typedef unsigned __int128 xuint128_t;
    typedef char check_voidptr_t[sizeof(void *) >= 8 ? 1 : -1];
    typedef char check_int128_t[sizeof(xint128_t) == 16 ? 1 : -1];
    typedef char check_uint128_t[sizeof(xuint128_t) == 16 ? 1 : -1];
    int main(int argc, char **argv) {
      xint128_t c = argv[0][0];
      xuint128_t r = argc + c;
      while (argc--) r *= r;
      return r >> 121;
    }
  ]=] MAKO_HAVE_INT128)
else()
  set(MAKO_HAVE_INT128)
endif()

set(MAKO_HAVE_ZLIB 0)

if(MAKO_TESTS)
  check_include_file(zlib.h MAKO_HAVE_ZLIB_H)
  check_library_exists(z compress2 "" MAKO_HAVE_ZLIB_A)

  if(MAKO_HAVE_ZLIB_H AND MAKO_HAVE_ZLIB_A)
    set(MAKO_HAVE_ZLIB 1)
  endif()
endif()

#
# Sources
#

list(APPEND mako_sources src/crypto/chacha20.c
                         src/crypto/drbg.c
                         src/crypto/ecc.c
                         src/crypto/hash160.c
                         src/crypto/hash256.c
                         src/crypto/hmac256.c
                         src/crypto/hmac512.c
                         src/crypto/merkle.c
                         src/crypto/poly1305.c
                         src/crypto/pbkdf256.c
                         src/crypto/pbkdf512.c
                         src/crypto/rand.c
                         src/crypto/rand_env.c
                         src/crypto/rand_sys.c
                         src/crypto/ripemd160.c
                         src/crypto/salsa20.c
                         src/crypto/secretbox.c
                         src/crypto/sha1.c
                         src/crypto/sha256.c
                         src/crypto/sha512.c
                         src/crypto/siphash.c
                         src/json/json_builder.c
                         src/json/json_extra.c
                         src/json/json_parser.c
                         src/map/addrmap.c
                         src/map/addrset.c
                         src/map/hashmap.c
                         src/map/hashset.c
                         src/map/hashtab.c
                         src/map/intmap.c
                         src/map/longmap.c
                         src/map/longset.c
                         src/map/longtab.c
                         src/map/netmap.c
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
                         src/select.c
                         src/sign.c
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
                       src/io/net.c
                       src/io/sockaddr.c
                       src/io/workers.c)

list(APPEND base_sources src/base/addrman.c
                         src/base/config.c
                         src/base/logger.c
                         src/base/timedata.c)

list(APPEND node_sources src/node/chain.c
                         src/node/chaindb.c
                         src/node/mempool.c
                         src/node/miner.c
                         src/node/node.c
                         src/node/pool.c
                         src/node/rpc.c)

list(APPEND wallet_sources src/wallet/account.c
                           src/wallet/client.c
                           src/wallet/iterator.c
                           src/wallet/master.c
                           src/wallet/record.c
                           src/wallet/txdb.c
                           src/wallet/wallet.c)

list(APPEND client_sources src/client/client.c)

list(APPEND test_sources test/lib/tests.c test/lib/rimraf.c)

#
# Flags
#

if(MSVC)
  append_c_compiler_flag(mako_cflags /wd4146  # negation of unsigned integer
                                     /wd4244  # implicit integer demotion
                                     /wd4267  # implicit size_t demotion
                                     /wd4334) # implicit 32->64 bit shift
elseif(BORLAND)
# Todo.
elseif(CMAKE_C_COMPILER_ID MATCHES "Watcom$")
  append_c_compiler_flag(mako_cflags -wcd=201  # unreachable code
                                     -wcd=202) # unused symbol
else()
  append_c_compiler_flag(mako_cflags -pedantic
                                     -Wall
                                     -Wextra
                                     -Wcast-align
                                     -Wcast-align=strict
                                     -Wconditional-uninitialized
                                     -Wmissing-prototypes
                                     -Wno-implicit-fallthrough
                                     -Wno-long-long
                                     -Wno-overlength-strings
                                     -Wshadow
                                     -Wstrict-prototypes
                                     -Wundef)
endif()

if(MAKO_COVERAGE)
  list(APPEND mako_cflags -O0 --coverage)
  list(APPEND mako_ldflags --coverage)
endif()

if(MINGW)
  # Ensure we are redistributable on windows.
  list(APPEND mako_ldflags -static-libgcc)
  # Much compatibility.
  if(MAKO_PORTABLE AND MINGW_ARCH STREQUAL "i686")
    list(APPEND mako_cflags -march=i486 -mtune=i686)
    list(APPEND mako_ldflags -march=i486 -mtune=i686)
  endif()
endif()

#
# Defines
#

if(MAKO_HAVE_ASM)
  list(APPEND mako_defines BTC_HAVE_ASM)
endif()

if(MAKO_BIGENDIAN)
  list(APPEND mako_defines BTC_BIGENDIAN)
endif()

if(MAKO_HAVE_CLOCK)
  list(APPEND mako_defines BTC_HAVE_CLOCK)
endif()

if(MAKO_COVERAGE)
  list(APPEND mako_defines BTC_COVERAGE)
endif()

list(APPEND mako_defines $<$<CONFIG:Debug>:BTC_DEBUG>)

if(MAKO_HAVE_GETHOSTNAME)
  list(APPEND mako_defines BTC_HAVE_GETHOSTNAME)
endif()

if(MAKO_HAVE_GETIFADDRS)
  list(APPEND mako_defines BTC_HAVE_GETIFADDRS)
endif()

if(MAKO_HAVE_INT128)
  list(APPEND mako_defines BTC_HAVE_INT128)
endif()

if(MAKO_PORTABLE)
  list(APPEND mako_defines BTC_PORTABLE)
endif()

if(MAKO_HAVE_RFC3493)
  list(APPEND mako_defines BTC_HAVE_RFC3493)
endif()

if(MAKO_HAVE_ZLIB)
  list(APPEND mako_defines BTC_HAVE_ZLIB)
endif()

#
# Includes
#

list(APPEND mako_includes ${PROJECT_SOURCE_DIR}/include)

#
# Libraries
#

if(MAKO_HAVE_ZLIB)
  list(APPEND test_libs z)
endif()

#
# Targets
#

function(mako_build_full)
  #
  # Interface Library
  #

  add_library(mako INTERFACE)
  target_compile_definitions(mako INTERFACE ${mako_defines})
  target_compile_options(mako INTERFACE ${mako_cflags})
  target_include_directories(mako INTERFACE ${mako_includes})
  target_link_options(mako INTERFACE ${mako_ldflags})
  target_link_libraries(mako INTERFACE ${mako_libs})

  #
  # Static Library
  #

  add_library(mako_static STATIC ${mako_sources})
  target_link_libraries(mako_static PRIVATE mako)
  set_property(TARGET mako_static PROPERTY POSITION_INDEPENDENT_CODE
                                           ${MAKO_PIC})

  if(WIN32)
    set_property(TARGET mako_static PROPERTY OUTPUT_NAME libmako)
  else()
    set_property(TARGET mako_static PROPERTY OUTPUT_NAME mako)
  endif()

  if(MINGW)
    set_target_properties(mako_static PROPERTIES PREFIX "" SUFFIX ".lib")
  endif()

  #
  # Test Library
  #

  add_library(mako_test STATIC ${test_sources})
  target_link_libraries(mako_test PRIVATE mako ${test_libs})
  set_property(TARGET mako_test PROPERTY OUTPUT_NAME test)

  mako_tests_lib()

  if(WASI OR EMSCRIPTEN)
    return()
  endif()

  #
  # Shared Library
  #

  if(MAKO_SHARED)
    add_library(mako_shared SHARED ${mako_sources})
    target_compile_definitions(mako_shared PRIVATE BTC_EXPORT)
    target_link_libraries(mako_shared PRIVATE mako)
    set_property(TARGET mako_shared PROPERTY OUTPUT_NAME mako)
    set_target_version_info(mako_shared ${MAKO_ABI_VERSION})

    if(MINGW)
      set_target_properties(mako_shared PROPERTIES PREFIX ""
                                                   SUFFIX ".dll"
                                                   IMPORT_PREFIX ""
                                                   IMPORT_SUFFIX ".lib")
      target_link_options(mako_shared PRIVATE -Wl,--output-def,mako.def)
    endif()
  endif()

  #
  # Install Targets
  #

  if(UNIX)
    string(REPLACE ";" " -l" PKGCONF_LIBS "-l${mako_libs}")

    configure_file(libmako-cmake.pc.in libmako.pc @ONLY)

    install(DIRECTORY include/mako/
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mako)
    install(FILES LICENSE
            DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/${PROJECT_NAME})
    install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
    install(FILES ${PROJECT_BINARY_DIR}/libmako.pc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    install(TARGETS mako_static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

    if(MAKO_SHARED)
      install(TARGETS mako_shared
              ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
              LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()
  endif()

  if(WIN32)
    install(DIRECTORY include/mako/ DESTINATION include/mako)
    install(FILES LICENSE README.md DESTINATION .)
    install(TARGETS mako_static ARCHIVE DESTINATION lib/$<CONFIG>)

    if(MAKO_SHARED)
      install(TARGETS mako_shared
              ARCHIVE DESTINATION lib/$<CONFIG>
              RUNTIME DESTINATION lib/$<CONFIG>)
    endif()
  endif()

  if(NOT MAKO_NODE)
    return()
  endif()

  #
  # Node Targets
  #

  if(MAKO_LEVELDB)
    add_subdirectory(deps/lcdb/contrib/lwdb)
  else()
    add_subdirectory(deps/lcdb)
  endif()

  add_library(mako_io STATIC ${io_sources})
  target_link_libraries(mako_io PRIVATE mako)
  set_property(TARGET mako_io PROPERTY OUTPUT_NAME io)

  add_library(mako_base STATIC ${base_sources})
  target_link_libraries(mako_base PRIVATE mako mako_io mako_static)
  set_property(TARGET mako_base PROPERTY OUTPUT_NAME base)

  add_library(mako_node STATIC ${node_sources})
  target_link_libraries(mako_node PRIVATE mako mako_base lcdb)
  set_property(TARGET mako_node PROPERTY OUTPUT_NAME node)

  add_library(mako_wallet STATIC ${wallet_sources})
  target_link_libraries(mako_wallet PRIVATE mako mako_base lcdb)
  set_property(TARGET mako_wallet PROPERTY OUTPUT_NAME wallet)

  add_library(mako_client STATIC ${client_sources})
  target_link_libraries(mako_client PRIVATE mako mako_base)
  set_property(TARGET mako_client PROPERTY OUTPUT_NAME client)

  add_executable(mako_daemon src/node/main.c)
  target_link_libraries(mako_daemon PRIVATE mako mako_node mako_wallet)
  set_property(TARGET mako_daemon PROPERTY OUTPUT_NAME makod)

  add_executable(mako_cli src/client/main.c)
  target_link_libraries(mako_cli PRIVATE mako mako_client)
  set_property(TARGET mako_cli PROPERTY OUTPUT_NAME mako)

  mako_tests_node()

  if(UNIX)
    install(TARGETS mako_daemon mako_cli
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()

  if(WIN32)
    install(TARGETS mako_daemon mako_cli
            RUNTIME DESTINATION bin/$<CONFIG>)
  endif()
endfunction()

function(mako_build_sub)
  # Bulding a subproject. Keep it simple.
  if(COMMAND add_node_library)
    add_node_library(mako STATIC ${mako_sources})
  else()
    add_library(mako STATIC ${mako_sources})
    set_property(TARGET mako PROPERTY POSITION_INDEPENDENT_CODE ${MAKO_PIC})
  endif()

  target_compile_definitions(mako PRIVATE ${mako_defines})
  target_compile_options(mako PRIVATE ${mako_cflags})
  target_include_directories(mako PUBLIC ${mako_includes})
  target_link_options(mako INTERFACE ${mako_ldflags})
  target_link_libraries(mako INTERFACE ${mako_libs})
endfunction()

#
# Tests
#

function(mako_tests_lib)
  set(tests_lib # crypto
                bip340
                chacha20
                drbg
                ecdsa
                hash160
                hash256
                hmac
                merkle
                poly1305
                pbkdf2
                rand
                ripemd160
                salsa20
                secretbox
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
                view)

  if(MAKO_TESTS)
    foreach(name ${tests_lib})
      add_executable(t-${name} test/t-${name}.c)
      target_link_libraries(t-${name} PRIVATE mako mako_test mako_static)
      add_test(NAME ${name} COMMAND t-${name})
    endforeach()
  endif()
endfunction()

function(mako_tests_node)
  set(tests_io addrinfo
               sockaddr
               fs
               loop
               thread
               http
               workers)

  set(tests_base addrman
                 config
                 timedata)

  set(tests_node chaindb
                 chain
                 mempool
                 miner
                 rpc)

  set(tests_wallet wallet)

  if(MAKO_TESTS)
    foreach(name ${tests_io})
      add_executable(t-${name} test/t-${name}.c)
      target_link_libraries(t-${name} PRIVATE mako mako_test mako_io)
      add_test(NAME ${name} COMMAND t-${name})
    endforeach()

    foreach(name ${tests_base})
      add_executable(t-${name} test/t-${name}.c)
      target_link_libraries(t-${name} PRIVATE mako mako_test mako_base)
      add_test(NAME ${name} COMMAND t-${name})
    endforeach()

    foreach(name ${tests_node})
      add_executable(t-${name} test/t-${name}.c)
      target_link_libraries(t-${name} PRIVATE mako mako_test mako_node)
      add_test(NAME ${name} COMMAND t-${name})
    endforeach()

    foreach(name ${tests_wallet})
      add_executable(t-${name} test/t-${name}.c)
      target_link_libraries(t-${name} PRIVATE mako mako_test mako_wallet)
      add_test(NAME ${name} COMMAND t-${name})
    endforeach()
  endif()
endfunction()

#
# Summary
#

function(mako_build_summary)
  set(build_type "")

  if(DEFINED CMAKE_BUILD_TYPE AND CMAKE_BUILD_TYPE)
    string(TOUPPER "${CMAKE_BUILD_TYPE}" build_type)
  endif()

  message(STATUS "Build Options:

   BUILD_TYPE:     ${CMAKE_BUILD_TYPE}
   INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}
   SYSTEM:         ${CMAKE_SYSTEM} (${CMAKE_SYSTEM_PROCESSOR})
   C_COMPILER:     ${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID})
   C_FLAGS:        ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${build_type}}
   SHARED_FLAGS:   ${CMAKE_SHARED_LINKER_FLAGS}
   EXE_FLAGS:      ${CMAKE_EXE_LINKER_FLAGS}

   mako_cflags:    ${mako_cflags}
   mako_ldflags:   ${mako_ldflags}
   mako_defines:   ${mako_defines}
   mako_libs:      ${mako_libs}
   test_libs:      ${test_libs}
")
endfunction()

#
# Build
#

if(NOT PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
  mako_build_sub()
else()
  mako_build_full()
  mako_build_summary()
endif()
