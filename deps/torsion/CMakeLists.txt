# CMakeLists.txt - cmake build for libtorsion
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/libtorsion

set(TORSION_PKG_VERSION 0.0.0)
set(TORSION_ABI_VERSION 0:0:0)

#
# Initialization
#

cmake_minimum_required(VERSION 3.4)
project(libtorsion VERSION ${TORSION_PKG_VERSION} LANGUAGES C)

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
include(cmake/CheckCThreadLocalStorage.cmake)
include(cmake/LibtoolEmulator.cmake)
include(cmake/TargetLinkOptions.cmake)
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)
include(CTest)
include(GNUInstallDirs)

#
# Options
#

option(TORSION_ENABLE_ASM "Use inline assembly if available" ON)
option(TORSION_ENABLE_COVERAGE "Enable coverage" OFF)
option(TORSION_ENABLE_DEBUG "Enable debug build (forces -g or /Zi)" OFF)
option(TORSION_ENABLE_INT128 "Use __int128 if available" ON)
option(TORSION_ENABLE_MPI "Export MPI functions" OFF)
option(TORSION_ENABLE_PIC "Enable PIC" ON)
option(TORSION_ENABLE_PTHREAD "Use pthread if present in libc" ON)
option(TORSION_ENABLE_RNG "Enable RNG" ON)
option(TORSION_ENABLE_SHARED "Build shared library" ON)
option(TORSION_ENABLE_TESTS "Build tests" ON)
option(TORSION_ENABLE_TLS "Use thread-local storage if available" ON)
option(TORSION_ENABLE_VERIFY "Enable scalar bounds checks" OFF)

if(WASI OR EMSCRIPTEN)
  set(TORSION_INITIAL_MEMORY "16777216" CACHE STRING "WASM initial memory")
  set(TORSION_MAX_MEMORY "2147483648" CACHE STRING "WASM maximum memory")
  set(TORSION_STACK_SIZE "5242880" CACHE STRING "WASM stack size")
endif()

if(EMSCRIPTEN)
  set(TORSION_ENVIRONMENT "node" CACHE STRING "Emscripten environment")
endif()

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

set(CMAKE_C_VISIBILITY_PRESET hidden)

if(APPLE)
  set(CMAKE_OSX_DEPLOYMENT_TARGET 10.7)
endif()

#
# Compiler Fixes
#

# Encourage the user to build with xlc_r.
if(CMAKE_C_COMPILER_ID STREQUAL "XL" AND CMAKE_SYSTEM_NAME STREQUAL "AIX")
  check_symbol_exists(_THREAD_SAFE "" TORSION_HAVE_XLC_R)

  if(NOT TORSION_HAVE_XLC_R)
    message(WARNING "Please use a thread-safe compiler invocation.\n"
                    "For example, `cmake . -DCMAKE_C_COMPILER=xlc_r`.")
  endif()
endif()

# Not sure why cmake fails to do this for tcc.
if(CMAKE_C_COMPILER_ID STREQUAL "TinyCC" AND NOT CMAKE_SKIP_RPATH)
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath,'${PROJECT_SOURCE_DIR}'")
endif()

# Modern glibc (stdlib.h in particular) breaks pcc.
check_symbol_exists(__PCC__ "" TORSION_HAVE_PCC)
check_symbol_exists(__GLIBC__ "limits.h" TORSION_HAVE_GLIBC)

if(TORSION_HAVE_PCC AND TORSION_HAVE_GLIBC)
  check_type_size(__float128 TORSION_SIZEOF_FLOAT128)

  if (NOT TORSION_SIZEOF_FLOAT128)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__float128='long double'")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__TC__=__SC__")
  endif()
endif()

# NWCC has issues with -fPIC and shared libraries.
check_symbol_exists(__NWCC__ "" TORSION_HAVE_NWCC)

if(TORSION_HAVE_NWCC)
  set(TORSION_ENABLE_PIC OFF)
  set(TORSION_ENABLE_SHARED OFF)
endif()

# chibicc doesn't support .so versioning.
# Furthermore, CMake doesn't know about chibicc's -fPIC.
check_symbol_exists(__chibicc__ "" TORSION_HAVE_CHIBICC)

if(TORSION_HAVE_CHIBICC)
  set(CMAKE_C_COMPILE_OPTIONS_PIC "-fPIC")
  set(CMAKE_SHARED_LIBRARY_C_FLAGS "-fPIC")
  set(TORSION_ENABLE_SHARED OFF)
endif()

# OpenWatcom-Linux can't create shared libraries.
if(CMAKE_C_COMPILER_ID STREQUAL "OpenWatcom")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(TORSION_ENABLE_SHARED OFF)
  endif()
endif()

# dietlibc is for static linking only.
check_symbol_exists(__dietlibc__ "" TORSION_HAVE_DIETLIBC)

if(TORSION_HAVE_DIETLIBC)
  set(TORSION_ENABLE_SHARED OFF)
endif()

#
# Feature Testing
#

if(TORSION_ENABLE_ASM)
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
#   elif defined(__arm__) || defined(__aarch64__)
        "mov %1, #0\\n"
#   elif defined(__powerpc__) || defined(__powerpc64__) || defined(__PPC__)
        "li %1, 0\\n"
#   elif defined(__riscv)
        "lui %1, 0\\n"
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
  ]=] TORSION_HAS_ASM)
else()
  set(TORSION_HAS_ASM)
endif()

if(TORSION_ENABLE_TESTS AND NOT APPLE)
  check_c_source_compiles([=[
#   include <time.h>
    int main(void) {
      struct timespec ts;
      (void)clock_gettime(CLOCK_REALTIME, &ts);
      (void)clock_gettime(CLOCK_MONOTONIC, &ts);
      return ts.tv_sec & ts.tv_nsec & 0x7f;
    }
  ]=] TORSION_HAS_CLOCK_GETTIME)
else()
  set(TORSION_HAS_CLOCK_GETTIME)
endif()

if(TORSION_ENABLE_TESTS AND NOT EMSCRIPTEN)
  check_c_source_compiles([=[
#   include <sys/types.h>
#   include <sys/wait.h>
#   include <unistd.h>
    int main(void) {
      unsigned char data[32];
      int pfds[2];
      int status;
      pid_t pid;
      pipe(pfds);
      pid = fork();
      close(pfds[1]);
      read(pfds[0], data, 32);
      close(pfds[0]);
      waitpid(pid, &status, 0);
      WIFEXITED(status);
      WEXITSTATUS(status);
      return status;
    }
  ]=] TORSION_HAS_FORK)
else()
  set(TORSION_HAS_FORK)
endif()

if(TORSION_ENABLE_TESTS)
  check_c_source_compiles([=[
#   include <stddef.h>
#   include <sys/time.h>
    int main(void) {
      struct timeval tv;
      (void)gettimeofday(&tv, NULL);
      return tv.tv_sec & tv.tv_usec & 0x7f;
    }
  ]=] TORSION_HAS_GETTIMEOFDAY)
else()
  set(TORSION_HAS_GETTIMEOFDAY)
endif()

if(TORSION_ENABLE_INT128)
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
  ]=] TORSION_HAS_INT128)
else()
  set(TORSION_HAS_INT128)
endif()

if(TORSION_ENABLE_PTHREAD AND NOT EMSCRIPTEN)
  check_c_source_compiles([=[
#   include <pthread.h>
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    int main(void) {
      (void)pthread_mutex_lock(&lock);
      (void)pthread_mutex_unlock(&lock);
      return 0;
    }
  ]=] TORSION_HAS_PTHREAD)
else()
  set(TORSION_HAS_PTHREAD)
endif()

if(TORSION_ENABLE_TESTS)
  check_c_source_compiles([=[
#   include <stddef.h>
#   include <time.h>
    int main(void) {
      return time(NULL) & 0x7f;
    }
  ]=] TORSION_HAS_TIME)
else()
  set(TORSION_HAS_TIME)
endif()

if(TORSION_ENABLE_TLS)
  check_c_thread_local_storage(TORSION_TLS_KEYWORD
                               TORSION_TLS_FLAG
                               TORSION_TLS_EMULATED)

  # Prefer pthread stubs over emulated TLS.
  if(TORSION_TLS_EMULATED AND TORSION_HAS_PTHREAD)
    set(TORSION_TLS_KEYWORD "")
    set(TORSION_TLS_FLAG "")
  endif()
else()
  set(TORSION_TLS_KEYWORD)
  set(TORSION_TLS_FLAG)
endif()

set(TORSION_HAS_MEMCHECK 0)
set(TORSION_HAS_ZLIB 0)

if(TORSION_ENABLE_TESTS)
  check_include_file(valgrind/memcheck.h TORSION_HAS_MEMCHECK_H)

  if(TORSION_HAS_MEMCHECK_H)
    set(TORSION_HAS_MEMCHECK 1)
  endif()

  if (TORSION_ENABLE_RNG)
    check_include_file(zlib.h TORSION_HAS_ZLIB_H)
    check_library_exists(z compress2 "" TORSION_HAS_ZLIB_A)

    if(TORSION_HAS_ZLIB_H AND TORSION_HAS_ZLIB_A)
      set(TORSION_HAS_ZLIB 1)
    endif()
  endif()
endif()

#
# Flags
#

set(torsion_cflags)
set(torsion_ldflags)
set(torsion_exeflags)

if(MSVC)
  append_c_compiler_flag(torsion_cflags /wd4146  # negation of unsigned integer
                                        /wd4244  # implicit integer demotion
                                        /wd4267  # implicit size_t demotion
                                        /wd4334) # implicit 32->64 bit shift
elseif(BORLAND)
# Todo.
elseif(CMAKE_C_COMPILER_ID MATCHES "Watcom$")
  append_c_compiler_flag(torsion_cflags -wcd=201  # unreachable code
                                        -wcd=202) # unused symbol
else()
  append_c_compiler_flag(torsion_cflags -pedantic
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

if(TORSION_ENABLE_COVERAGE)
  list(APPEND torsion_cflags -O0 --coverage)
  list(APPEND torsion_ldflags --coverage)
endif()

if(TORSION_ENABLE_DEBUG)
  if(MSVC)
    append_c_compiler_flag(torsion_cflags /Zi)
  elseif(BORLAND)
    append_c_compiler_flag(torsion_cflags -v)
  elseif(CMAKE_C_COMPILER_ID MATCHES "Watcom$")
    append_c_compiler_flag(torsion_cflags -d2)
  else()
    append_c_compiler_flag(torsion_cflags -g)
  endif()
endif()

if(TORSION_TLS_FLAG)
  list(APPEND torsion_cflags ${TORSION_TLS_FLAG})
endif()

if(MINGW)
  # Ensure we are redistributable on windows.
  list(APPEND torsion_ldflags -static-libgcc)
endif()

#
# Defines
#

set(torsion_defines)

list(APPEND torsion_defines TORSION_HAVE_CONFIG)

if(TORSION_HAS_ASM)
  list(APPEND torsion_defines TORSION_HAVE_ASM)
endif()

if(TORSION_HAS_CLOCK_GETTIME)
  list(APPEND torsion_defines TORSION_HAVE_CLOCK_GETTIME)
endif()

if(TORSION_ENABLE_COVERAGE)
  list(APPEND torsion_defines TORSION_COVERAGE)
endif()

if(TORSION_ENABLE_DEBUG)
  list(APPEND torsion_defines TORSION_DEBUG)
else()
  list(APPEND torsion_defines $<$<CONFIG:Debug>:TORSION_DEBUG>)
endif()

if(TORSION_HAS_FORK)
  list(APPEND torsion_defines TORSION_HAVE_FORK)
endif()

if(TORSION_HAS_GETTIMEOFDAY)
  list(APPEND torsion_defines TORSION_HAVE_GETTIMEOFDAY)
endif()

if(TORSION_HAS_INT128)
  list(APPEND torsion_defines TORSION_HAVE_INT128)
endif()

if(TORSION_ENABLE_MPI)
  list(APPEND torsion_defines TORSION_HAVE_MPI)
endif()

if(TORSION_HAS_PTHREAD)
  list(APPEND torsion_defines TORSION_HAVE_PTHREAD)
endif()

if(TORSION_ENABLE_RNG)
  list(APPEND torsion_defines TORSION_HAVE_RNG)
endif()

if(TORSION_HAS_TIME)
  list(APPEND torsion_defines TORSION_HAVE_TIME)
endif()

if(TORSION_TLS_KEYWORD)
  list(APPEND torsion_defines TORSION_TLS=${TORSION_TLS_KEYWORD})
endif()

if(TORSION_ENABLE_VERIFY)
  list(APPEND torsion_defines TORSION_VERIFY)
endif()

if(TORSION_HAS_ZLIB)
  list(APPEND torsion_defines TORSION_HAVE_ZLIB)
endif()

#
# Feature Test Macros
#

if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  list(APPEND torsion_defines _TS_ERRNO)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
  list(APPEND torsion_defines _THREAD_SAFE_ERRNO)
endif()

#
# Libraries
#

set(torsion_libs)
set(test_libs)

if(TORSION_HAS_ZLIB)
  list(APPEND test_libs z)
endif()

#
# Includes
#

set(torsion_includes ${PROJECT_SOURCE_DIR}/include)

#
# Sources
#

set(torsion_sources src/aead.c
                    src/asn1.c
                    src/cipher.c
                    src/ecc.c
                    src/encoding.c
                    src/drbg.c
                    src/dsa.c
                    src/hash.c
                    src/ies.c
                    src/internal.c
                    src/kdf.c
                    src/mac.c
                    src/mpi.c
                    src/rsa.c
                    src/stream.c
                    src/util.c)

set(rng_sources src/entropy/hw.c
                src/entropy/sys.c
                src/rand.c)

set(test_sources test/test.c test/utils.c)
set(bench_sources test/bench.c test/hrtime.c test/utils.c)
set(ctgrind_sources test/ctgrind.c test/utils.c)

if(TORSION_ENABLE_RNG)
  list(APPEND torsion_sources ${rng_sources})
endif()

#
# Targets
#

if(NOT PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
  # Bulding a subproject. Keep it simple.
  if(COMMAND add_node_library)
    add_node_library(torsion STATIC ${torsion_sources})
  else()
    add_library(torsion STATIC ${torsion_sources})
    set_property(TARGET torsion PROPERTY POSITION_INDEPENDENT_CODE
                                         ${TORSION_ENABLE_PIC})
  endif()

  target_compile_definitions(torsion PRIVATE ${torsion_defines})
  target_compile_options(torsion PRIVATE ${torsion_cflags})
  target_include_directories(torsion PUBLIC ${torsion_includes})
  target_link_options(torsion INTERFACE ${torsion_ldflags})
  target_link_libraries(torsion INTERFACE ${torsion_libs})
elseif(WASI OR EMSCRIPTEN)
  if(WASI)
    set(torsion_ldflags -Wl,--allow-undefined
                        -Wl,--initial-memory=${TORSION_INITIAL_MEMORY}
                        -Wl,--max-memory=${TORSION_MAX_MEMORY}
                        -Wl,-z,stack-size=${TORSION_STACK_SIZE}
                        -Wl,--stack-first)

    set(torsion_exeflags -mexec-model=reactor
                         -Wl,--export-dynamic
                         -Wl,--export=malloc
                         -Wl,--export=free)
  else()
    set(torsion_ldflags "SHELL:-s SINGLE_FILE=1"
                        "SHELL:-s ASSERTIONS=0"
                        "SHELL:-s NODEJS_CATCH_EXIT=0"
                        "SHELL:-s NODEJS_CATCH_REJECTION=0"
                        "SHELL:-s ALLOW_MEMORY_GROWTH=1"
                        "SHELL:-s INITIAL_MEMORY=${TORSION_INITIAL_MEMORY}"
                        "SHELL:-s MAXIMUM_MEMORY=${TORSION_MAX_MEMORY}"
                        "SHELL:-s TOTAL_STACK=${TORSION_STACK_SIZE}"
                        "SHELL:-s ENVIRONMENT=${TORSION_ENVIRONMENT}")

    set(torsion_exeflags "SHELL:-s EXPORTED_FUNCTIONS=@etc/exports.json")
  endif()

  add_library(torsion_static STATIC ${torsion_sources})
  target_compile_definitions(torsion_static PUBLIC ${torsion_defines})
  target_compile_options(torsion_static PUBLIC ${torsion_cflags})
  target_include_directories(torsion_static PUBLIC ${torsion_includes})
  target_link_options(torsion_static INTERFACE ${torsion_ldflags})
  set_property(TARGET torsion_static PROPERTY OUTPUT_NAME torsion)

  add_executable(torsion_reactor ${torsion_sources})
  target_compile_definitions(torsion_reactor PRIVATE ${torsion_defines}
                                                     TORSION_EXPORT)
  target_compile_options(torsion_reactor PRIVATE ${torsion_cflags})
  target_include_directories(torsion_reactor PRIVATE ${torsion_includes})
  target_link_options(torsion_reactor PRIVATE ${torsion_ldflags}
                                              ${torsion_exeflags})
  set_property(TARGET torsion_reactor PROPERTY OUTPUT_NAME torsion)

  if(TORSION_ENABLE_TESTS)
    add_executable(torsion_bench ${bench_sources})
    target_link_libraries(torsion_bench PRIVATE torsion_static)

    add_executable(torsion_test ${test_sources})
    target_link_libraries(torsion_test PRIVATE torsion_static)
    add_test(NAME test_wasm COMMAND torsion_test)

    if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
      add_custom_target(bench COMMAND torsion_bench)
    endif()
  endif()
else()
  if(TORSION_ENABLE_SHARED)
    set(torsion_target torsion_shared)
    set(torsion_targets torsion_static torsion_shared)
  else()
    set(torsion_target torsion_static)
    set(torsion_targets torsion_static)
  endif()

  add_library(torsion_static STATIC ${torsion_sources})
  target_compile_definitions(torsion_static PUBLIC ${torsion_defines})
  target_compile_options(torsion_static PUBLIC ${torsion_cflags})
  target_include_directories(torsion_static PUBLIC ${torsion_includes})
  target_link_options(torsion_static INTERFACE ${torsion_ldflags})
  target_link_libraries(torsion_static INTERFACE ${torsion_libs})

  set_property(TARGET torsion_static PROPERTY POSITION_INDEPENDENT_CODE
                                              ${TORSION_ENABLE_PIC})

  if(TORSION_ENABLE_SHARED)
    add_library(torsion_shared SHARED ${torsion_sources})
    target_compile_definitions(torsion_shared PUBLIC ${torsion_defines}
                                              PRIVATE TORSION_EXPORT)
    target_compile_options(torsion_shared PUBLIC ${torsion_cflags})
    target_include_directories(torsion_shared PUBLIC ${torsion_includes})
    target_link_options(torsion_shared PUBLIC ${torsion_ldflags})
    target_link_libraries(torsion_shared PRIVATE ${torsion_libs})

    set_property(TARGET torsion_shared PROPERTY OUTPUT_NAME torsion)
    set_target_version_info(torsion_shared ${TORSION_ABI_VERSION})
  endif()

  if(UNIX)
    set_property(TARGET torsion_static PROPERTY OUTPUT_NAME torsion)

    configure_file(libtorsion-cmake.pc.in libtorsion.pc @ONLY)

    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES LICENSE
            DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/${PROJECT_NAME})
    install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
    install(FILES ${PROJECT_BINARY_DIR}/libtorsion.pc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    install(TARGETS ${torsion_targets}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()

  if(MINGW)
    set_target_properties(torsion_static PROPERTIES PREFIX "" SUFFIX ".lib")

    if(TORSION_ENABLE_SHARED)
      set_target_properties(torsion_shared PROPERTIES PREFIX ""
                                                      SUFFIX ".dll"
                                                      IMPORT_PREFIX ""
                                                      IMPORT_SUFFIX ".lib")
      target_link_options(torsion_shared PRIVATE -Wl,--output-def,torsion.def)
    endif()
  endif()

  if(WIN32)
    set_property(TARGET torsion_static PROPERTY OUTPUT_NAME libtorsion)

    install(DIRECTORY include/ DESTINATION include)
    install(FILES LICENSE README.md DESTINATION .)
    install(TARGETS ${torsion_targets}
            ARCHIVE DESTINATION lib/$<CONFIG>
            RUNTIME DESTINATION lib/$<CONFIG>)
  endif()

  if(TORSION_ENABLE_TESTS)
    add_executable(torsion_bench ${bench_sources})
    target_link_libraries(torsion_bench PRIVATE ${torsion_target})

    add_executable(torsion_test ${test_sources})
    target_link_options(torsion_test PRIVATE ${torsion_exeflags})
    target_link_libraries(torsion_test PRIVATE ${torsion_target} ${test_libs})
    add_test(NAME test_torsion COMMAND torsion_test)

    if(TORSION_ENABLE_SHARED)
      add_executable(torsion_test_static ${test_sources})
      target_link_options(torsion_test_static PRIVATE ${torsion_exeflags})
      target_link_libraries(torsion_test_static PRIVATE torsion_static
                                                        ${test_libs})
      add_test(NAME test_static COMMAND torsion_test_static)
    endif()

    if(TORSION_HAS_MEMCHECK)
      add_executable(torsion_ctgrind ${ctgrind_sources})
      target_link_options(torsion_ctgrind PRIVATE ${torsion_exeflags})
      target_link_libraries(torsion_ctgrind PRIVATE ${torsion_target})
    endif()

    find_program(TORSION_VALGRIND valgrind)

    if(TORSION_VALGRIND)
      if(TORSION_HAS_MEMCHECK AND NOT TORSION_ENABLE_DEBUG)
        add_test(NAME test_ctgrind COMMAND ${TORSION_VALGRIND}
                                           --leak-check=full
                                           --error-exitcode=1
                                           $<TARGET_FILE:torsion_ctgrind>)
      endif()

      add_test(NAME test_valgrind COMMAND ${TORSION_VALGRIND}
                                          --leak-check=full
                                          --error-exitcode=1
                                          $<TARGET_FILE:torsion_test>)
    endif()

    if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
      add_custom_target(bench COMMAND torsion_bench)

      if(TORSION_VALGRIND)
        if(TORSION_HAS_MEMCHECK AND NOT TORSION_ENABLE_DEBUG)
          add_custom_target(ctgrind COMMAND ${TORSION_VALGRIND}
                                            --leak-check=full
                                            --error-exitcode=1
                                            $<TARGET_FILE:torsion_ctgrind>
                                    DEPENDS torsion_ctgrind)
        endif()

        add_custom_target(valgrind COMMAND ${TORSION_VALGRIND}
                                           --leak-check=full
                                           --error-exitcode=1
                                           $<TARGET_FILE:torsion_test>
                                   DEPENDS torsion_test)
      endif()
    endif()
  endif()
endif()

#
# Output
#

foreach(name C_FLAGS SHARED_LINKER_FLAGS EXE_LINKER_FLAGS)
  set(flags "")

  if(DEFINED CMAKE_BUILD_TYPE AND CMAKE_BUILD_TYPE)
    string(TOUPPER "${CMAKE_BUILD_TYPE}" build_type)
    if(DEFINED CMAKE_${name}_${build_type} AND CMAKE_${name}_${build_type})
      set(flags "${CMAKE_${name}_${build_type}}")
    endif()
  endif()

  if(DEFINED CMAKE_${name} AND CMAKE_${name})
    if(flags)
      set(flags "${flags} ${CMAKE_${name}}")
    else()
      set(flags "${CMAKE_${name}}")
    endif()
  endif()

  set(TORSION_${name} "${flags}")
endforeach()

message(STATUS "Build Options:

   BUILD_TYPE:       ${CMAKE_BUILD_TYPE}
   INSTALL_PREFIX:   ${CMAKE_INSTALL_PREFIX}
   SYSTEM:           ${CMAKE_SYSTEM} (${CMAKE_SYSTEM_PROCESSOR})
   C_COMPILER:       ${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID})
   C_FLAGS:          ${TORSION_C_FLAGS}
   SHARED_FLAGS:     ${TORSION_SHARED_LINKER_FLAGS}
   EXE_FLAGS:        ${TORSION_EXE_LINKER_FLAGS}
   torsion_cflags:   ${torsion_cflags}
   torsion_ldflags:  ${torsion_ldflags}
   torsion_exeflags: ${torsion_exeflags}
   torsion_defines:  ${torsion_defines}
   torsion_libs:     ${torsion_libs}
   test_libs:        ${test_libs}
")
