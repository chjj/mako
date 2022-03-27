# CMakeLists.txt - cmake build for lcdb
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/lcdb

set(LDB_PKG_VERSION 0.0.0)
set(LDB_ABI_VERSION 0:0:0)

#
# Initialization
#

cmake_minimum_required(VERSION 3.4)
project(lcdb VERSION ${LDB_PKG_VERSION} LANGUAGES C)

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
include(cmake/LibtoolEmulator.cmake)
include(cmake/TargetLinkOptions.cmake)
include(CheckSymbolExists)
include(CTest)
include(GNUInstallDirs)

#
# Options
#

option(LDB_COVERAGE "Enable coverage" OFF)
option(LDB_PIC "Enable PIC" OFF)
option(LDB_PORTABLE "Be as portable as possible" OFF)
option(LDB_SHARED "Build shared library" OFF)
option(LDB_TESTS "Build tests" ON)

#
# Variables
#

set(ldb_sources)
set(ldb_defines)
set(ldb_cflags)
set(ldb_includes)
set(ldb_ldflags)
set(ldb_libs)

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

check_symbol_exists(__GLIBC__ "limits.h" LDB_GLIBC)

if(LDB_GLIBC)
  set(CMAKE_C_STANDARD 90)
  set(CMAKE_C_EXTENSIONS OFF)
  set(CMAKE_C_STANDARD_REQUIRED OFF)
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
  check_symbol_exists(_THREAD_SAFE "" LDB_XLC_R)

  if(NOT LDB_XLC_R)
    message(WARNING "Please use a thread-safe compiler invocation.\n"
                    "For example, `cmake . -DCMAKE_C_COMPILER=xlc_r`.")
  endif()
endif()

# CMake doesn't know about chibicc's -fPIC.
check_symbol_exists(__chibicc__ "" LDB_CHIBICC)

if(LDB_CHIBICC)
  set(CMAKE_C_COMPILE_OPTIONS_PIC "-fPIC")
  set(CMAKE_SHARED_LIBRARY_C_FLAGS "-fPIC")
endif()

#
# Feature Testing
#

if(LDB_PORTABLE OR MAKO_PORTABLE)
  set(LDB_HAVE_FDATASYNC OFF)
  set(LDB_HAVE_PREAD OFF)
else()
  check_symbol_exists(fdatasync unistd.h LDB_HAVE_FDATASYNC)
  check_symbol_exists(pread unistd.h LDB_HAVE_PREAD)
endif()

set(LDB_HAVE_PTHREAD 0)

if(NOT WIN32 AND NOT WASI AND NOT EMSCRIPTEN
   AND NOT CMAKE_C_COMPILER_ID MATCHES "Watcom$")
  set(THREADS_PREFER_PTHREAD_FLAG ON)

  find_package(Threads)

  if(CMAKE_USE_PTHREADS_INIT)
    set(LDB_HAVE_PTHREAD 1)
  endif()
endif()

#
# Sources
#

list(APPEND ldb_sources # util
                        src/util/arena.c
                        src/util/array.c
                        src/util/atomic.c
                        src/util/bloom.c
                        src/util/buffer.c
                        src/util/cache.c
                        src/util/comparator.c
                        src/util/crc32c.c
                        src/util/env.c
                        src/util/hash.c
                        src/util/internal.c
                        src/util/logger.c
                        src/util/options.c
                        src/util/port.c
                        src/util/random.c
                        src/util/rbt.c
                        src/util/slice.c
                        src/util/snappy.c
                        src/util/status.c
                        src/util/strutil.c
                        src/util/thread_pool.c
                        src/util/vector.c
                        # table
                        src/table/block.c
                        src/table/block_builder.c
                        src/table/filter_block.c
                        src/table/format.c
                        src/table/iterator.c
                        src/table/merger.c
                        src/table/table.c
                        src/table/table_builder.c
                        src/table/two_level_iterator.c
                        # db
                        src/builder.c
                        src/c.c
                        src/db_impl.c
                        src/db_iter.c
                        src/dbformat.c
                        src/dumpfile.c
                        src/filename.c
                        src/log_reader.c
                        src/log_writer.c
                        src/memtable.c
                        src/repair.c
                        src/skiplist.c
                        src/table_cache.c
                        src/version_edit.c
                        src/version_set.c
                        src/write_batch.c)

list(APPEND test_sources # util
                         src/util/arena_test.c
                         src/util/bloom_test.c
                         src/util/cache_test.c
                         src/util/coding_test.c
                         src/util/crc32c_test.c
                         src/util/env_test.c
                         src/util/hash_test.c
                         src/util/rbt_test.c
                         src/util/snappy_test.c
                         src/util/strutil_test.c
                         src/util/status_test.c
                         src/util/testutil.c
                         # table
                         src/table/filter_block_test.c
                         src/table/table_test.c
                         # db
                         src/autocompact_test.c
                         src/c_test.c
                         src/corruption_test.c
                         src/dbformat_test.c
                         src/db_test.c
                         src/filename_test.c
                         src/log_test.c
                         src/recovery_test.c
                         src/skiplist_test.c
                         src/version_edit_test.c
                         src/version_set_test.c
                         src/write_batch_test.c)

#
# Flags
#

if(MSVC)
  append_c_compiler_flag(ldb_cflags /wd4146  # negation of unsigned integer
                                    /wd4244  # implicit integer demotion
                                    /wd4267  # implicit size_t demotion
                                    /wd4334) # implicit 32->64 bit shift
elseif(BORLAND)
# Todo.
elseif(CMAKE_C_COMPILER_ID MATCHES "Watcom$")
  append_c_compiler_flag(ldb_cflags -wcd=201  # unreachable code
                                    -wcd=202) # unused symbol
else()
  append_c_compiler_flag(ldb_cflags -pedantic
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

if(LDB_COVERAGE)
  list(APPEND ldb_cflags -O0 --coverage)
  list(APPEND ldb_ldflags --coverage)
endif()

if(MINGW)
  # Ensure we are redistributable on windows.
  list(APPEND ldb_ldflags -static-libgcc)
  # Much compatibility.
  if(MINGW_ARCH STREQUAL "i686")
    list(APPEND ldb_cflags -march=i486 -mtune=i686)
    list(APPEND ldb_ldflags -march=i486 -mtune=i686)
  endif()
endif()

#
# Defines
#

if(LDB_HAVE_FDATASYNC)
  list(APPEND ldb_defines LDB_HAVE_FDATASYNC)
endif()

if(LDB_HAVE_PREAD)
  list(APPEND ldb_defines LDB_HAVE_PREAD)
endif()

if(LDB_HAVE_PTHREAD)
  list(APPEND ldb_defines LDB_PTHREAD)
endif()

#
# Feature Test Macros
#

if(WIN32)
  list(APPEND ldb_defines _WIN32_WINNT=0x501)
endif()

if(LDB_GLIBC)
  list(APPEND ldb_defines _GNU_SOURCE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  list(APPEND ldb_defines _TS_ERRNO)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
  list(APPEND ldb_defines _THREAD_SAFE_ERRNO)
endif()

#
# Includes
#

list(APPEND ldb_includes ${PROJECT_SOURCE_DIR}/include)

#
# Libraries
#

if(WIN32)
  list(APPEND ldb_libs kernel32)
elseif(LDB_HAVE_PTHREAD)
  list(APPEND ldb_libs Threads::Threads)
endif()

#
# Subproject
#

if(NOT PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
  # Bulding a subproject. Keep it simple.
  if(COMMAND add_node_library)
    add_node_library(lcdb STATIC ${ldb_sources})
  else()
    add_library(lcdb STATIC ${ldb_sources})
    set_property(TARGET lcdb PROPERTY POSITION_INDEPENDENT_CODE ${LDB_PIC})
  endif()

  target_compile_definitions(lcdb PRIVATE ${ldb_defines})
  target_compile_options(lcdb PRIVATE ${ldb_cflags})
  target_include_directories(lcdb PUBLIC ${ldb_includes})
  target_link_options(lcdb INTERFACE ${ldb_ldflags})
  target_link_libraries(lcdb INTERFACE ${ldb_libs})

  return()
endif()

#
# Targets
#

add_library(lcdb INTERFACE)
target_compile_definitions(lcdb INTERFACE ${ldb_defines})
target_compile_options(lcdb INTERFACE ${ldb_cflags})
target_include_directories(lcdb INTERFACE ${ldb_includes})
target_link_options(lcdb INTERFACE ${ldb_ldflags})
target_link_libraries(lcdb INTERFACE ${ldb_libs})

add_library(lcdb_static STATIC ${ldb_sources})
target_link_libraries(lcdb_static PRIVATE lcdb)
set_property(TARGET lcdb_static PROPERTY POSITION_INDEPENDENT_CODE ${LDB_PIC})

if(WIN32)
  set_property(TARGET lcdb_static PROPERTY OUTPUT_NAME liblcdb)
else()
  set_property(TARGET lcdb_static PROPERTY OUTPUT_NAME lcdb)
endif()

if(MINGW)
  set_target_properties(lcdb_static PROPERTIES PREFIX "" SUFFIX ".lib")
endif()

if(LDB_TESTS)
  add_library(lcdb_test STATIC ${test_sources})
  target_link_libraries(lcdb_test PRIVATE lcdb lcdb_static)
  set_property(TARGET lcdb_test PROPERTY OUTPUT_NAME test)
endif()

if(LDB_SHARED)
  add_library(lcdb_shared SHARED ${ldb_sources})
  target_compile_definitions(lcdb_shared PRIVATE LDB_EXPORT)
  target_link_libraries(lcdb_shared PRIVATE lcdb)
  set_property(TARGET lcdb_shared PROPERTY OUTPUT_NAME lcdb)

  if (NOT LDB_CHIBICC) # chibicc doesn't support .so versioning.
    set_target_version_info(lcdb_shared ${LDB_ABI_VERSION})
  endif()

  if(MINGW)
    set_target_properties(lcdb_shared PROPERTIES PREFIX ""
                                                 SUFFIX ".dll"
                                                 IMPORT_PREFIX ""
                                                 IMPORT_SUFFIX ".lib")
    target_link_options(lcdb_shared PRIVATE -Wl,--output-def,lcdb.def)
  endif()
endif()

if(LDB_SHARED)
  set(lcdb_name lcdb_shared)
else()
  set(lcdb_name lcdb_static)
endif()

add_executable(lcdb_util src/dbutil.c)
target_link_libraries(lcdb_util PRIVATE lcdb ${lcdb_name})
set_property(TARGET lcdb_util PROPERTY OUTPUT_NAME lcdbutil)

#
# Tests
#

if(LDB_TESTS)
  set(tests arena
            autocompact
            bloom
            c
            cache
            coding
            corruption
            crc32c
            db
            dbformat
            env
            filename
            filter_block
            hash
            issue178
            issue200
            issue320
            log
            rbt
            recovery
            simple
            skiplist
            snappy
            status
            strutil
            table
            version_edit
            version_set
            write_batch)

  foreach(name ${tests})
    add_executable(t-${name} test/t-${name}.c)
    target_link_libraries(t-${name} PRIVATE lcdb lcdb_test)
    add_test(NAME ${name} COMMAND t-${name})
  endforeach()
endif()

#
# Install
#

if(WASI OR EMSCRIPTEN)
  return()
endif()

if(UNIX)
  configure_file(lcdb-cmake.pc.in lcdb.pc @ONLY)

  install(FILES include/lcdb.h include/lcdb_c.h
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(FILES LICENSE
          DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/${PROJECT_NAME})
  install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
  install(FILES ${PROJECT_BINARY_DIR}/lcdb.pc
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
  install(TARGETS lcdb_static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

  if(LDB_SHARED)
    install(TARGETS lcdb_shared
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()

  install(TARGETS lcdb_util RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(WIN32)
  install(FILES include/lcdb.h include/lcdb_c.h DESTINATION include)
  install(FILES LICENSE README.md DESTINATION .)
  install(TARGETS lcdb_static ARCHIVE DESTINATION lib/$<CONFIG>)

  if(LDB_SHARED)
    install(TARGETS lcdb_shared
            ARCHIVE DESTINATION lib/$<CONFIG>
            RUNTIME DESTINATION lib/$<CONFIG>)
  endif()

  install(TARGETS lcdb_util RUNTIME DESTINATION bin/$<CONFIG>)
endif()
