# CMakeLists.txt - cmake build for rdb
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

cmake_minimum_required(VERSION 3.4)
project(rdb LANGUAGES C)

add_library(rdb STATIC rdb.c)

if(MAKO_TLS_FLAG)
  target_compile_options(rdb PRIVATE ${MAKO_TLS_FLAG})
endif()

target_compile_definitions(rdb PRIVATE RDB_BACKGROUND_COMPACTION)

if(MAKO_HAVE_PTHREAD AND NOT WIN32)
  target_compile_definitions(rdb PRIVATE RDB_PTHREAD)
  list(APPEND rdb Threads::Threads)
endif()

if(MAKO_TLS_KEYWORD)
  target_compile_definitions(rdb PRIVATE RDB_TLS=${MAKO_TLS_KEYWORD})
endif()

target_include_directories(rdb INTERFACE ${PROJECT_SOURCE_DIR})
