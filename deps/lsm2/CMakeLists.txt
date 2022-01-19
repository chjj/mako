# CMakeLists.txt - cmake build for leveldb wrapper
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

cmake_minimum_required(VERSION 3.4)
project(lsm2 LANGUAGES C)

add_library(lsm2 STATIC lsm.c)

target_include_directories(lsm2 INTERFACE ${PROJECT_SOURCE_DIR})
target_link_libraries(lsm2 PRIVATE leveldb)
