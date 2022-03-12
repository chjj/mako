# CMakeLists.txt - cmake build for leveldb wrapper
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/lcdb

cmake_minimum_required(VERSION 3.4)
project(lcdb LANGUAGES C)

add_library(lcdb STATIC lwdb.c)
target_include_directories(lcdb INTERFACE ${PROJECT_SOURCE_DIR}/../../include)
target_link_libraries(lcdb PRIVATE leveldb)
