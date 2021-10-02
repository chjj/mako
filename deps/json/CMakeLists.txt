cmake_minimum_required(VERSION 3.4)
project(json LANGUAGES C)

add_library(json STATIC json.c json-builder.c)
target_include_directories(json PUBLIC ${PROJECT_SOURCE_DIR})
