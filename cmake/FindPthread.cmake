# FindPthread.cmake - pthread finder for cmake
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj

if(COMMAND find_pthread)
  return()
endif()

function(find_pthread found cflags libs)
  set(${found} 0 PARENT_SCOPE)
  set(${cflags} "" PARENT_SCOPE)
  set(${libs} "" PARENT_SCOPE)

  if(WIN32 OR WASI OR EMSCRIPTEN OR CMAKE_C_COMPILER_ID MATCHES "Watcom$")
    return()
  endif()

  set(THREADS_PREFER_PTHREAD_FLAG ON)

  find_package(Threads)

  if(CMAKE_USE_PTHREADS_INIT)
    set(_cflags "")
    set(_libs "")

    if(CMAKE_THREAD_LIBS_INIT STREQUAL "-pthread")
      set(_cflags -pthread)
      set(_libs pthread)
    elseif(CMAKE_THREAD_LIBS_INIT)
      string(REGEX REPLACE "^-l" "" _libs "${CMAKE_THREAD_LIBS_INIT}")
    endif()

    set(${found} 1 PARENT_SCOPE)
    set(${cflags} ${_cflags} PARENT_SCOPE)
    set(${libs} ${_libs} PARENT_SCOPE)
  endif()
endfunction()
