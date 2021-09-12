# CheckCThreadLocalStorage.cmake - tls check for c
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj

if(COMMAND check_c_thread_local_storage)
  return()
endif()

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckCSourceRuns)

function(_check_c_emutls result code flags)
  set(dir ${CMAKE_BINARY_DIR}/CMakeFiles/CheckCEmuTLS)
  set(src ${dir}/emutls.c)
  set(bin ${dir}/emutls${CMAKE_EXECUTABLE_SUFFIX})
  set(found 0)

  file(MAKE_DIRECTORY ${dir})
  file(WRITE ${src} "${code}\n")

  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${src}
              CMAKE_FLAGS -DCOMPILE_DEFINITIONS:STRING=${flags}
              COPY_FILE ${bin} COPY_FILE_ERROR ERROR_VAR)

  if(RESULT_VAR AND NOT ERROR_VAR AND EXISTS "${bin}")
    # There is evidence that some non-GNU platforms also do TLS
    # emulation. It's possible this includes 32-bit AIX, but I
    # cannot confirm this.
    #
    # TODO: Find other platforms with emulated TLS and figure
    #       out how to detect it.
    file(STRINGS ${bin} emutls LIMIT_COUNT 1 REGEX "__emutls_get_address")

    if(emutls)
      set(found 1)
    endif()
  endif()

  file(REMOVE_RECURSE "${dir}")

  set(${result} ${found} PARENT_SCOPE)
endfunction()

function(check_c_thread_local_storage keyword_name flags_name emulated_name)
  if(DEFINED "${keyword_name}" AND DEFINED "${flags_name}"
                               AND DEFINED "${emulated_name}")
    return()
  endif()

  if(NOT CMAKE_REQUIRED_QUIET AND NOT CMAKE_VERSION VERSION_LESS 3.17)
    message(CHECK_START "Checking for thread-local storage")
    set(verbose 1)
  else()
    set(verbose 0)
  endif()

  set(CMAKE_REQUIRED_FLAGS "")
  set(CMAKE_REQUIRED_QUIET 1)
  set(_flags)

  # XL requires a special flag. Don't ask me why.
  # Note that CMake handles -qthreaded for us.
  if(CMAKE_C_COMPILER_ID MATCHES "^XL")
    check_c_compiler_flag(-qtls HAVE_C_FLAG_QTLS)
    if(HAVE_C_FLAG_QTLS)
      list(APPEND _flags -qtls)
    endif()
  endif()

  # Various TLS keywords.
  #
  # The last keyword is not widely known, but there is evidence
  # that Compaq C for Tru64 UNIX supported it at one point.
  set(keywords __thread "__declspec(thread)" "__declspec(__thread)")

  # Prepend or append _Thread_local according to the C standard.
  if(DEFINED CMAKE_C_STANDARD AND CMAKE_C_STANDARD GREATER 88)
    list(APPEND keywords _Thread_local)
  else()
    list(INSERT keywords 0 _Thread_local)
  endif()

  # We try to run the executable when not cross compiling. There
  # are far too many instances of TLS code successfully building
  # but not running.
  set(keyword "")
  set(flags "")
  set(emulated 0)

  # Setup flags for check_c_source_{compiles,runs}.
  string(REPLACE ";" " " CMAKE_REQUIRED_FLAGS "${_flags}")

  foreach(_keyword ${keywords})
    string(REGEX REPLACE "[^0-9A-Za-z]" "_" name "${_keyword}")
    string(TOUPPER "${keyword_name}_${name}" name)

    # The thread-local variable must have external linkage otherwise
    # the optimizer may remove the TLS code. GCC and Clang refuse to
    # optimize the below code (even with -O3 enabled).
    set(code "${_keyword} int x; int main(void) { x = 1; return !x; }")

    if(CMAKE_CROSSCOMPILING)
      check_c_source_compiles("${code}" ${name})
    else()
      check_c_source_runs("${code}" ${name})
    endif()

    if(${name})
      set(keyword "${_keyword}")
      set(flags "${_flags}")
      _check_c_emutls(emulated "${code}" "${flags}")
      break()
    endif()
  endforeach()

  set(${keyword_name} "${keyword}" CACHE INTERNAL "TLS keyword")
  set(${flags_name} "${flags}" CACHE INTERNAL "TLS flags")
  set(${emulated_name} ${emulated} CACHE INTERNAL "TLS emulation")

  if(verbose)
    if(keyword AND flags)
      message(CHECK_PASS "${keyword} (flags=${flags}, emulated=${emulated})")
    elseif(keyword)
      message(CHECK_PASS "${keyword} (emulated=${emulated})")
    else()
      message(CHECK_FAIL "Failed")
    endif()
  endif()
endfunction()
