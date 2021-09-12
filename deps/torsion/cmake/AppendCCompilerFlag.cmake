# AppendCCompilerFlag.cmake - checked c flags appending
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj

if(COMMAND append_c_compiler_flag)
  return()
endif()

include(CheckCCompilerFlag)

function(append_c_compiler_flag result)
  set(flags ${${result}})

  check_c_compiler_flag(-Werror=unknown-warning-option
                        HAVE_UNKNOWN_WARNING_OPTION)

  foreach(flag ${ARGN})
    string(REGEX REPLACE "[^A-Z0-9a-z]" "_" name "${flag}")
    string(TOUPPER "HAVE_C_FLAG${name}" name)

    if(HAVE_UNKNOWN_WARNING_OPTION)
      check_c_compiler_flag("-Werror=unknown-warning-option ${flag}" ${name})
    else()
      check_c_compiler_flag(${flag} ${name})
    endif()

    if(${name})
      list(APPEND flags ${flag})
    endif()
  endforeach()

  set(${result} ${flags} PARENT_SCOPE)
endfunction()
