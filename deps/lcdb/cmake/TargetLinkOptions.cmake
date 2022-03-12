# TargetLinkOptions.cmake - target_link_options fallback
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj

if(COMMAND target_link_options)
  return()
endif()

# Fallback for cmake < 3.13.
function(target_link_options)
  target_link_libraries(${ARGV})
endfunction()
