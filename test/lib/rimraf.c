/*!
 * rimraf.c - rm -rf for c
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj
 */

#ifdef _WIN32
#  include "rimraf_win_impl.h"
#else
#  include "rimraf_unix_impl.h"
#endif
