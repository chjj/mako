/*!
 * rand_env.c - entropy gathering for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifdef _WIN32
#  include "rand_win_impl.h"
#else
#  include "rand_unix_impl.h"
#endif
