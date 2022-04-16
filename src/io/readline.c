/*!
 * readline.c - readline for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifdef _WIN32
#  include "readline_win_impl.h"
#else
#  include "readline_unix_impl.h"
#endif
