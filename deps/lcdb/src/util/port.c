/*!
 * port.c - ported functions for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#if defined(_WIN32)
#  include "port_win_impl.h"
#elif defined(LDB_PTHREAD)
#  include "port_unix_impl.h"
#else
#  include "port_none_impl.h"
#endif
