/*!
 * net.c - network functions for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <signal.h>
#include <io/core.h>

void
btc_net_startup(void) {
  signal(SIGPIPE, SIG_IGN);
}

void
btc_net_cleanup(void) {
  return;
}
