/*!
 * net.c - network functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
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
