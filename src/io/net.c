/*!
 * net.c - network functions for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifdef _WIN32
#  include <stdio.h>
#  include <stdlib.h>
#  include <winsock2.h>
#  ifndef __MINGW32__
#    pragma comment(lib, "ws2_32.lib")
#  endif
#else
#  include <signal.h>
#endif

#include <io/core.h>

/*
 * Net
 */

void
btc_net_startup(void) {
#if defined(_WIN32)
  WSADATA wsa_data;
  int rc;

  rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);

  if (rc != 0) {
    fprintf(stderr, "Could not initialize winsock (%d).\n", rc);
    fflush(stderr);
    abort();
  }
#else
  signal(SIGPIPE, SIG_IGN);
#endif
}

void
btc_net_cleanup(void) {
#ifdef _WIN32
  WSACleanup();
#endif
}
