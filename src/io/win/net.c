/*!
 * net.c - network functions for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <io/core.h>

#ifndef __MINGW32__
#  pragma comment(lib, "ws2_32.lib")
#endif

void
btc_net_startup(void) {
  WSADATA wsa_data;
  int rc;

  rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);

  if (rc != 0) {
    printf("Could not initialize winsock (%d).\n", rc);
    abort();
  }
}

void
btc_net_cleanup(void) {
  WSACleanup();
}
