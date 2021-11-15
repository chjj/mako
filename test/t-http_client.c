/*!
 * t-http.c - http test for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io/core.h>
#include <io/http.h>
#include "lib/tests.h"

int main(void) {
  btc_sockaddr_t addr;
  http_msg_t *msg;
  char *s;

  btc_net_startup();

  msg = http_get("icanhazip.com", 80, "/", BTC_AF_INET);

  ASSERT(msg != NULL);

  printf("%s", msg->body.data);

  s = msg->body.data;

  while (*s) {
    if (*s <= ' ') {
      *s = '\0';
      break;
    }
    s++;
  }

  ASSERT(btc_sockaddr_import(&addr, msg->body.data, 0));

  http_msg_destroy(msg);

  btc_net_cleanup();

  return 0;
}
