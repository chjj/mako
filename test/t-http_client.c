/*!
 * t-http.c - http test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io/core.h>
#include <io/http.h>
#include "lib/tests.h"

int main(void) {
  http_client_t *client = http_client_create();
  btc_sockaddr_t addr;
  http_options_t opt;
  http_msg_t *msg;
  char *s;

  ASSERT(http_client_open(client, "icanhazip.com", 80));

  http_options_init(&opt);

  msg = http_client_request(client, &opt);

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
  http_client_close(client);
  http_client_destroy(client);

  return 0;
}
