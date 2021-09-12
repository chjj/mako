/*!
 * address.c - address for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/address.h>
#include "impl.h"
#include "internal.h"

/*
 * Address
 */

DEFINE_OBJECT(btc_address, SCOPE_EXTERN)

void
btc_address_init(btc_address_t *z) {
  z->type = 0;
  z->version = 0;
  z->length = 20;
  memset(z->hash, 0, 40);
}

void
btc_address_clear(btc_address_t *z) {
  (void)z;
}

void
btc_address_copy(btc_address_t *z, const btc_address_t *x) {
  z->type = x->type;
  z->version = x->version;
  z->length = x->length;
  memcpy(z->hash, x->hash, 40);
}

int
btc_address_set_str(btc_address_t *addr, const char *str, const char *expect) {
  return 1;
}

int
btc_address_get_str(char *str, const btc_address_t *addr, const char *hrp) {
  return 1;
}
