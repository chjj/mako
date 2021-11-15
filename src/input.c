/*!
 * input.c - input for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/crypto/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Input
 */

DEFINE_SERIALIZABLE_OBJECT(btc_input, SCOPE_EXTERN)

void
btc_input_init(btc_input_t *z) {
  btc_outpoint_init(&z->prevout);
  btc_script_init(&z->script);
  z->sequence = (uint32_t)-1;
  btc_stack_init(&z->witness);
}

void
btc_input_clear(btc_input_t *z) {
  btc_outpoint_clear(&z->prevout);
  btc_script_clear(&z->script);
  btc_stack_clear(&z->witness);
}

void
btc_input_copy(btc_input_t *z, const btc_input_t *x) {
  btc_outpoint_copy(&z->prevout, &x->prevout);
  btc_script_copy(&z->script, &x->script);
  z->sequence = x->sequence;
  btc_stack_copy(&z->witness, &x->witness);
}

size_t
btc_input_size(const btc_input_t *x) {
  size_t size = 0;

  size += btc_outpoint_size(&x->prevout);
  size += btc_script_size(&x->script);
  size += 4;

  return size;
}

uint8_t *
btc_input_write(uint8_t *zp, const btc_input_t *x) {
  zp = btc_outpoint_write(zp, &x->prevout);
  zp = btc_script_write(zp, &x->script);
  zp = btc_uint32_write(zp, x->sequence);
  return zp;
}

int
btc_input_read(btc_input_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_outpoint_read(&z->prevout, xp, xn))
    return 0;

  if (!btc_script_read(&z->script, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->sequence, xp, xn))
    return 0;

  return 1;
}

void
btc_input_update(btc_hash256_t *ctx, const btc_input_t *x) {
  btc_outpoint_update(ctx, &x->prevout);
  btc_script_update(ctx, &x->script);
  btc_uint32_update(ctx, x->sequence);
}
