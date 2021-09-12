/*!
 * script.c - script for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/buffer.h>
#include <satoshi/consensus.h>
#include <satoshi/crypto.h>
#include <satoshi/policy.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <torsion/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Script Number
 */

int
btc_scriptnum_is_minimal(const uint8_t *xp, size_t xn) {
  if (xn == 0)
    return 1;

  if ((xp[xn - 1] & 0x7f) == 0) {
    if (xn == 1)
      return 0;

    if ((xp[xn - 2] & 0x80) == 0)
      return 0;
  }

  return 1;
}

size_t
btc_scriptnum_export(uint8_t *zp, int64_t x) {
  uint64_t abs;
  size_t n;
  int neg;

  /* Zeroes are always empty arrays. */
  if (x == 0)
    return 0;

  /* Write number. */
  neg = (x < 0);
  abs = neg ? -x : x;
  n = 0;

  while (abs != 0) {
    zp[n++] = abs & 0xff;
    abs >>= 8;
  }

  /* Append sign bit. */
  if (zp[n - 1] & 0x80)
    zp[n++] = neg ? 0x80 : 0;
  else if (neg)
    zp[n - 1] |= 0x80;

  return n;
}

int64_t
btc_scriptnum_import(const uint8_t *xp, size_t xn) {
  int64_t z;
  size_t i;

  /* Empty arrays are always zero. */
  if (xn == 0)
    return 0;

  /* Read number. */
  z = 0;

  for (i = 0; i < xn; i++)
    z |= (int64_t)xp[i] << (i * 8);

  /* Remove high bit and flip sign. */
  if (xp[xn - 1] & 0x80)
    return -((int64_t)(z & ~(UINT64_C(0x80) << (8 * (xn - 1)))));

  return z;
}

/*
 * Stack
 */

DEFINE_HASHABLE_VECTOR(btc_stack, btc_buffer, SCOPE_EXTERN)

const btc_buffer_t *
btc_stack_get(const btc_stack_t *stack, int index) {
  if (index < 0)
    index += (int)stack->length;

  CHECK((size_t)index < stack->length);

  return stack->items[index];
}

int
btc_stack_get_num(int64_t *num,
                  const btc_stack_t *stack,
                  int index,
                  int minimal,
                  size_t limit) {
  const btc_buffer_t *buf = btc_stack_get(stack, index);

  if (buf->length > limit)
    return 0;

  if (minimal && !btc_scriptnum_is_minimal(buf->data, buf->length))
    return 0;

  *num = btc_scriptnum_import(buf->data, buf->length);

  return 1;
}

int
btc_stack_get_int(int *num,
                  const btc_stack_t *stack,
                  int index,
                  int minimal,
                  size_t limit) {
  int64_t z;

  if (!btc_stack_get_num(&z, stack, index, minimal, limit)) {
    *num = 0;
    return 0;
  }

  if (z < INT_MIN)
    *num = INT_MIN;
  else if (z > INT_MAX)
    *num = INT_MAX;
  else
    *num = z;

  return 1;
}

int
btc_stack_get_bool(const btc_stack_t *stack, int index) {
  const btc_buffer_t *buf = btc_stack_get(stack, index);
  size_t i;

  for (i = 0; i < buf->length; i++) {
    if (buf->data[i] != 0) {
      /* Cannot be negative zero. */
      if (i == buf->length - 1 && buf->data[i] == 0x80)
        return 0;
      return 1;
    }
  }

  return 0;
}

void
btc_stack_push_data(btc_stack_t *stack, const uint8_t *data, size_t length) {
  btc_buffer_t *item = btc_buffer_create();
  btc_buffer_set(item, data, length);
  btc_stack_push(stack, item);
}

void
btc_stack_push_num(btc_stack_t *stack, int64_t num) {
  btc_buffer_t *item = btc_buffer_create();

  btc_buffer_grow(item, 9);

  item->length = btc_scriptnum_export(item->data, num);

  btc_stack_push(stack, item);
}

void
btc_stack_push_int(btc_stack_t *stack, int num) {
  btc_stack_push_num(stack, num);
}

void
btc_stack_push_bool(btc_stack_t *stack, int value) {
  btc_buffer_t *item = btc_buffer_create();

  if (value) {
    btc_buffer_grow(item, 1);

    item->data[0] = 1;
    item->length = 1;
  }

  btc_stack_push(stack, item);
}

static void
btc_stack_insert(btc_stack_t *stack, int index, btc_buffer_t *item) {
  size_t i;

  if (index < 0)
    index += (int)stack->length;

  CHECK((size_t)index < stack->length);

  btc_stack_grow(stack, stack->length + 1);

  for (i = stack->length; i != (size_t)index; i--)
    stack->items[i] = stack->items[i - 1];

  stack->items[index] = item;
  stack->length++;
}

static btc_buffer_t *
btc_stack_remove(btc_stack_t *stack, int index) {
  btc_buffer_t *item;
  size_t i;

  if (index < 0)
    index += (int)stack->length;

  CHECK((size_t)index < stack->length);

  item = stack->items[index];

  for (i = index; i < stack->length - 1; i++)
    stack->items[i] = stack->items[i + 1];

  stack->length--;

  return item;
}

static void
btc_stack_erase(btc_stack_t *stack, int start, int end) {
  size_t i;

  if (start < 0)
    start += (int)stack->length;

  if (end < 0)
    end += (int)stack->length;

  CHECK(end >= start);
  CHECK((size_t)start < stack->length);
  CHECK((size_t)end < stack->length);

  for (i = end; i < stack->length; i++)
    stack->items[start++] = stack->items[i];

  stack->length = start;
}

static void
btc_stack_swap(btc_stack_t *stack, int i1, int i2) {
  btc_buffer_t *v1, *v2;

  if (i1 < 0)
    i1 += (int)stack->length;

  if (i2 < 0)
    i2 += (int)stack->length;

  CHECK((size_t)i1 < stack->length);
  CHECK((size_t)i2 < stack->length);

  v1 = stack->items[i1];
  v2 = stack->items[i2];

  stack->items[i1] = v2;
  stack->items[i2] = v1;
}

/*
 * State
 */

typedef struct btc_state_s {
  uint8_t *items;
  size_t alloc;
  size_t length;
} btc_state_t;

static void
btc_state_init(btc_state_t *z) {
  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

static void
btc_state_clear(btc_state_t *z) {
  if (z->alloc > 0)
    free(z->items);

  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

static void
btc_state_grow(btc_state_t *z, size_t zn) {
  if (zn > z->alloc) {
    uint8_t *zp = (uint8_t *)realloc(z->items, zn);

    CHECK(zp != NULL);

    z->items = zp;
    z->alloc = zn;
  }
}

static void
btc_state_push(btc_state_t *z, int x) {
  if (z->length == z->alloc)
    btc_state_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->items[z->length++] = x;
}

static int
btc_state_pop(btc_state_t *z) {
  CHECK(z->length > 0);
  return z->items[--z->length];
}

/*
 * Opcode
 */

DEFINE_SERIALIZABLE_OBJECT(btc_opcode, SCOPE_EXTERN)

void
btc_opcode_init(btc_opcode_t *z) {
  z->value = 0;
  z->data = NULL;
  z->length = 0;
}

void
btc_opcode_clear(btc_opcode_t *z) {
  (void)z;
}

void
btc_opcode_copy(btc_opcode_t *z, const btc_opcode_t *x) {
  z->value = x->value;
  z->data = x->data;
  z->length = z->length;
}

int
btc_opcode_equal(const btc_opcode_t *x, const btc_opcode_t *y) {
  if (x->value != y->value)
    return 0;

  if (x->length != y->length)
    return 0;

  if (x->length > 0) {
    if (memcmp(x->data, y->data, x->length) != 0)
      return 0;
  }

  return 1;
}

int
btc_opcode_is_minimal(const btc_opcode_t *x) {
  if (x->value > BTC_OP_PUSHDATA4)
    return 1;

  if (x->length == 1) {
    if (x->data[0] == 0x81)
      return 0;

    if (x->data[0] >= 1 && x->data[0] <= 16)
      return 0;
  }

  if (x->length <= 0x4b)
    return (size_t)x->value == x->length;

  if (x->length <= 0xff)
    return x->value == BTC_OP_PUSHDATA1;

  if (x->length <= 0xffff)
    return x->value == BTC_OP_PUSHDATA2;

  return x->value == BTC_OP_PUSHDATA4;
}

int
btc_opcode_is_disabled(const btc_opcode_t *x) {
  switch (x->value) {
    case BTC_OP_CAT:
    case BTC_OP_SUBSTR:
    case BTC_OP_LEFT:
    case BTC_OP_RIGHT:
    case BTC_OP_INVERT:
    case BTC_OP_AND:
    case BTC_OP_OR:
    case BTC_OP_XOR:
    case BTC_OP_2MUL:
    case BTC_OP_2DIV:
    case BTC_OP_MUL:
    case BTC_OP_DIV:
    case BTC_OP_MOD:
    case BTC_OP_LSHIFT:
    case BTC_OP_RSHIFT:
      return 1;
  }
  return 0;
}

int
btc_opcode_is_branch(const btc_opcode_t *x) {
  return x->value >= BTC_OP_IF && x->value <= BTC_OP_ENDIF;
}

void
btc_opcode_set_push(btc_opcode_t *z, const uint8_t *data, size_t length) {
  if (length <= 0x4b)
    z->value = length;
  else if (length <= 0xff)
    z->value = BTC_OP_PUSHDATA1;
  else if (length <= 0xffff)
    z->value = BTC_OP_PUSHDATA2;
  else
    z->value = BTC_OP_PUSHDATA4;

  z->data = data;
  z->length = length;
}

size_t
btc_opcode_size(const btc_opcode_t *x) {
  if (x->value > BTC_OP_PUSHDATA4)
    return 1;

  switch (x->value) {
    case BTC_OP_PUSHDATA1:
      return 2 + x->length;
    case BTC_OP_PUSHDATA2:
      return 3 + x->length;
    case BTC_OP_PUSHDATA4:
      return 5 + x->length;
    default:
      return 1 + x->length;
  }
}

uint8_t *
btc_opcode_write(uint8_t *zp, const btc_opcode_t *x) {
  CHECK(x->value != -1);

  if (x->value > BTC_OP_PUSHDATA4) {
    zp = btc_uint8_write(zp, x->value);
    return zp;
  }

  switch (x->value) {
    case BTC_OP_PUSHDATA1:
      zp = btc_uint8_write(zp, x->value);
      zp = btc_uint8_write(zp, x->length);
      zp = btc_raw_write(zp, x->data, x->length);
      break;
    case BTC_OP_PUSHDATA2:
      zp = btc_uint8_write(zp, x->value);
      zp = btc_uint16_write(zp, x->length);
      zp = btc_raw_write(zp, x->data, x->length);
      break;
    case BTC_OP_PUSHDATA4:
      zp = btc_uint8_write(zp, x->value);
      zp = btc_uint32_write(zp, x->length);
      zp = btc_raw_write(zp, x->data, x->length);
      break;
    default:
      CHECK((size_t)x->value == x->length);
      zp = btc_uint8_write(zp, x->value);
      zp = btc_raw_write(zp, x->data, x->length);
      break;
  }

  return zp;
}

int
btc_opcode_read(btc_opcode_t *z, const uint8_t **xp, size_t *xn) {
  uint8_t value;

  btc_opcode_init(z);

  if (!btc_uint8_read(&value, xp, xn))
    return 0;

  if (value > BTC_OP_PUSHDATA4) {
    z->value = value;
    return 1;
  }

  z->value = -1;

  switch (value) {
    case BTC_OP_PUSHDATA1: {
      uint8_t length;

      if (!btc_uint8_read(&length, xp, xn))
        return 0;

      if (*xn < length)
        return 0;

      z->value = value;
      z->data = *xp;
      z->length = length;

      *xp += length;
      *xn -= length;

      break;
    }

    case BTC_OP_PUSHDATA2: {
      uint16_t length;

      if (!btc_uint16_read(&length, xp, xn))
        return 0;

      if (*xn < length)
        return 0;

      z->value = value;
      z->data = *xp;
      z->length = length;

      *xp += length;
      *xn -= length;

      break;
    }

    case BTC_OP_PUSHDATA4: {
      uint32_t length;

      if (!btc_uint32_read(&length, xp, xn))
        return 0;

      if (*xn < length)
        return 0;

      z->value = value;
      z->data = *xp;
      z->length = length;

      *xp += length;
      *xn -= length;

      break;
    }

    default: {
      if (*xn < value)
        return 0;

      z->value = value;
      z->data = *xp;
      z->length = value;

      *xp += value;
      *xn -= value;

      break;
    }
  }

  return 1;
}

/*
 * Script
 */

DEFINE_SERIALIZABLE_OBJECT(btc_script, SCOPE_EXTERN)

void
btc_script_init(btc_script_t *z) {
  btc_buffer_init(z);
}

void
btc_script_clear(btc_script_t *z) {
  btc_buffer_clear(z);
}

uint8_t *
btc_script_grow(btc_script_t *z, size_t zn) {
  return btc_buffer_grow(z, zn);
}

uint8_t *
btc_script_resize(btc_script_t *z, size_t zn) {
  return btc_buffer_resize(z, zn);
}

void
btc_script_set(btc_script_t *z, const uint8_t *xp, size_t xn) {
  btc_buffer_set(z, xp, xn);
}

void
btc_script_copy(btc_script_t *z, const btc_script_t *x) {
  btc_buffer_copy(z, x);
}

int
btc_script_equal(const btc_script_t *x, const btc_script_t *y) {
  return btc_buffer_equal(x, y);
}

size_t
btc_script_size(const btc_script_t *x) {
  return btc_buffer_size(x);
}

uint8_t *
btc_script_write(uint8_t *zp, const btc_script_t *x) {
  return btc_buffer_write(zp, x);
}

int
btc_script_read(btc_script_t *z, const uint8_t **xp, size_t *xn) {
  return btc_buffer_read(z, xp, xn);
}

void
btc_script_update(hash256_t *ctx, const btc_script_t *x) {
  btc_buffer_update(ctx, x);
}

void
btc_script_hash160(uint8_t *hash, const btc_script_t *script) {
  btc_hash160(hash, script->data, script->length);
}

void
btc_script_sha256(uint8_t *hash, const btc_script_t *script) {
  btc_sha256(hash, script->data, script->length);
}

int
btc_script_is_p2pk(const btc_script_t *script) {
  return btc_script_get_p2pk(NULL, NULL, script);
}

void
btc_script_set_p2pk(btc_script_t *script, const uint8_t *pub, size_t len) {
  btc_script_grow(script, 2 + len);

  script->data[0] = len;

  memcpy(script->data + 1, pub, len);

  script->data[1 + len] = BTC_OP_CHECKSIG;

  script->length = 2 + len;
}

int
btc_script_get_p2pk(uint8_t *pub, size_t *len, const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    switch (reader.ip) {
      case 0: {
        if (op.length != 33 && op.length != 65)
          return 0;

        if (pub != NULL)
          memcpy(pub, op.data, op.length);

        if (len != NULL)
          *len = op.length;

        break;
      }
      case 1: {
        if (op.value != BTC_OP_CHECKSIG)
          return 0;

        break;
      }
      default: {
        return 0;
      }
    }
  }

  if (reader.ip != 1)
    return 0;

  if (op.value == -1)
    return 0;

  return 1;
}

int
btc_script_is_p2pkh(const btc_script_t *script) {
  return btc_script_get_p2pkh(NULL, script);
}

void
btc_script_set_p2pkh(btc_script_t *script, const uint8_t *hash) {
  btc_script_grow(script, 25);

  script->data[0] = BTC_OP_DUP;
  script->data[1] = BTC_OP_HASH160;
  script->data[2] = 0x14;

  memcpy(script->data + 3, hash, 20);

  script->data[23] = BTC_OP_EQUALVERIFY;
  script->data[24] = BTC_OP_CHECKSIG;

  script->length = 25;
}

int
btc_script_get_p2pkh(uint8_t *hash, const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    switch (reader.ip) {
      case 0:
        if (op.value != BTC_OP_DUP)
          return 0;
        break;
      case 1:
        if (op.value != BTC_OP_HASH160)
          return 0;
        break;
      case 2:
        if (op.length != 20)
          return 0;

        if (hash != NULL)
          memcpy(hash, op.data, 20);

        break;
      case 3:
        if (op.value != BTC_OP_EQUALVERIFY)
          return 0;
        break;
      case 4:
        if (op.value != BTC_OP_CHECKSIG)
          return 0;
        break;
      default:
        return 0;
    }
  }

  if (reader.ip != 4)
    return 0;

  if (op.value == -1)
    return 0;

  return 1;
}

int
btc_script_is_p2sh(const btc_script_t *script) {
  return script->length == 23
      && script->data[0] == BTC_OP_HASH160
      && script->data[1] == 0x14
      && script->data[22] == BTC_OP_EQUAL;
}

void
btc_script_set_p2sh(btc_script_t *script, const uint8_t *hash) {
  btc_script_grow(script, 23);

  script->data[0] = BTC_OP_HASH160;
  script->data[1] = 0x14;

  memcpy(script->data + 2, hash, 20);

  script->data[22] = BTC_OP_EQUAL;

  script->length = 23;
}

int
btc_script_get_p2sh(uint8_t *hash, const btc_script_t *script) {
  if (!btc_script_is_p2sh(script))
    return 0;

  memcpy(hash, script->data + 2, 20);

  return 1;
}

int
btc_script_is_nulldata(const btc_script_t *script, int minimal) {
  btc_reader_t reader;
  btc_opcode_t op;

  if (minimal && script->length > BTC_MAX_OP_RETURN_BYTES)
    return 0;

  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    switch (reader.ip) {
      case 0: {
        if (op.value != BTC_OP_RETURN)
          return 0;

        break;
      }
      default: {
        if (op.value > BTC_OP_16)
          return 0;

        if (minimal && !btc_opcode_is_minimal(&op))
          return 0;

        break;
      }
    }
  }

  if (reader.ip < 0)
    return 0;

  if (op.value == -1)
    return 0;

  return 1;
}

void
btc_script_set_nulldata(btc_script_t *script, uint8_t *data, size_t len) {
  size_t n = 0;

  btc_script_grow(script, 3 + len);

  script->data[n++] = BTC_OP_RETURN;

  if (len <= 0x4b) {
    script->data[n++] = len;
  } else {
    script->data[n++] = BTC_OP_PUSHDATA1;
    script->data[n++] = len;
  }

  memcpy(script->data + n, data, len);

  script->length = n + len;
}

int
btc_script_get_nulldata(uint8_t *data,
                        size_t *len,
                        const btc_script_t *script) {
  if (script->length < 2)
    return 0;

  if (script->data[0] != BTC_OP_RETURN)
    return 0;

  if (script->data[1] <= 0x4b) {
    if (2 + (size_t)script->data[1] != script->length)
      return 0;

    memcpy(data, script->data + 2, script->data[1]);

    *len = script->data[1];

    return 1;
  }

  if (script->length < 3)
    return 0;

  if (script->data[1] == BTC_OP_PUSHDATA1) {
    if (3 + (size_t)script->data[2] != script->length)
      return 0;

    memcpy(data, script->data + 3, script->data[2]);

    *len = script->data[2];

    return 1;
  }

  return 0;
}

int
btc_script_is_commitment(const btc_script_t *script) {
  return script->length >= 38
      && script->data[0] == BTC_OP_RETURN
      && script->data[1] == 0x24
      && script->data[2] == 0xaa
      && script->data[3] == 0x21
      && script->data[4] == 0xa9
      && script->data[5] == 0xed;
}

void
btc_script_set_commitment(btc_script_t *script, const uint8_t *hash) {
  btc_script_grow(script, 38);

  script->data[0] = BTC_OP_RETURN;
  script->data[1] = 0x24;
  script->data[2] = 0xaa;
  script->data[3] = 0x21;
  script->data[4] = 0xa9;
  script->data[5] = 0xed;

  memcpy(script->data + 6, hash, 32);
}

int
btc_script_get_commitment(uint8_t *hash, const btc_script_t *script) {
  if (!btc_script_is_commitment(script))
    return 0;

  memcpy(hash, script->data + 6, 32);

  return 1;
}

int
btc_script_is_program(const btc_script_t *script) {
  if (script->length < 4 || script->length > 42)
    return 0;

  if (script->data[0] != BTC_OP_0
      && (script->data[0] < BTC_OP_1 || script->data[0] > BTC_OP_16)) {
    return 0;
  }

  if ((size_t)script->data[1] + 2 != script->length)
    return 0;

  return 1;
}

void
btc_script_set_program(btc_script_t *script, const btc_program_t *program) {
  btc_script_grow(script, 2 + program->length);

  script->data[0] = program->version == 0 ? 0 : program->version + 0x50;
  script->data[1] = program->length;

  memcpy(script->data + 2, program->data, program->length);

  script->length = 2 + program->length;
}

int
btc_script_get_program(btc_program_t *program, const btc_script_t *script) {
  if (!btc_script_is_program(script))
    return 0;

  program->version = script->data[0];
  program->length = script->data[1];

  if (program->version != 0)
    program->version -= 0x50;

  memcpy(program->data, script->data + 2, program->length);

  return 1;
}

int
btc_script_is_p2wpkh(const btc_script_t *script) {
  return script->length == 22
      && script->data[0] == BTC_OP_0
      && script->data[1] == 20;
}

int
btc_script_get_p2wpkh(uint8_t *hash, const btc_script_t *script) {
  if (!btc_script_is_p2wpkh(script))
    return 0;

  memcpy(hash, script->data + 2, 20);

  return 1;
}

void
btc_script_set_p2wpkh(btc_script_t *script, const uint8_t *hash) {
  btc_script_grow(script, 22);

  script->data[0] = 0;
  script->data[1] = 20;

  memcpy(script->data + 2, hash, 20);

  script->length = 22;
}

int
btc_script_is_p2wsh(const btc_script_t *script) {
  return script->length == 34
      && script->data[0] == BTC_OP_0
      && script->data[1] == 32;
}

int
btc_script_get_p2wsh(uint8_t *hash, const btc_script_t *script) {
  if (!btc_script_is_p2wsh(script))
    return 0;

  memcpy(hash, script->data + 2, 32);

  return 1;
}

void
btc_script_set_p2wsh(btc_script_t *script, const uint8_t *hash) {
  btc_script_grow(script, 34);

  script->data[0] = 0;
  script->data[1] = 32;

  memcpy(script->data + 2, hash, 32);

  script->length = 34;
}

int
btc_script_is_unspendable(const btc_script_t *script) {
  if (script->length > BTC_MAX_SCRIPT_SIZE)
    return 1;

  return script->length > 0 && script->data[0] == BTC_OP_RETURN;
}

int
btc_script_is_push_only(const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    if (op.value > BTC_OP_16)
      return 0;
  }

  if (op.value == -1)
    return 0;

  return 1;
}

int
btc_script_get_height(uint32_t *height, const btc_script_t *script) {
  btc_opcode_t op;
  uint8_t tmp[9];
  int64_t num;

  *height = (uint32_t)-1;

  if (!btc_opcode_import(&op, script->data, script->length))
    return 0;

  if (op.value == BTC_OP_0) {
    *height = 0;
    return 1;
  }

  if (op.value >= BTC_OP_1 && op.value <= BTC_OP_16) {
    *height = op.value - 0x50;
    return 1;
  }

  if (op.value > 6)
    return 0;

  num = btc_scriptnum_import(op.data, op.length);

  if (num < 16)
    return 0;

  if (num > INT32_MAX)
    return 0;

  if (btc_scriptnum_export(tmp, num) != op.length)
    return 0;

  if (memcmp(op.data, tmp, op.length) != 0)
    return 0;

  *height = num;

  return 1;
}

static int
btc_script_get_redeem(btc_script_t *redeem, const btc_script_t *script) {
  btc_opcode_t op, last;
  btc_reader_t reader;

  memset(&op, 0, sizeof(op));

  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    if (op.value > BTC_OP_16)
      return 0;

    last = op;
  }

  if (reader.ip < 0)
    return 0;

  if (op.value == -1)
    return 0;

  if (last.length > 0) {
    redeem->data = (uint8_t *)last.data;
    redeem->length = last.length;
    redeem->alloc = 0;
    return 1;
  }

  return 0;
}

int
btc_script_sigops(const btc_script_t *script, int accurate) {
  btc_reader_t reader;
  btc_opcode_t op;
  int lastop = -1;
  int total = 0;

  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    switch (op.value) {
      case BTC_OP_CHECKSIG:
      case BTC_OP_CHECKSIGVERIFY:
        total += 1;
        break;
      case BTC_OP_CHECKMULTISIG:
      case BTC_OP_CHECKMULTISIGVERIFY:
        if (accurate && lastop >= BTC_OP_1 && lastop <= BTC_OP_16)
          total += lastop - 0x50;
        else
          total += BTC_MAX_MULTISIG_PUBKEYS;
        break;
    }

    lastop = op.value;
  }

  return total;
}

int
btc_script_p2sh_sigops(const btc_script_t *script, const btc_script_t *input) {
  btc_script_t redeem;

  if (!btc_script_is_p2sh(script))
    return btc_script_sigops(script, 1);

  if (!btc_script_get_redeem(&redeem, input))
    return 0;

  return btc_script_sigops(&redeem, 1);
}

int
btc_script_witness_sigops(const btc_script_t *script,
                          const btc_script_t *input,
                          const btc_stack_t *witness) {
  btc_program_t program;
  btc_script_t redeem;

  if (!btc_script_get_program(&program, script)) {
    if (!btc_script_is_p2sh(script))
      return 0;

    if (!btc_script_get_redeem(&redeem, input))
      return 0;

    if (!btc_script_get_program(&program, &redeem))
      return 0;
  }

  if (program.version == 0) {
    if (program.length == 20)
      return 1;

    if (program.length == 32 && witness->length > 0) {
      const btc_script_t *item = btc_stack_get(witness, -1);
      return btc_script_sigops(item, 1);
    }
  }

  return 0;
}

void
btc_script_get_subscript(btc_script_t *z, const btc_script_t *x, int index) {
  btc_reader_t reader;
  btc_writer_t writer;
  btc_opcode_t op;

  if (index == 0) {
    btc_script_copy(z, x);
    return;
  }

  btc_reader_init(&reader, z);
  btc_writer_init(&writer);

  while (btc_reader_next(&op, &reader)) {
    if (reader.ip < index)
      continue;

    btc_writer_push(&writer, btc_opcode_clone(&op));
  }

  btc_writer_compile(z, &writer);
  btc_writer_clear(&writer);
}

int
btc_script_find_and_delete(btc_script_t *z, const btc_buffer_t *sig) {
  /**
   * Remove all matched data elements from
   * a script's code (used to remove signatures
   * before verification). Note that this
   * compares and removes data on the _byte level_.
   * It also reserializes the data to a single
   * script with minimaldata encoding beforehand.
   * A signature will _not_ be removed if it is
   * not minimaldata.
   *
   * https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2014-November/006878.html
   * https://test.webbtc.com/tx/19aa42fee0fa57c45d3b16488198b27caaacc4ff5794510d0c17f173f05587ff
   */
  btc_reader_t reader;
  btc_writer_t writer;
  btc_opcode_t target;
  btc_opcode_t op;
  int total = 0;
  int found = 0;

  btc_opcode_set_push(&target, sig->data, sig->length);

  if (z->length < btc_opcode_size(&target))
    return 0;

  btc_reader_init(&reader, z);

  while (btc_reader_next(&op, &reader)) {
    if (btc_opcode_equal(&op, &target)) {
      found = 1;
      break;
    }
  }

  if (!found)
    return 0;

  btc_reader_init(&reader, z);
  btc_writer_init(&writer);

  while (btc_reader_next(&op, &reader)) {
    if (btc_opcode_equal(&op, &target)) {
      total += 1;
      continue;
    }

    btc_writer_push(&writer, btc_opcode_clone(&op));
  }

  btc_writer_compile(z, &writer);
  btc_writer_clear(&writer);

  return total;
}

void
btc_script_remove_separators(btc_script_t *z, const btc_script_t *x) {
  /**
   * Get the script's "subscript" starting at a separator.
   * Remove all OP_CODESEPARATORs if present. This bizarre
   * behavior is necessary for signing and verification when
   * code separators are present.
   */
  btc_reader_t reader;
  btc_writer_t writer;
  btc_opcode_t op;
  int found = 0;

  btc_reader_init(&reader, x);

  /* Optimizing for the common case:
     Check for any separators first. */
  while (btc_reader_next(&op, &reader)) {
    if (op.value == BTC_OP_CODESEPARATOR) {
      found = 1;
      break;
    }
  }

  if (!found) {
    btc_script_copy(z, x);
    return;
  }

  /* Uncommon case: someone actually
     has a code separator. Go through
     and remove them all. */
  btc_reader_init(&reader, x);
  btc_writer_init(&writer);

  while (btc_reader_next(&op, &reader)) {
    if (op.value != BTC_OP_CODESEPARATOR)
      btc_writer_push(&writer, btc_opcode_clone(&op));
  }

  btc_writer_compile(z, &writer);
  btc_writer_clear(&writer);
}

static int
is_signature_encoding(const btc_buffer_t *sig) {
  /* Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
   * * total-length: 1-byte length descriptor of everything that follows,
   *   excluding the sighash byte.
   * * R-length: 1-byte length descriptor of the R value that follows.
   * * R: arbitrary-length big-endian encoded R value. It must use the shortest
   *   possible encoding for a positive integers (which means no null bytes at
   *   the start, except a single one when the next byte has its highest bit set).
   * * S-length: 1-byte length descriptor of the S value that follows.
   * * S: arbitrary-length big-endian encoded S value. The same rules apply.
   * * sighash: 1-byte value indicating what data is hashed (not part of the DER
   *   signature)
   */
  unsigned int lenR, lenS;

  /* Minimum and maximum size constraints. */
  if (sig->length < 9)
    return 0;

  if (sig->length > 73)
    return 0;

  /* A signature is of type 0x30 (compound). */
  if (sig->data[0] != 0x30)
    return 0;

  /* Make sure the length covers the entire signature. */
  if (sig->data[1] != sig->length - 3)
    return 0;

  /* Extract the length of the R element. */
  lenR = sig->data[3];

  /* Make sure the length of the S element is still inside the signature. */
  if (5 + lenR >= sig->length)
    return 0;

  /* Extract the length of the S element. */
  lenS = sig->data[5 + lenR];

  /* Verify that the length of the signature matches the sum of the length */
  /* of the elements. */
  if ((size_t)(lenR + lenS + 7) != sig->length)
    return 0;

  /* Check whether the R element is an integer. */
  if (sig->data[2] != 0x02)
    return 0;

  /* Zero-length integers are not allowed for R. */
  if (lenR == 0)
    return 0;

  /* Negative numbers are not allowed for R. */
  if (sig->data[4] & 0x80)
    return 0;

  /* Null bytes at the start of R are not allowed, unless R would */
  /* otherwise be interpreted as a negative number. */
  if (lenR > 1 && (sig->data[4] == 0x00) && !(sig->data[5] & 0x80))
    return 0;

  /* Check whether the S element is an integer. */
  if (sig->data[lenR + 4] != 0x02)
    return 0;

  /* Zero-length integers are not allowed for S. */
  if (lenS == 0)
    return 0;

  /* Negative numbers are not allowed for S. */
  if (sig->data[lenR + 6] & 0x80)
    return 0;

  /* Null bytes at the start of S are not allowed, unless S would otherwise be */
  /* interpreted as a negative number. */
  if (lenS > 1 && (sig->data[lenR + 6] == 0x00) && !(sig->data[lenR + 7] & 0x80))
    return 0;

  return 1;
}

static int
is_low_der(const btc_buffer_t *sig) {
  return btc_ecdsa_is_low_der(sig->data, sig->length);
}

static int
is_hash_type(const btc_buffer_t *sig) {
  int type;

  if (sig->length == 0)
    return 0;

  type = sig->data[sig->length - 1] & ~BTC_SIGHASH_ANYONECANPAY;

  if (type < BTC_SIGHASH_ALL || type > BTC_SIGHASH_SINGLE)
    return 0;

  return 1;
}

static int
is_key_encoding(const btc_buffer_t *key) {
  if (key->length < 33)
    return 0;

  if (key->data[0] == 0x04) {
    if (key->length != 65)
      return 0;
  } else if (key->data[0] == 0x02 || key->data[0] == 0x03) {
    if (key->length != 33)
      return 0;
  } else {
    return 0;
  }

  return 1;
}

static int
is_compressed_encoding(const btc_buffer_t *key) {
  if (key->length != 33)
    return 0;

  if (key->data[0] != 0x02 && key->data[0] != 0x03)
    return 0;

  return 1;
}

static int
validate_signature(const btc_buffer_t *sig, unsigned int flags) {
  /* Allow empty sigs. */
  if (sig->length == 0)
    return BTC_SCRIPT_ERR_OK;

  if ((flags & BTC_SCRIPT_VERIFY_DERSIG)
      || (flags & BTC_SCRIPT_VERIFY_LOW_S)
      || (flags & BTC_SCRIPT_VERIFY_STRICTENC)) {
    if (!is_signature_encoding(sig))
      return BTC_SCRIPT_ERR_SIG_DER;
  }

  if (flags & BTC_SCRIPT_VERIFY_LOW_S) {
    if (!is_low_der(sig))
      return BTC_SCRIPT_ERR_SIG_HIGH_S;
  }

  if (flags & BTC_SCRIPT_VERIFY_STRICTENC) {
    if (!is_hash_type(sig))
      return BTC_SCRIPT_ERR_SIG_HASHTYPE;
  }

  return BTC_SCRIPT_ERR_OK;
}

static int
validate_key(const btc_buffer_t *key, unsigned int flags, int version) {
  if (flags & BTC_SCRIPT_VERIFY_STRICTENC) {
    if (!is_key_encoding(key))
      return BTC_SCRIPT_ERR_PUBKEYTYPE;
  }

  if (version == 1) {
    if (flags & BTC_SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) {
      if (!is_compressed_encoding(key))
        return BTC_SCRIPT_ERR_WITNESS_PUBKEYTYPE;
    }
  }

  return BTC_SCRIPT_ERR_OK;
}

static int
checksig(const uint8_t *msg, const btc_buffer_t *sig, const btc_buffer_t *key) {
  if (sig->length == 0)
    return 0;

  return btc_ecdsa_checksig(msg, sig->data, sig->length - 1,
                                 key->data, key->length);
}

#define THROW(x) do { err = (x); goto done; } while (0)

int
btc_script_execute(const btc_script_t *script,
                   btc_stack_t *stack,
                   unsigned int flags,
                   const btc_tx_t *tx,
                   size_t index,
                   int64_t value,
                   int version,
                   btc_tx_cache_t *cache) {
  int err = BTC_SCRIPT_ERR_OK;
  int lastsep = 0;
  int opcount = 0;
  int negate = 0;
  int minimal = 0;

  btc_state_t state;
  btc_stack_t alt;
  btc_reader_t reader;
  btc_script_t subscript;
  btc_opcode_t op;

  if (script->length > BTC_MAX_SCRIPT_SIZE)
    return BTC_SCRIPT_ERR_SCRIPT_SIZE;

  if (flags & BTC_SCRIPT_VERIFY_MINIMALDATA)
    minimal = 1;

  btc_state_init(&state);
  btc_stack_init(&alt);
  btc_script_init(&subscript);
  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    if (op.length > BTC_MAX_SCRIPT_PUSH)
      THROW(BTC_SCRIPT_ERR_PUSH_SIZE);

    if (op.value > BTC_OP_16 && ++opcount > BTC_MAX_SCRIPT_OPS)
      THROW(BTC_SCRIPT_ERR_OP_COUNT);

    if (btc_opcode_is_disabled(&op))
      THROW(BTC_SCRIPT_ERR_DISABLED_OPCODE);

    if (negate && !btc_opcode_is_branch(&op)) {
      if (stack->length + alt.length > BTC_MAX_SCRIPT_STACK)
        THROW(BTC_SCRIPT_ERR_STACK_SIZE);
      continue;
    }

    if (op.value <= BTC_OP_PUSHDATA4) {
      if (minimal && !btc_opcode_is_minimal(&op))
        THROW(BTC_SCRIPT_ERR_MINIMALDATA);

      btc_stack_push_data(stack, op.data, op.length); /* no alloc */

      if (stack->length + alt.length > BTC_MAX_SCRIPT_STACK)
        THROW(BTC_SCRIPT_ERR_STACK_SIZE);

      continue;
    }

    switch (op.value) {
      case BTC_OP_1NEGATE: {
        btc_stack_push_int(stack, -1);
        break;
      }
      case BTC_OP_1:
      case BTC_OP_2:
      case BTC_OP_3:
      case BTC_OP_4:
      case BTC_OP_5:
      case BTC_OP_6:
      case BTC_OP_7:
      case BTC_OP_8:
      case BTC_OP_9:
      case BTC_OP_10:
      case BTC_OP_11:
      case BTC_OP_12:
      case BTC_OP_13:
      case BTC_OP_14:
      case BTC_OP_15:
      case BTC_OP_16: {
        btc_stack_push_int(stack, op.value - 0x50);
        break;
      }
      case BTC_OP_NOP: {
        break;
      }
      case BTC_OP_CHECKLOCKTIMEVERIFY: {
        int64_t locktime;

        /* OP_CHECKLOCKTIMEVERIFY = OP_NOP2 */
        if (!(flags & BTC_SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
          if (flags & BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            THROW(BTC_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
          break;
        }

        if (tx == NULL)
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&locktime, stack, -1, minimal, 5))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (locktime < 0)
          THROW(BTC_SCRIPT_ERR_NEGATIVE_LOCKTIME);

        if (!btc_tx_verify_locktime(tx, index, locktime))
          THROW(BTC_SCRIPT_ERR_UNSATISFIED_LOCKTIME);

        break;
      }
      case BTC_OP_CHECKSEQUENCEVERIFY: {
        int64_t locktime;

        /* OP_CHECKSEQUENCEVERIFY = OP_NOP3 */
        if (!(flags & BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
          if (flags & BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            THROW(BTC_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
          break;
        }

        if (tx == NULL)
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&locktime, stack, -1, minimal, 5))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (locktime < 0)
          THROW(BTC_SCRIPT_ERR_NEGATIVE_LOCKTIME);

        if (!btc_tx_verify_sequence(tx, index, locktime))
          THROW(BTC_SCRIPT_ERR_UNSATISFIED_LOCKTIME);

        break;
      }
      case BTC_OP_NOP1:
      case BTC_OP_NOP4:
      case BTC_OP_NOP5:
      case BTC_OP_NOP6:
      case BTC_OP_NOP7:
      case BTC_OP_NOP8:
      case BTC_OP_NOP9:
      case BTC_OP_NOP10: {
        if (flags & BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
          THROW(BTC_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
        break;
      }
      case BTC_OP_IF:
      case BTC_OP_NOTIF: {
        int val = 0;

        if (!negate) {
          if (stack->length < 1)
            THROW(BTC_SCRIPT_ERR_UNBALANCED_CONDITIONAL);

          if (version == 1 && (flags & BTC_SCRIPT_VERIFY_MINIMALIF)) {
            const btc_buffer_t *item = btc_stack_get(stack, -1);

            if (item->length > 1)
              THROW(BTC_SCRIPT_ERR_MINIMALIF);

            if (item->length == 1 && item->data[0] != 1)
              THROW(BTC_SCRIPT_ERR_MINIMALIF);
          }

          val = btc_stack_get_bool(stack, -1);

          if (op.value == BTC_OP_NOTIF)
            val = !val;

          btc_stack_drop(stack);
        }

        btc_state_push(&state, val);

        if (!val)
          negate += 1;

        break;
      }
      case BTC_OP_ELSE: {
        if (state.length == 0)
          THROW(BTC_SCRIPT_ERR_UNBALANCED_CONDITIONAL);

        state.items[state.length - 1] = !state.items[state.length - 1];

        if (!state.items[state.length - 1])
          negate += 1;
        else
          negate -= 1;

        break;
      }
      case BTC_OP_ENDIF: {
        if (state.length == 0)
          THROW(BTC_SCRIPT_ERR_UNBALANCED_CONDITIONAL);

        if (!btc_state_pop(&state))
          negate -= 1;

        break;
      }
      case BTC_OP_VERIFY: {
        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_bool(stack, -1))
          THROW(BTC_SCRIPT_ERR_VERIFY);

        btc_stack_drop(stack);

        break;
      }
      case BTC_OP_RETURN: {
        THROW(BTC_SCRIPT_ERR_OP_RETURN);
      }
      case BTC_OP_TOALTSTACK: {
        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_stack_push(&alt, btc_stack_pop(stack));

        break;
      }
      case BTC_OP_FROMALTSTACK: {
        if (alt.length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);

        btc_stack_push(stack, btc_stack_pop(&alt));

        break;
      }
      case BTC_OP_2DROP: {
        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_stack_drop(stack);
        btc_stack_drop(stack);

        break;
      }
      case BTC_OP_2DUP: {
        const btc_buffer_t *v1, *v2;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -2);
        v2 = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_clone(v1)); /* no alloc */
        btc_stack_push(stack, btc_buffer_clone(v2)); /* no alloc */

        break;
      }
      case BTC_OP_3DUP: {
        const btc_buffer_t *v1, *v2, *v3;

        if (stack->length < 3)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -3);
        v2 = btc_stack_get(stack, -2);
        v3 = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_clone(v1)); /* no alloc */
        btc_stack_push(stack, btc_buffer_clone(v2)); /* no alloc */
        btc_stack_push(stack, btc_buffer_clone(v3)); /* no alloc */

        break;
      }
      case BTC_OP_2OVER: {
        const btc_buffer_t *v1, *v2;

        if (stack->length < 4)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -4);
        v2 = btc_stack_get(stack, -3);

        btc_stack_push(stack, btc_buffer_clone(v1)); /* no alloc */
        btc_stack_push(stack, btc_buffer_clone(v2)); /* no alloc */

        break;
      }
      case BTC_OP_2ROT: {
        const btc_buffer_t *v1, *v2;

        if (stack->length < 6)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -6);
        v2 = btc_stack_get(stack, -5);

        btc_stack_erase(stack, -6, -4);
        btc_stack_push(stack, (btc_buffer_t *)v1);
        btc_stack_push(stack, (btc_buffer_t *)v2);

        break;
      }
      case BTC_OP_2SWAP: {
        if (stack->length < 4)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_stack_swap(stack, -4, -2);
        btc_stack_swap(stack, -3, -1);

        break;
      }
      case BTC_OP_IFDUP: {
        const btc_buffer_t *val;

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (btc_stack_get_bool(stack, -1)) {
          val = btc_stack_get(stack, -1);

          btc_stack_push(stack, btc_buffer_clone(val)); /* no alloc */
        }

        break;
      }
      case BTC_OP_DEPTH: {
        btc_stack_push_int(stack, stack->length);
        break;
      }
      case BTC_OP_DROP: {
        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_stack_drop(stack);

        break;
      }
      case BTC_OP_DUP: {
        const btc_buffer_t *val;

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_clone(val)); /* no alloc */

        break;
      }
      case BTC_OP_NIP: {
        btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_remove(stack, -2);

        btc_buffer_destroy(val);

        break;
      }
      case BTC_OP_OVER: {
        const btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -2);

        btc_stack_push(stack, btc_buffer_clone(val)); /* no alloc */

        break;
      }
      case BTC_OP_PICK:
      case BTC_OP_ROLL: {
        const btc_buffer_t *val;
        int num;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_int(&num, stack, -1, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        btc_stack_drop(stack);

        if (num < 0 || (size_t)num >= stack->length)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (op.value == BTC_OP_ROLL) {
          btc_stack_push(stack, btc_stack_remove(stack, -num - 1));
        } else {
          val = btc_stack_get(stack, -num - 1);
          btc_stack_push(stack, btc_buffer_clone(val));
        }

        break;
      }
      case BTC_OP_ROT: {
        if (stack->length < 3)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_stack_swap(stack, -3, -2);
        btc_stack_swap(stack, -2, -1);

        break;
      }
      case BTC_OP_SWAP: {
        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_stack_swap(stack, -2, -1);

        break;
      }
      case BTC_OP_TUCK: {
        const btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_insert(stack, -2, btc_buffer_clone(val)); /* no alloc */

        break;
      }
      case BTC_OP_SIZE: {
        const btc_buffer_t *val;

        if (stack->length < 1)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_push_int(stack, val->length);

        break;
      }
      case BTC_OP_EQUAL:
      case BTC_OP_EQUALVERIFY: {
        const btc_buffer_t *v1, *v2;
        int res;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -2);
        v2 = btc_stack_get(stack, -1);

        res = btc_buffer_equal(v1, v2);

        btc_stack_drop(stack);
        btc_stack_drop(stack);

        btc_stack_push_bool(stack, res);

        if (op.value == BTC_OP_EQUALVERIFY) {
          if (!res)
            THROW(BTC_SCRIPT_ERR_EQUALVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      case BTC_OP_1ADD:
      case BTC_OP_1SUB:
      case BTC_OP_NEGATE:
      case BTC_OP_ABS:
      case BTC_OP_NOT:
      case BTC_OP_0NOTEQUAL: {
        int64_t num;

        if (stack->length < 1)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&num, stack, -1, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        switch (op.value) {
          case BTC_OP_1ADD:
            num++;
            break;
          case BTC_OP_1SUB:
            num--;
            break;
          case BTC_OP_NEGATE:
            num = -num;
            break;
          case BTC_OP_ABS:
            if (num < 0)
              num = -num;
            break;
          case BTC_OP_NOT:
            num = (num == 0);
            break;
          case BTC_OP_0NOTEQUAL:
            num = (num != 0);
            break;
          default:
            btc_abort(); /* LCOV_EXCL_LINE */
            break;
        }

        btc_stack_drop(stack);
        btc_stack_push_num(stack, num);

        break;
      }
      case BTC_OP_ADD:
      case BTC_OP_SUB:
      case BTC_OP_BOOLAND:
      case BTC_OP_BOOLOR:
      case BTC_OP_NUMEQUAL:
      case BTC_OP_NUMEQUALVERIFY:
      case BTC_OP_NUMNOTEQUAL:
      case BTC_OP_LESSTHAN:
      case BTC_OP_GREATERTHAN:
      case BTC_OP_LESSTHANOREQUAL:
      case BTC_OP_GREATERTHANOREQUAL:
      case BTC_OP_MIN:
      case BTC_OP_MAX: {
        int64_t n1, n2, num;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&n1, stack, -2, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (!btc_stack_get_num(&n2, stack, -1, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        switch (op.value) {
          case BTC_OP_ADD:
            num = n1 + n2;
            break;
          case BTC_OP_SUB:
            num = n1 - n2;
            break;
          case BTC_OP_BOOLAND:
            num = (n1 != 0 && n2 != 0);
            break;
          case BTC_OP_BOOLOR:
            num = (n1 != 0 || n2 != 0);
            break;
          case BTC_OP_NUMEQUAL:
            num = (n1 == n2);
            break;
          case BTC_OP_NUMEQUALVERIFY:
            num = (n1 == n2);
            break;
          case BTC_OP_NUMNOTEQUAL:
            num = (n1 != n2);
            break;
          case BTC_OP_LESSTHAN:
            num = (n1 < n2);
            break;
          case BTC_OP_GREATERTHAN:
            num = (n1 > n2);
            break;
          case BTC_OP_LESSTHANOREQUAL:
            num = (n1 <= n2);
            break;
          case BTC_OP_GREATERTHANOREQUAL:
            num = (n1 >= n2);
            break;
          case BTC_OP_MIN:
            num = n1 < n2 ? n1 : n2;
            break;
          case BTC_OP_MAX:
            num = n1 > n2 ? n1 : n2;
            break;
          default:
            btc_abort(); /* LCOV_EXCL_LINE */
            break;
        }

        btc_stack_drop(stack);
        btc_stack_drop(stack);

        btc_stack_push_num(stack, num);

        if (op.value == BTC_OP_NUMEQUALVERIFY) {
          if (!btc_stack_get_bool(stack, -1))
            THROW(BTC_SCRIPT_ERR_NUMEQUALVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      case BTC_OP_WITHIN: {
        int64_t n1, n2, n3;
        int val;

        if (stack->length < 3)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&n1, stack, -3, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (!btc_stack_get_num(&n2, stack, -2, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (!btc_stack_get_num(&n3, stack, -1, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        val = (n2 <= n1 && n1 < n3);

        btc_stack_drop(stack);
        btc_stack_drop(stack);
        btc_stack_drop(stack);

        btc_stack_push_bool(stack, val);

        break;
      }
      case BTC_OP_RIPEMD160: {
        const btc_buffer_t *val;
        uint8_t hash[20];

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_ripemd160(hash, val->data, val->length);

        btc_stack_drop(stack);
        btc_stack_push_data(stack, hash, 20);

        break;
      }
      case BTC_OP_SHA1: {
        const btc_buffer_t *val;
        uint8_t hash[20];

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_sha1(hash, val->data, val->length);

        btc_stack_drop(stack);
        btc_stack_push_data(stack, hash, 20);

        break;
      }
      case BTC_OP_SHA256: {
        const btc_buffer_t *val;
        uint8_t hash[32];

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_sha256(hash, val->data, val->length);

        btc_stack_drop(stack);
        btc_stack_push_data(stack, hash, 32);

        break;
      }
      case BTC_OP_HASH160: {
        const btc_buffer_t *val;
        uint8_t hash[20];

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_hash160(hash, val->data, val->length);

        btc_stack_drop(stack);
        btc_stack_push_data(stack, hash, 20);

        break;
      }
      case BTC_OP_HASH256: {
        const btc_buffer_t *val;
        uint8_t hash[32];

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_hash256(hash, val->data, val->length);

        btc_stack_drop(stack);
        btc_stack_push_data(stack, hash, 32);

        break;
      }
      case BTC_OP_CODESEPARATOR: {
        lastsep = reader.ip + 1;
        break;
      }
      case BTC_OP_CHECKSIG:
      case BTC_OP_CHECKSIGVERIFY: {
        const btc_buffer_t *sig, *key;
        unsigned int type;
        uint8_t hash[32];
        int res;

        if (tx == NULL)
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        sig = btc_stack_get(stack, -2);
        key = btc_stack_get(stack, -1);

        btc_script_get_subscript(&subscript, script, lastsep);

        if (version == 0)
          btc_script_find_and_delete(&subscript, sig);

        if ((err = validate_signature(sig, flags)))
          goto done;

        if ((err = validate_key(key, flags, version)))
          goto done;

        res = 0;

        if (sig->length > 0) {
          type = sig->data[sig->length - 1];

          btc_tx_sighash(hash, tx, index, &subscript,
                         value, type, version, cache);

          res = checksig(hash, sig, key);
        }

        if (!res && (flags & BTC_SCRIPT_VERIFY_NULLFAIL)) {
          if (sig->length != 0)
            THROW(BTC_SCRIPT_ERR_SIG_NULLFAIL);
        }

        btc_stack_drop(stack);
        btc_stack_drop(stack);

        btc_stack_push_bool(stack, res);

        if (op.value == BTC_OP_CHECKSIGVERIFY) {
          if (!res)
            THROW(BTC_SCRIPT_ERR_CHECKSIGVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      case BTC_OP_CHECKMULTISIG:
      case BTC_OP_CHECKMULTISIGVERIFY: {
        int i, j, m, n, okey, ikey, isig, res;
        const btc_buffer_t *sig, *key;
        unsigned int type;
        uint8_t hash[32];

        if (tx == NULL)
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        i = 1;

        if (stack->length < (size_t)i)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_int(&n, stack, -i, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        okey = n + 2;

        if (n < 0 || n > BTC_MAX_MULTISIG_PUBKEYS)
          THROW(BTC_SCRIPT_ERR_PUBKEY_COUNT);

        opcount += n;

        if (opcount > BTC_MAX_SCRIPT_OPS)
          THROW(BTC_SCRIPT_ERR_OP_COUNT);

        i += 1;
        ikey = i;
        i += n;

        if (stack->length < (size_t)i)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_int(&m, stack, -i, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (m < 0 || m > n)
          THROW(BTC_SCRIPT_ERR_SIG_COUNT);

        i += 1;
        isig = i;
        i += m;

        if (stack->length < (size_t)i)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_script_get_subscript(&subscript, script, lastsep);

        for (j = 0; j < m; j++) {
          sig = btc_stack_get(stack, -isig - j);

          if (version == 0)
            btc_script_find_and_delete(&subscript, sig);
        }

        res = 1;

        while (res && m > 0) {
          sig = btc_stack_get(stack, -isig);
          key = btc_stack_get(stack, -ikey);

          if ((err = validate_signature(sig, flags)))
            goto done;

          if ((err = validate_key(key, flags, version)))
            goto done;

          if (sig->length > 0) {
            type = sig->data[sig->length - 1];

            btc_tx_sighash(hash, tx, index, &subscript,
                           value, type, version, cache);

            if (checksig(hash, sig, key)) {
              isig += 1;
              m -= 1;
            }
          }

          ikey += 1;
          n -= 1;

          if (m > n)
            res = 0;
        }

        while (i > 1) {
          if (!res && (flags & BTC_SCRIPT_VERIFY_NULLFAIL)) {
            if (okey == 0 && btc_stack_get(stack, -1)->length != 0)
              THROW(BTC_SCRIPT_ERR_SIG_NULLFAIL);
          }

          if (okey > 0)
            okey -= 1;

          btc_stack_drop(stack);

          i -= 1;
        }

        if (stack->length < 1)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (flags & BTC_SCRIPT_VERIFY_NULLDUMMY) {
          if (btc_stack_get(stack, -1)->length != 0)
            THROW(BTC_SCRIPT_ERR_SIG_NULLDUMMY);
        }

        btc_stack_drop(stack);
        btc_stack_push_bool(stack, res);

        if (op.value == BTC_OP_CHECKMULTISIGVERIFY) {
          if (!res)
            THROW(BTC_SCRIPT_ERR_CHECKMULTISIGVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      default: {
        THROW(BTC_SCRIPT_ERR_BAD_OPCODE);
      }
    }

    if (stack->length + alt.length > BTC_MAX_SCRIPT_STACK)
      THROW(BTC_SCRIPT_ERR_STACK_SIZE);
  }

  if (op.value == -1)
    THROW(BTC_SCRIPT_ERR_BAD_OPCODE);

  if (state.length != 0)
    THROW(BTC_SCRIPT_ERR_UNBALANCED_CONDITIONAL);

done:
  btc_state_clear(&state);
  btc_stack_clear(&alt);
  btc_script_clear(&subscript);
  return err;
}

static int
btc_script_verify_program(const btc_stack_t *witness,
                          const btc_script_t *output,
                          unsigned int flags,
                          const btc_tx_t *tx,
                          size_t index,
                          int64_t value,
                          btc_tx_cache_t *cache) {
  int err = BTC_SCRIPT_ERR_OK;
  btc_script_t *redeem = NULL;
  btc_program_t program;
  btc_stack_t stack;
  uint8_t hash[32];
  size_t i;

  CHECK((flags & BTC_SCRIPT_VERIFY_WITNESS) != 0);

  btc_stack_init(&stack);

  if (!btc_script_get_program(&program, output))
    THROW(BTC_SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

  btc_stack_copy(&stack, witness);

  if (program.version == 0) {
    if (program.length == 32) {
      if (stack.length == 0)
        THROW(BTC_SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);

      redeem = btc_stack_pop(&stack);

      btc_sha256(hash, redeem->data, redeem->length);

      if (memcmp(hash, program.data, 32) != 0)
        THROW(BTC_SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    } else if (program.length == 20) {
      if (stack.length != 2)
        THROW(BTC_SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

      redeem = btc_script_create();

      btc_script_set_p2pkh(redeem, program.data);
    } else {
      /* Failure on version=0 (bad program data length). */
      THROW(BTC_SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
    }
  } else {
    /* Anyone can spend (we can return true here
       if we want to always relay these transactions).
       Otherwise, if we want to act like an "old"
       implementation and only accept them in blocks,
       we can use the regular output script which will
       succeed in a block, but fail in the mempool
       due to VERIFY_CLEANSTACK. */
    if (flags & BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
      THROW(BTC_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    goto done;
  }

  /* Witnesses still have push limits. */
  for (i = 0; i < stack.length; i++) {
    if (stack.items[i]->length > BTC_MAX_SCRIPT_PUSH)
      THROW(BTC_SCRIPT_ERR_PUSH_SIZE);
  }

  /* Verify the redeem script. */
  if ((err = btc_script_execute(redeem, &stack, flags,
                                tx, index, value, 1, cache))) {
    goto done;
  }

  /* Verify the stack values. */
  if (stack.length != 1 || !btc_stack_get_bool(&stack, -1))
    THROW(BTC_SCRIPT_ERR_EVAL_FALSE);

done:
  btc_stack_clear(&stack);
  if (redeem != NULL)
    btc_script_destroy(redeem);
  return err;
}

int
btc_script_verify(const btc_script_t *input,
                  const btc_stack_t *witness,
                  const btc_script_t *output,
                  const btc_tx_t *tx,
                  size_t index,
                  int64_t value,
                  unsigned int flags,
                  btc_tx_cache_t *cache) {
  int err = BTC_SCRIPT_ERR_OK;
  btc_script_t *redeem = NULL;
  btc_stack_t stack, copy;
  btc_opcode_t op1, op2;
  int had_witness;

  /* Setup a stack. */
  btc_stack_init(&stack);
  btc_stack_init(&copy);

  if (flags & BTC_SCRIPT_VERIFY_SIGPUSHONLY) {
    if (!btc_script_is_push_only(input))
      THROW(BTC_SCRIPT_ERR_SIG_PUSHONLY);
  }

  /* Execute the input script. */
  if ((err = btc_script_execute(input, &stack, flags,
                                tx, index, value, 0, cache))) {
    goto done;
  }

  /* Copy the stack for P2SH */
  if (flags & BTC_SCRIPT_VERIFY_P2SH)
    btc_stack_copy(&copy, &stack);

  /* Execute the previous output script. */
  if ((err = btc_script_execute(output, &stack, flags,
                                tx, index, value, 0, cache))) {
    goto done;
  }

  /* Verify the stack values. */
  if (stack.length == 0 || !btc_stack_get_bool(&stack, -1))
    THROW(BTC_SCRIPT_ERR_EVAL_FALSE);

  /* Verify witness. */
  had_witness = 0;

  if ((flags & BTC_SCRIPT_VERIFY_WITNESS) && btc_script_is_program(output)) {
    had_witness = 1;

    /* Input script must be empty. */
    if (input->length != 0)
      THROW(BTC_SCRIPT_ERR_WITNESS_MALLEATED);

    /* Verify the program in the output script. */
    if ((err = btc_script_verify_program(witness, output, flags,
                                         tx, index, value, cache))) {
      goto done;
    }

    /* Force a cleanstack */
    btc_stack_resize(&stack, 1);
  }

  /* If the script is P2SH, execute the real output script. */
  if ((flags & BTC_SCRIPT_VERIFY_P2SH) && btc_script_is_p2sh(output)) {
    /* P2SH can only have push ops in the scriptSig. */
    if (!btc_script_is_push_only(input))
      THROW(BTC_SCRIPT_ERR_SIG_PUSHONLY);

    /* Reset the stack */
    btc_stack_copy(&stack, &copy);

    /* Stack should not be empty at this point. */
    if (stack.length == 0)
      THROW(BTC_SCRIPT_ERR_EVAL_FALSE);

    /* Grab the real redeem script. */
    redeem = btc_stack_pop(&stack);

    /* Execute the redeem script. */
    if ((err = btc_script_execute(redeem, &stack, flags,
                                  tx, index, value, 0, cache))) {
      goto done;
    }

    /* Verify the the stack values. */
    if (stack.length == 0 || !btc_stack_get_bool(&stack, -1))
      THROW(BTC_SCRIPT_ERR_EVAL_FALSE);

    if ((flags & BTC_SCRIPT_VERIFY_WITNESS) && btc_script_is_program(redeem)) {
      had_witness = 1;

      /* Input script must be exactly one push of the redeem script. */
      if (!btc_opcode_import(&op1, input->data, input->length))
        THROW(BTC_SCRIPT_ERR_WITNESS_MALLEATED_P2SH);

      if (btc_opcode_size(&op1) != input->length)
        THROW(BTC_SCRIPT_ERR_WITNESS_MALLEATED_P2SH);

      btc_opcode_set_push(&op2, redeem->data, redeem->length);

      if (!btc_opcode_equal(&op1, &op2))
        THROW(BTC_SCRIPT_ERR_WITNESS_MALLEATED_P2SH);

      /* Verify the program in the redeem script. */
      if ((err = btc_script_verify_program(witness, redeem, flags,
                                           tx, index, value, cache))) {
        goto done;
      }

      /* Force a cleanstack. */
      btc_stack_resize(&stack, 1);
    }
  }

  /* Ensure there is nothing left on the stack. */
  if (flags & BTC_SCRIPT_VERIFY_CLEANSTACK) {
    CHECK((flags & BTC_SCRIPT_VERIFY_P2SH) != 0);
    if (stack.length != 1)
      THROW(BTC_SCRIPT_ERR_CLEANSTACK);
  }

  /* If we had a witness but no witness program, fail. */
  if (flags & BTC_SCRIPT_VERIFY_WITNESS) {
    CHECK((flags & BTC_SCRIPT_VERIFY_P2SH) != 0);
    if (!had_witness && witness->length > 0)
      THROW(BTC_SCRIPT_ERR_WITNESS_UNEXPECTED);
  }

done:
  btc_stack_clear(&stack);
  btc_stack_clear(&copy);
  if (redeem != NULL)
    btc_script_destroy(redeem);
  return err;
}

#undef THROW

/*
 * Reader
 */

void
btc_reader_init(btc_reader_t *z, const btc_script_t *x) {
  z->data = x->data;
  z->length = x->length;
  z->ip = -1;
}

int
btc_reader_next(btc_opcode_t *z, btc_reader_t *x) {
  int ret = btc_opcode_read(z, &x->data, &x->length);
  x->ip += ret;
  return ret;
}

/*
 * Writer
 */

DEFINE_VECTOR(btc_writer, btc_opcode, SCOPE_EXTERN)

void
btc_writer_push_op(btc_writer_t *z, int value) {
  btc_opcode_t *op = btc_opcode_create();

  op->value = value;

  btc_writer_push(z, op);
}

void
btc_writer_push_data(btc_writer_t *z, const uint8_t *data, size_t length) {
  btc_opcode_t *op = btc_opcode_create();

  btc_opcode_set_push(op, data, length);

  btc_writer_push(z, op);
}

void
btc_writer_compile(btc_script_t *z, const btc_writer_t *x) {
  size_t zn = 0;
  uint8_t *zp;
  size_t i;

  for (i = 0; i < x->length; i++)
    zn += btc_opcode_size(x->items[i]);

  zp = btc_script_resize(z, zn);

  for (i = 0; i < x->length; i++)
    zp = btc_opcode_write(zp, x->items[i]);
}
