/*!
 * script.c - script for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/array.h>
#include <satoshi/buffer.h>
#include <satoshi/consensus.h>
#include <satoshi/encoding.h>
#include <satoshi/crypto/ecc.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/policy.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/vector.h>
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

static void
btc_stack_assign(btc_stack_t *z, const btc_stack_t *x) {
  size_t i;

  btc_stack_reset(z);
  btc_stack_resize(z, x->length);

  for (i = 0; i < x->length; i++)
    z->items[i] = btc_buffer_ref(x->items[i]);
}

btc_buffer_t *
btc_stack_get(const btc_stack_t *stack, int index) {
  if (index < 0)
    index += (int)stack->length;

  CHECK((size_t)index < stack->length);

  return (btc_buffer_t *)stack->items[index];
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

static void
btc_stack_push_rodata(btc_stack_t *stack, const uint8_t *data, size_t length) {
  btc_buffer_t *item = btc_buffer_create();
  btc_buffer_roset(item, data, length);
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
btc_stack_push_bool(btc_stack_t *stack, int value) {
  btc_buffer_t *item = btc_buffer_create();

  if (value)
    btc_buffer_resize(item, 1)[0] = 1;

  btc_stack_push(stack, item);
}

static void
btc_stack_push_robool(btc_stack_t *stack, int value) {
  static const uint8_t one[1] = {1};
  btc_buffer_t *item = btc_buffer_create();

  if (value)
    btc_buffer_roset(item, one, 1);

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
  z->length = x->length;
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

static int
btc_opcode_is_key(const btc_opcode_t *op) {
  if (op->length == 33)
    return op->data[0] == 0x02 || op->data[0] == 0x03;

  if (op->length == 65)
    return op->data[0] == 0x04 || op->data[0] == 0x06 || op->data[0] == 0x07;

  return 0;
}

static int
btc_opcode_key_count(const btc_opcode_t *op) {
  if (op->value == 1) {
    if (op->data[0] < 17 || op->data[0] > BTC_MAX_MULTISIG_PUBKEYS)
      return 0;

    return op->data[0];
  }

  if (op->value < BTC_OP_1 || op->value > BTC_OP_16)
    return 0;

  return btc_smi_decode(op->value);
}

static int
btc_opcode_is_int(const btc_opcode_t *op) {
  uint8_t tmp[9];
  int64_t num;
  size_t len;

  if (op->value > 6)
    return 0;

  if (op->value == 0)
    return 1;

  num = btc_scriptnum_import(op->data, op->length);

  if (num < INT_MIN || num > INT_MAX)
    return 0;

  len = btc_scriptnum_export(tmp, num);

  if (len != op->length)
    return 0;

  return memcmp(tmp, op->data, op->length) == 0;
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

void
btc_opcode_set_num(btc_opcode_t *z, int64_t value, uint8_t *scratch) {
  if (value >= -1 && value <= 16) {
    z->value = btc_smi_encode(value);
    z->data = NULL;
    z->length = 0;
  } else {
    btc_opcode_set_push(z, scratch, btc_scriptnum_export(scratch, value));
  }
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
  if (x->value > BTC_OP_PUSHDATA4) {
    zp = btc_uint8_write(zp, x->value);
    return zp;
  }

  zp = btc_uint8_write(zp, x->value);

  switch (x->value) {
    case BTC_OP_PUSHDATA1:
      zp = btc_uint8_write(zp, x->length);
      break;
    case BTC_OP_PUSHDATA2:
      zp = btc_uint16_write(zp, x->length);
      break;
    case BTC_OP_PUSHDATA4:
      zp = btc_uint32_write(zp, x->length);
      break;
    default:
      CHECK((size_t)x->value == x->length);
      break;
  }

  zp = btc_raw_write(zp, x->data, x->length);

  return zp;
}

int
btc_opcode_read(btc_opcode_t *z, const uint8_t **xp, size_t *xn) {
  uint8_t value;
  size_t length;

  z->value = BTC_OP_INVALIDOPCODE;
  z->data = NULL;
  z->length = 0;

  if (!btc_uint8_read(&value, xp, xn))
    return 0;

  if (value > BTC_OP_PUSHDATA4) {
    z->value = value;
    return 1;
  }

  switch (value) {
    case BTC_OP_PUSHDATA1: {
      uint8_t len8;

      if (!btc_uint8_read(&len8, xp, xn))
        return 0;

      length = len8;

      break;
    }

    case BTC_OP_PUSHDATA2: {
      uint16_t len16;

      if (!btc_uint16_read(&len16, xp, xn))
        return 0;

      length = len16;

      break;
    }

    case BTC_OP_PUSHDATA4: {
      uint32_t len32;

      if (!btc_uint32_read(&len32, xp, xn))
        return 0;

      length = len32;

      break;
    }

    default: {
      length = value;
      break;
    }
  }

  if (*xn < length)
    return 0;

  z->value = value;
  z->data = *xp;
  z->length = length;

  *xp += length;
  *xn -= length;

  return 1;
}

/*
 * Script
 */

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
  uint8_t *zp = btc_script_resize(script, 2 + len);

  zp[0] = len;

  memcpy(zp + 1, pub, len);

  zp[1 + len] = BTC_OP_CHECKSIG;
}

int
btc_script_get_p2pk(uint8_t *pub, size_t *len, const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  if (!btc_reader_next(&op, &reader))
    return 0;

  if (!btc_opcode_is_key(&op))
    return 0;

  if (pub != NULL)
    memcpy(pub, op.data, op.length);

  if (len != NULL)
    *len = op.length;

  if (btc_reader_op(&reader) != BTC_OP_CHECKSIG)
    return 0;

  return reader.length == 0;
}

int
btc_script_is_p2pkh(const btc_script_t *script) {
  return btc_script_get_p2pkh(NULL, script);
}

void
btc_script_set_p2pkh(btc_script_t *script, const uint8_t *hash) {
  uint8_t *zp = btc_script_resize(script, 25);

  zp[0] = BTC_OP_DUP;
  zp[1] = BTC_OP_HASH160;
  zp[2] = 20;

  memcpy(zp + 3, hash, 20);

  zp[23] = BTC_OP_EQUALVERIFY;
  zp[24] = BTC_OP_CHECKSIG;
}

int
btc_script_get_p2pkh(uint8_t *hash, const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  if (btc_reader_op(&reader) != BTC_OP_DUP)
    return 0;

  if (btc_reader_op(&reader) != BTC_OP_HASH160)
    return 0;

  if (!btc_reader_next(&op, &reader))
    return 0;

  if (op.length != 20)
    return 0;

  if (hash != NULL)
    memcpy(hash, op.data, 20);

  if (btc_reader_op(&reader) != BTC_OP_EQUALVERIFY)
    return 0;

  if (btc_reader_op(&reader) != BTC_OP_CHECKSIG)
    return 0;

  return reader.length == 0;
}

int
btc_script_is_multisig(const btc_script_t *script) {
  return btc_script_get_multisig(NULL, NULL, NULL, script);
}

void
btc_script_set_multisig(btc_script_t *script,
                        unsigned int m,
                        const btc_multikey_t *keys,
                        unsigned int n) {
  size_t zn = 3 + (m > 16) + (n > 16);
  unsigned int i;
  uint8_t *zp;

  CHECK(m >= 1 && m <= n);
  CHECK(n >= 1 && n <= BTC_MAX_MULTISIG_PUBKEYS);

  for (i = 0; i < n; i++)
    zn += 1 + keys[i].length;

  zp = btc_script_resize(script, zn);

  if (m > 16) {
    *zp++ = 1;
    *zp++ = m;
  } else {
    *zp++ = btc_smi_encode(m);
  }

  for (i = 0; i < n; i++) {
    *zp++ = keys[i].length;

    memcpy(zp, keys[i].data, keys[i].length);

    zp += keys[i].length;
  }

  if (n > 16) {
    *zp++ = 1;
    *zp++ = n;
  } else {
    *zp++ = btc_smi_encode(n);
  }

  *zp++ = BTC_OP_CHECKMULTISIG;
}

int
btc_script_get_multisig(unsigned int *m,
                        btc_multikey_t *keys,
                        unsigned int *n,
                        const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;
  int mm, nn;
  int i = 0;

  btc_reader_init(&reader, script);

  if (!btc_reader_next(&op, &reader))
    return 0;

  if (!(mm = btc_opcode_key_count(&op)))
    return 0;

  for (;;) {
    if (!btc_reader_next(&op, &reader))
      return 0;

    if (!btc_opcode_is_key(&op))
      break;

    if (i == BTC_MAX_MULTISIG_PUBKEYS)
      return 0;

    if (keys != NULL) {
      keys[i].data = op.data;
      keys[i].length = op.length;
    }

    i += 1;
  }

  if (!(nn = btc_opcode_key_count(&op)))
    return 0;

  if (btc_reader_op(&reader) != BTC_OP_CHECKMULTISIG)
    return 0;

  if (reader.length > 0)
    return 0;

  if (mm > nn)
    return 0;

  if (nn != i)
    return 0;

  if (m != NULL)
    *m = mm;

  if (n != NULL)
    *n = nn;

  return 1;
}

static int
multikey_compare(const void *a, const void *b) {
  const btc_multikey_t *x = (const btc_multikey_t *)a;
  const btc_multikey_t *y = (const btc_multikey_t *)b;
  int xn = x->length;
  int yn = y->length;
  int mn = xn < yn ? xn : yn;
  int cmp = memcmp(x->data, y->data, mn);

  if (cmp != 0)
    return cmp;

  return xn - yn;
}

void
btc_multikey_sort(btc_multikey_t *keys, unsigned int n) {
  qsort(keys, n, sizeof(*keys), multikey_compare);
}

int
btc_script_is_p2sh(const btc_script_t *script) {
  return script->length == 23
      && script->data[0] == BTC_OP_HASH160
      && script->data[1] == 20
      && script->data[22] == BTC_OP_EQUAL;
}

void
btc_script_set_p2sh(btc_script_t *script, const uint8_t *hash) {
  uint8_t *zp = btc_script_resize(script, 23);

  zp[0] = BTC_OP_HASH160;
  zp[1] = 20;

  memcpy(zp + 2, hash, 20);

  zp[22] = BTC_OP_EQUAL;
}

int
btc_script_get_p2sh(uint8_t *hash, const btc_script_t *script) {
  if (!btc_script_is_p2sh(script))
    return 0;

  memcpy(hash, script->data + 2, 20);

  return 1;
}

int
btc_script_is_nulldata(const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  if (btc_reader_op(&reader) != BTC_OP_RETURN)
    return 0;

  while (reader.length > 0) {
    if (!btc_reader_next(&op, &reader))
      return 0;

    if (op.value > BTC_OP_16)
      return 0;
  }

  return 1;
}

void
btc_script_set_nulldata(btc_script_t *script, const uint8_t *data, size_t len) {
  btc_opcode_t op;
  uint8_t *zp;

  btc_opcode_set_push(&op, data, len);

  zp = btc_script_resize(script, 1 + btc_opcode_size(&op));

  zp[0] = BTC_OP_RETURN;

  btc_opcode_write(zp + 1, &op);
}

int
btc_script_get_nulldata(const uint8_t **data,
                        size_t *len,
                        const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  if (btc_reader_op(&reader) != BTC_OP_RETURN)
    return 0;

  if (!btc_reader_next(&op, &reader))
    return 0;

  if (op.value > BTC_OP_PUSHDATA4)
    return 0;

  if (data != NULL)
    *data = op.data;

  if (len != NULL)
    *len = op.length;

  return reader.length == 0;
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
  uint8_t *zp = btc_script_resize(script, 38);

  zp[0] = BTC_OP_RETURN;
  zp[1] = 0x24;
  zp[2] = 0xaa;
  zp[3] = 0x21;
  zp[4] = 0xa9;
  zp[5] = 0xed;

  memcpy(zp + 6, hash, 32);
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

  if (script->data[0] != BTC_OP_0) {
    if (script->data[0] < BTC_OP_1 || script->data[0] > BTC_OP_16)
      return 0;
  }

  if ((size_t)script->data[1] + 2 != script->length)
    return 0;

  return 1;
}

void
btc_script_set_program(btc_script_t *script, const btc_program_t *program) {
  uint8_t *zp = btc_script_resize(script, 2 + program->length);

  zp[0] = btc_smi_encode(program->version);
  zp[1] = program->length;

  memcpy(zp + 2, program->data, program->length);
}

int
btc_script_get_program(btc_program_t *program, const btc_script_t *script) {
  if (!btc_script_is_program(script))
    return 0;

  program->version = btc_smi_decode(script->data[0]);
  program->length = script->data[1];

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
  uint8_t *zp = btc_script_resize(script, 22);

  zp[0] = BTC_OP_0;
  zp[1] = 20;

  memcpy(zp + 2, hash, 20);
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
  uint8_t *zp = btc_script_resize(script, 34);

  zp[0] = BTC_OP_0;
  zp[1] = 32;

  memcpy(zp + 2, hash, 32);
}

int
btc_script_is_unknown(const btc_script_t *script) {
  return !btc_script_is_p2pk(script)
      && !btc_script_is_p2pkh(script)
      && !btc_script_is_p2sh(script)
      && !btc_script_is_p2wpkh(script)
      && !btc_script_is_p2wsh(script)
      && !btc_script_is_multisig(script)
      && !btc_script_is_nulldata(script);
}

int
btc_script_is_standard(const btc_script_t *script) {
  unsigned int m, n;

  if (btc_script_get_multisig(&m, NULL, &n, script)) {
    if (n < 1 || n > 3)
      return 0;

    if (m < 1 || m > n)
      return 0;

    return 1;
  }

  if (btc_script_is_nulldata(script))
    return script->length <= BTC_MAX_OP_RETURN_BYTES;

  return !btc_script_is_unknown(script);
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

  while (reader.length > 0) {
    if (!btc_reader_next(&op, &reader))
      return 0;

    if (op.value > BTC_OP_16)
      return 0;
  }

  return 1;
}

int32_t
btc_script_get_height(const btc_script_t *script) {
  btc_opcode_t op;
  uint8_t tmp[9];
  int64_t num;

  if (!btc_opcode_import(&op, script->data, script->length))
    return -1;

  if (op.value == BTC_OP_0)
    return 0;

  if (op.value >= BTC_OP_1 && op.value <= BTC_OP_16)
    return btc_smi_decode(op.value);

  if (op.value > 6)
    return -1;

  num = btc_scriptnum_import(op.data, op.length);

  if (num < 16)
    return -1;

  if (num > INT32_MAX)
    return -1;

  if (btc_scriptnum_export(tmp, num) != op.length)
    return -1;

  if (memcmp(op.data, tmp, op.length) != 0)
    return -1;

  return num;
}

int
btc_script_get_redeem(btc_script_t *redeem, const btc_script_t *script) {
  btc_opcode_t op, last;
  btc_reader_t reader;

  memset(&op, 0, sizeof(op));

  btc_opcode_init(&last);
  btc_reader_init(&reader, script);

  while (reader.length > 0) {
    if (!btc_reader_next(&op, &reader))
      return 0;

    if (op.value > BTC_OP_16)
      return 0;

    last = op;
  }

  btc_script_roset(redeem, last.data, last.length);

  return 1;
}

int
btc_script_sigops(const btc_script_t *script, int accurate) {
  int last = BTC_OP_INVALIDOPCODE;
  btc_reader_t reader;
  btc_opcode_t op;
  int total = 0;

  btc_reader_init(&reader, script);

  while (reader.length > 0) {
    if (!btc_reader_next(&op, &reader))
      break;

    switch (op.value) {
      case BTC_OP_CHECKSIG:
      case BTC_OP_CHECKSIGVERIFY:
        total += 1;
        break;
      case BTC_OP_CHECKMULTISIG:
      case BTC_OP_CHECKMULTISIGVERIFY:
        if (accurate && last >= BTC_OP_1 && last <= BTC_OP_16)
          total += btc_smi_decode(last);
        else
          total += BTC_MAX_MULTISIG_PUBKEYS;
        break;
    }

    last = op.value;
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
btc_script_equal_push(const btc_script_t *x, const btc_buffer_t *y) {
  /**
   * Ensures `x` is equivalent to a single pushdata of `y`.
   *
   * This function avoids allocations and is used for ensuring
   * that a nested segwit+p2sh input script was not malleated.
   */
  uint8_t raw[5 + BTC_MAX_SCRIPT_PUSH];
  btc_script_t expect;
  btc_opcode_t op;
  size_t len;

  btc_opcode_set_push(&op, y->data, y->length);

  CHECK(btc_opcode_size(&op) <= sizeof(raw));

  len = btc_opcode_export(raw, &op);

  btc_script_roset(&expect, raw, len);

  return btc_script_equal(x, &expect);
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
  uint8_t tmp[64];

  if (!btc_ecdsa_sig_import(tmp, sig->data, sig->length))
    return 0;

  return btc_ecdsa_is_low_s(tmp);
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
  if (key->length == 33)
    return key->data[0] == 0x02 || key->data[0] == 0x03;

  if (key->length == 65)
    return key->data[0] == 0x04;

  return 0;
}

static int
is_compressed_encoding(const btc_buffer_t *key) {
  if (key->length != 33)
    return 0;

  return key->data[0] == 0x02 || key->data[0] == 0x03;
}

static int
validate_signature(const btc_buffer_t *sig, unsigned int flags) {
  /* Allow empty sigs. */
  if (sig->length == 0)
    return BTC_SCRIPT_ERR_OK;

  if (flags & (BTC_SCRIPT_VERIFY_DERSIG
             | BTC_SCRIPT_VERIFY_LOW_S
             | BTC_SCRIPT_VERIFY_STRICTENC)) {
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
  uint8_t tmp[64];

  if (sig->length == 0)
    return 0;

  if (!btc_ecdsa_sig_import_lax(tmp, sig->data, sig->length - 1))
    return 0;

  if (!btc_ecdsa_sig_normalize(tmp, tmp))
    return 0;

  return btc_ecdsa_verify(msg, 32, tmp, key->data, key->length);
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
  int opcount = 0;
  int negate = 0;
  int minimal = 0;

  btc_array_t state;
  btc_stack_t alt;
  btc_reader_t reader;
  btc_reader_t begin;
  btc_script_t subscript;
  btc_opcode_t op;

  if (script->length > BTC_MAX_SCRIPT_SIZE)
    return BTC_SCRIPT_ERR_SCRIPT_SIZE;

  if (flags & BTC_SCRIPT_VERIFY_MINIMALDATA)
    minimal = 1;

  btc_array_init(&state);
  btc_stack_init(&alt);
  btc_script_init(&subscript);
  btc_reader_init(&reader, script);
  btc_reader_init(&begin, script);

  while (reader.length > 0) {
    if (!btc_reader_next(&op, &reader))
      THROW(BTC_SCRIPT_ERR_BAD_OPCODE);

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

      btc_stack_push_rodata(stack, op.data, op.length);

      if (stack->length + alt.length > BTC_MAX_SCRIPT_STACK)
        THROW(BTC_SCRIPT_ERR_STACK_SIZE);

      continue;
    }

    switch (op.value) {
      case BTC_OP_1NEGATE: {
        btc_stack_push_num(stack, -1);
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
        btc_stack_push_num(stack, op.value - (BTC_OP_1 - 1));
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

        btc_array_push(&state, val);

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

        if (!btc_array_pop(&state))
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
        btc_buffer_t *v1, *v2;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -2);
        v2 = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_ref(v1));
        btc_stack_push(stack, btc_buffer_ref(v2));

        break;
      }
      case BTC_OP_3DUP: {
        btc_buffer_t *v1, *v2, *v3;

        if (stack->length < 3)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -3);
        v2 = btc_stack_get(stack, -2);
        v3 = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_ref(v1));
        btc_stack_push(stack, btc_buffer_ref(v2));
        btc_stack_push(stack, btc_buffer_ref(v3));

        break;
      }
      case BTC_OP_2OVER: {
        btc_buffer_t *v1, *v2;

        if (stack->length < 4)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -4);
        v2 = btc_stack_get(stack, -3);

        btc_stack_push(stack, btc_buffer_ref(v1));
        btc_stack_push(stack, btc_buffer_ref(v2));

        break;
      }
      case BTC_OP_2ROT: {
        btc_buffer_t *v1, *v2;

        if (stack->length < 6)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -6);
        v2 = btc_stack_get(stack, -5);

        btc_stack_erase(stack, -6, -4);
        btc_stack_push(stack, v1);
        btc_stack_push(stack, v2);

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
        btc_buffer_t *val;

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (btc_stack_get_bool(stack, -1)) {
          val = btc_stack_get(stack, -1);

          btc_stack_push(stack, btc_buffer_ref(val));
        }

        break;
      }
      case BTC_OP_DEPTH: {
        btc_stack_push_num(stack, stack->length);
        break;
      }
      case BTC_OP_DROP: {
        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        btc_stack_drop(stack);

        break;
      }
      case BTC_OP_DUP: {
        btc_buffer_t *val;

        if (stack->length == 0)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_ref(val));

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
        btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -2);

        btc_stack_push(stack, btc_buffer_ref(val));

        break;
      }
      case BTC_OP_PICK:
      case BTC_OP_ROLL: {
        btc_buffer_t *val;
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
          btc_stack_push(stack, btc_buffer_ref(val));
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
        btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_insert(stack, -2, btc_buffer_ref(val));

        break;
      }
      case BTC_OP_SIZE: {
        const btc_buffer_t *val;

        if (stack->length < 1)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_push_num(stack, val->length);

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

        btc_stack_push_robool(stack, res);

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

        btc_stack_push_robool(stack, val);

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
        begin.data = reader.data;
        begin.length = reader.length;
        break;
      }
      case BTC_OP_CHECKSIG:
      case BTC_OP_CHECKSIGVERIFY: {
        const btc_buffer_t *sig, *key;
        uint8_t hash[32];
        int res, type;

        if (tx == NULL)
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (stack->length < 2)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        sig = btc_stack_get(stack, -2);
        key = btc_stack_get(stack, -1);

        btc_script_set(&subscript, begin.data, begin.length);

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

        btc_stack_push_robool(stack, res);

        if (op.value == BTC_OP_CHECKSIGVERIFY) {
          if (!res)
            THROW(BTC_SCRIPT_ERR_CHECKSIGVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      case BTC_OP_CHECKMULTISIG:
      case BTC_OP_CHECKMULTISIGVERIFY: {
        int i, j, m, n, okey, ikey, isig;
        const btc_buffer_t *sig, *key;
        uint8_t hash[32];
        int res, type;

        if (tx == NULL)
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        i = 1;

        if (stack->length < (size_t)i)
          THROW(BTC_SCRIPT_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_int(&n, stack, -i, minimal, 4))
          THROW(BTC_SCRIPT_ERR_UNKNOWN_ERROR);

        if (n < 0 || n > BTC_MAX_MULTISIG_PUBKEYS)
          THROW(BTC_SCRIPT_ERR_PUBKEY_COUNT);

        opcount += n;

        if (opcount > BTC_MAX_SCRIPT_OPS)
          THROW(BTC_SCRIPT_ERR_OP_COUNT);

        i += 1;
        ikey = i;
        okey = n + 2;
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

        btc_script_set(&subscript, begin.data, begin.length);

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
        btc_stack_push_robool(stack, res);

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

  if (state.length != 0)
    THROW(BTC_SCRIPT_ERR_UNBALANCED_CONDITIONAL);

done:
  btc_array_clear(&state);
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
  CHECK(btc_script_get_program(&program, output));

  btc_stack_init(&stack);
  btc_stack_assign(&stack, witness);

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
      THROW(BTC_SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
    }
  } else {
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
    btc_stack_assign(&copy, &stack);

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
    btc_stack_assign(&stack, &copy);

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
      if (!btc_script_equal_push(input, redeem))
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
}

int
btc_reader_next(btc_opcode_t *z, btc_reader_t *x) {
  return btc_opcode_read(z, &x->data, &x->length);
}

int
btc_reader_op(btc_reader_t *z) {
  btc_opcode_t op;
  btc_reader_next(&op, z);
  return op.value;
}

/*
 * Writer
 */

void
btc_writer_init(btc_writer_t *z) {
  btc_vector_init(z);
}

void
btc_writer_clear(btc_writer_t *z) {
  size_t i;

  for (i = 0; i < z->length; i++)
    btc_opcode_destroy(z->items[i]);

  btc_vector_clear(z);
}

void
btc_writer_push(btc_writer_t *z, btc_opcode_t *x) {
  btc_vector_push(z, x);
}

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
btc_writer_push_num(btc_writer_t *z, int64_t value, uint8_t *scratch) {
  btc_opcode_t *op = btc_opcode_create();

  btc_opcode_set_num(op, value, scratch);

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

/*
 * Disassembler
 */

static const char *
asm_opcode(int value) {
  switch (value) {
#define X(name) case BTC_##name: return #name
    /* push value */
    X(OP_0);
    X(OP_PUSHDATA1);
    X(OP_PUSHDATA2);
    X(OP_PUSHDATA4);
    X(OP_1NEGATE);
    X(OP_RESERVED);
    X(OP_1);
    X(OP_2);
    X(OP_3);
    X(OP_4);
    X(OP_5);
    X(OP_6);
    X(OP_7);
    X(OP_8);
    X(OP_9);
    X(OP_10);
    X(OP_11);
    X(OP_12);
    X(OP_13);
    X(OP_14);
    X(OP_15);
    X(OP_16);

    /* control */
    X(OP_NOP);
    X(OP_VER);
    X(OP_IF);
    X(OP_NOTIF);
    X(OP_VERIF);
    X(OP_VERNOTIF);
    X(OP_ELSE);
    X(OP_ENDIF);
    X(OP_VERIFY);
    X(OP_RETURN);

    /* stack ops */
    X(OP_TOALTSTACK);
    X(OP_FROMALTSTACK);
    X(OP_2DROP);
    X(OP_2DUP);
    X(OP_3DUP);
    X(OP_2OVER);
    X(OP_2ROT);
    X(OP_2SWAP);
    X(OP_IFDUP);
    X(OP_DEPTH);
    X(OP_DROP);
    X(OP_DUP);
    X(OP_NIP);
    X(OP_OVER);
    X(OP_PICK);
    X(OP_ROLL);
    X(OP_ROT);
    X(OP_SWAP);
    X(OP_TUCK);

    /* splice ops */
    X(OP_CAT);
    X(OP_SUBSTR);
    X(OP_LEFT);
    X(OP_RIGHT);
    X(OP_SIZE);

    /* bit logic */
    X(OP_INVERT);
    X(OP_AND);
    X(OP_OR);
    X(OP_XOR);
    X(OP_EQUAL);
    X(OP_EQUALVERIFY);
    X(OP_RESERVED1);
    X(OP_RESERVED2);

    /* numeric */
    X(OP_1ADD);
    X(OP_1SUB);
    X(OP_2MUL);
    X(OP_2DIV);
    X(OP_NEGATE);
    X(OP_ABS);
    X(OP_NOT);
    X(OP_0NOTEQUAL);
    X(OP_ADD);
    X(OP_SUB);
    X(OP_MUL);
    X(OP_DIV);
    X(OP_MOD);
    X(OP_LSHIFT);
    X(OP_RSHIFT);
    X(OP_BOOLAND);
    X(OP_BOOLOR);
    X(OP_NUMEQUAL);
    X(OP_NUMEQUALVERIFY);
    X(OP_NUMNOTEQUAL);
    X(OP_LESSTHAN);
    X(OP_GREATERTHAN);
    X(OP_LESSTHANOREQUAL);
    X(OP_GREATERTHANOREQUAL);
    X(OP_MIN);
    X(OP_MAX);
    X(OP_WITHIN);

    /* crypto */
    X(OP_RIPEMD160);
    X(OP_SHA1);
    X(OP_SHA256);
    X(OP_HASH160);
    X(OP_HASH256);
    X(OP_CODESEPARATOR);
    X(OP_CHECKSIG);
    X(OP_CHECKSIGVERIFY);
    X(OP_CHECKMULTISIG);
    X(OP_CHECKMULTISIGVERIFY);

    /* expansion */
    X(OP_NOP1);
    X(OP_CHECKLOCKTIMEVERIFY);
    X(OP_CHECKSEQUENCEVERIFY);
    X(OP_NOP4);
    X(OP_NOP5);
    X(OP_NOP6);
    X(OP_NOP7);
    X(OP_NOP8);
    X(OP_NOP9);
    X(OP_NOP10);

    X(OP_INVALIDOPCODE);
#undef X
  }
  return NULL;
}

static int
asm_cpy(char *zp, const char *xp) {
  const char *sp = xp;

  while (*xp)
    *zp++ = *xp++;

  *zp = '\0';

  return xp - sp;
}

static int
asm_uint(char *zp, unsigned int x) {
  unsigned int t = x;
  int n = 0;
  int i;

  do {
    n++;
    t /= 10;
  } while (t != 0);

  zp[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    zp[i] = '0' + (int)(x % 10);
    x /= 10;
  }

  return n;
}

static int
asm_int(char *zp, int x) {
  if (x < 0) {
    *zp++ = '-';
    return 1 + asm_uint(zp, -x);
  }

  return asm_uint(zp, x);
}

static int
asm_hex(char *zp, unsigned int x, int n) {
  int i;

  n += 2;

  zp[n] = '\0';

  for (i = n - 1; i >= 2; i--) {
    zp[i] = "0123456789abcdef"[x & 15];
    x >>= 4;
  }

  zp[1] = 'x';
  zp[0] = '0';

  return n;
}

static size_t
btc_script_asmlen(const btc_script_t *script) {
  btc_reader_t reader;
  btc_opcode_t op;
  size_t length = 0;
  char tmp[12];

  btc_reader_init(&reader, script);

  while (reader.length > 0) {
    const char *name;

    if (length > 0)
      length += 1; /* ' ' */

    if (!btc_reader_next(&op, &reader)) {
      length += 7; /* [error] */
      break;
    }

    if (op.value == BTC_OP_0) {
      length += 4; /* OP_0 */
      continue;
    }

    if (btc_opcode_is_int(&op)) {
      int num = btc_scriptnum_import(op.data, op.length);
      length += asm_int(tmp, num);
      continue;
    }

    if (op.value <= BTC_OP_PUSHDATA4) {
      if (op.value < BTC_OP_PUSHDATA1) {
        length += 4; /* 0x00 */
      } else {
        length += 12; /* OP_PUSHDATA* */

        length += 1; /* ' ' */

        if (op.length <= 0xff)
          length += 4; /* 0x00 */
        else if (op.length <= 0xffff)
          length += 6; /* 0x0000 */
        else
          length += 10; /* 0x00000000 */
      }

      length += 1; /* ' ' */
      length += 2; /* 0x */

      length += op.length * 2;

      continue;
    }

    name = asm_opcode(op.value);

    if (name != NULL)
      length += strlen(name); /* OP_* */
    else
      length += 4; /* 0x00 */
  }

  return length;
}

char *
btc_script_asm(const btc_script_t *script) {
  char *str = btc_malloc(btc_script_asmlen(script) + 1);
  btc_reader_t reader;
  btc_opcode_t op;
  char *zp = str;

  btc_reader_init(&reader, script);

  while (reader.length > 0) {
    const char *name;

    if (zp != str)
      *zp++ = ' ';

    if (!btc_reader_next(&op, &reader)) {
      zp += asm_cpy(zp, "[error]");
      break;
    }

    if (op.value == BTC_OP_0) {
      zp += asm_cpy(zp, "OP_0");
      continue;
    }

    if (btc_opcode_is_int(&op)) {
      int num = btc_scriptnum_import(op.data, op.length);
      zp += asm_int(zp, num);
      continue;
    }

    if (op.value <= BTC_OP_PUSHDATA4) {
      if (op.value < BTC_OP_PUSHDATA1) {
        zp += asm_hex(zp, op.value, 2);
      } else {
        zp += asm_cpy(zp, asm_opcode(op.value));

        *zp++ = ' ';

        if (op.length <= 0xff)
          zp += asm_hex(zp, op.length, 2);
        else if (op.length <= 0xffff)
          zp += asm_hex(zp, op.length, 4);
        else
          zp += asm_hex(zp, op.length, 8);
      }

      *zp++ = ' ';
      *zp++ = '0';
      *zp++ = 'x';

      btc_base16_encode(zp, op.data, op.length);

      zp += op.length * 2;

      continue;
    }

    name = asm_opcode(op.value);

    if (name != NULL)
      zp += asm_cpy(zp, name);
    else
      zp += asm_hex(zp, op.value, 2);
  }

  *zp = '\0';

  return str;
}
