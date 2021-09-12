typedef struct btc_buffer_s {
  uint8_t *data;
  size_t alloc;
  size_t length;
} btc_buffer_t;

typedef struct btc_stack_s {
  btc_buffer_t **items;
  size_t length;
} btc_stack_t;

typedef struct btc_state_s {
  uint8_t *items;
  size_t length;
} btc_state_t;

typedef struct btc_opcode_s {
  int value;
  const uint8_t *data;
  size_t length;
} btc_opcode_t;

typedef btc_buffer_t btc_script_t;

typedef struct btc_reader_s {
  const uint8_t *data;
  size_t *length;
  int ip;
} btc_reader_t;

typedef struct btc_writer_s {
  btc_opcode_t **items;
  size_t length;
} btc_writer_t;

typedef struct btc_outpoint_s {
  uint8_t hash[32];
  uint32_t index;
} btc_outpoint_t;

typedef struct btc_input_s {
  btc_outpoint_t prevout;
  btc_script_t script;
  uint32_t sequence;
  btc_stack_t witness;
} btc_input_t;

typedef struct btc_address_s {
  unsigned int type;
  unsigned int version;
  uint8_t hash[40];
  size_t length;
} btc_address_t;

typedef struct btc_output_s {
  int64_t value;
  btc_script_t script;
} btc_output_t;

typedef struct btc_program_s {
  unsigned int version;
  uint8_t hash[40];
  size_t length;
} btc_program_t;

typedef struct btc_inpvec_s {
  btc_input_t **items;
  size_t length;
} btc_inpvec_t;

typedef struct btc_outvec_s {
  btc_output_t **items;
  size_t length;
} btc_outvec_t;

typedef struct btc_tx_s {
  uint32_t version;
  btc_inpvec_t inputs;
  btc_outvec_t outputs;
  uint32_t locktime;
} btc_tx_t;

typedef struct btc_txvec_s {
  btc_tx_t **items;
  size_t length;
} btc_txvec_t;

typedef struct btc_header_s {
  uint32_t version;
  uint8_t prev_block[32];
  uint8_t merkle_root[32];
  uint32_t time;
  uint32_t bits;
  uint32_t nonce;
} btc_header_t;

typedef struct btc_block_s {
  btc_header_t header;
  btc_txvec_t txs;
} btc_block_t;

typedef struct btc_entry_s {
  uint8_t hash[32];
  btc_header_t header;
  uint32_t height;
  uint8_t chainwork[32];
  struct btc_entry_s *prev;
  struct btc_entry_s *next;
} btc_entry_t;

typedef struct btc_coin_s {
  uint32_t version;
  uint32_t height;
  int coinbase;
  int spent;
  btc_output_t output;
} btc_coin_t;

typedef struct btc_undo_s {
  btc_coin_t **items;
  size_t length;
} btc_undo_t;

typedef struct btc_tx_cache_s {
  uint8_t prevouts[32];
  uint8_t sequences[32];
  uint8_t outputs[32];
  int has_prevouts;
  int has_sequences;
  int has_outputs;
} btc_tx_cache_t;

typedef struct btc_verify_error_s {
  const char *msg;
  int score;
} btc_verify_error_t;

/*
 * Encoding
 */

static uint8_t *
btc_uint8_write(uint8_t *zp, uint8_t x) {
  *zp++ = x;
  return zp;
}

static int
btc_uint8_read(uint8_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 1)
    return 0;

  *zp = (*xp)[0];
  *xp += 1;
  *xn -= 1;

  return 1;
}

static void
btc_uint8_update(hash256_t *ctx, uint8_t x) {
  hash256_update(ctx, &x, 1);
}

static uint8_t *
btc_int8_write(uint8_t *zp, int8_t x) {
  btc_uint8_write(zp, (uint8_t)x);
}

static int
btc_int8_read(int8_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint8_read((uint8_t *)zp, xp, xn);
}

static void
btc_int8_update(hash256_t *ctx, int8_t x) {
  btc_uint8_update(ctx, (uint8_t)x);
}

static uint8_t *
btc_uint16_write(uint8_t *zp, uint16_t x) {
  *zp++ = (x >> 0);
  *zp++ = (x >> 8);
  return zp;
}

static int
btc_uint16_read(uint16_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 2)
    return 0;

  *zp = ((uint16_t)(*xp)[0] <<  0)
      | ((uint16_t)(*xp)[1] <<  8);

  *xp += 2;
  *xn -= 2;

  return 1;
}

static void
btc_uint16_update(hash256_t *ctx, uint16_t x) {
  uint8_t tmp[2];
  btc_uint16_write(tmp, x);
  hash256_update(ctx, tmp, 2);
}

static uint8_t *
btc_int16_write(uint8_t *zp, int16_t x) {
  btc_uint16_write(zp, (uint16_t)x);
}

static int
btc_int16_read(int16_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint16_read((uint16_t *)zp, xp, xn);
}

static void
btc_int16_update(hash256_t *ctx, int16_t x) {
  btc_uint16_update(ctx, (uint16_t)x);
}

static uint8_t *
btc_uint32_write(uint8_t *zp, uint32_t x) {
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  return zp;
}

static int
btc_uint32_read(uint32_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 4)
    return 0;

  *zp = ((uint32_t)(*xp)[0] <<  0)
      | ((uint32_t)(*xp)[1] <<  8)
      | ((uint32_t)(*xp)[2] << 16)
      | ((uint32_t)(*xp)[3] << 24);

  *xp += 4;
  *xn -= 4;

  return 1;
}

static void
btc_uint32_update(hash256_t *ctx, uint32_t x) {
  uint8_t tmp[4];
  btc_uint32_write(tmp, x);
  hash256_update(ctx, tmp, 4);
}

static uint8_t *
btc_int32_write(uint8_t *zp, int32_t x) {
  btc_uint32_write(zp, (uint32_t)x);
}

static int
btc_int32_read(int32_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint32_read((uint32_t *)zp, xp, xn);
}

static void
btc_int32_update(hash256_t *ctx, int32_t x) {
  btc_uint32_update(ctx, (uint32_t)x);
}

static uint8_t *
btc_uint64_write(uint8_t *zp, uint64_t x) {
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  *zp++ = (x >> 32);
  *zp++ = (x >> 40);
  *zp++ = (x >> 48);
  *zp++ = (x >> 56);
  return zp;
}

static int
btc_uint64_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 8)
    return 0;

  *zp = ((uint64_t)(*xp)[0] <<  0)
      | ((uint64_t)(*xp)[1] <<  8)
      | ((uint64_t)(*xp)[2] << 16)
      | ((uint64_t)(*xp)[3] << 24)
      | ((uint64_t)(*xp)[4] << 32)
      | ((uint64_t)(*xp)[5] << 40)
      | ((uint64_t)(*xp)[6] << 48)
      | ((uint64_t)(*xp)[7] << 56);

  *xp += 8;
  *xn -= 8;

  return 1;
}

static void
btc_uint64_update(hash256_t *ctx, uint64_t x) {
  uint8_t tmp[8];
  btc_uint64_write(tmp, x);
  hash256_update(ctx, tmp, 8);
}

static uint8_t *
btc_int64_write(uint8_t *zp, int64_t x) {
  btc_uint64_write(zp, (uint64_t)x);
}

static int
btc_int64_read(int64_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint64_read((uint64_t *)zp, xp, xn);
}

static void
btc_int64_update(hash256_t *ctx, int64_t x) {
  btc_uint64_update(ctx, (uint64_t)x);
}

static size_t
btc_varint_size(uint64_t x) {
  if (x < 0xfd)
    return 1;

  if (x <= 0xffff)
    return 3;

  if (x <= 0xffffffff)
    return 5;

  return 9;
}

static uint8_t *
btc_varint_write(uint8_t *zp, uint64_t x) {
  if (x < 0xfd)
    return btc_uint8_write(zp, x);

  if (x <= 0xffff) {
    *zp++ = 0xfd;
    return btc_uint16_write(zp, x);
  }

  if (x <= 0xffffffff) {
    *zp++ = 0xfe;
    return btc_uint32_write(zp, x);
  }

  *zp++ = 0xff;
  return btc_uint64_write(zp, x);
}

static int
btc_varint_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
  uint8_t type;

  if (!btc_uint8_read(&type, xp, xn))
    return 0;

  switch (type) {
    case 0xff: {
      if (!btc_uint64_read(zp, xp, xn))
        return 0;

      if (*zp <= 0xffffffff)
        return 0;

      break;
    }

    case 0xfe: {
      uint32_t z;

      if (!btc_uint32_read(&z, xp, xn))
        return 0;

      if (z <= 0xffff)
        return 0;

      *zp = z;

      break;
    }

    case 0xfd: {
      uint16_t z;

      if (!btc_uint16_read(&z, xp, xn))
        return 0;

      if (z < 0xfd)
        return 0;

      *zp = z;

      break;
    }

    default: {
      *zp = type;
      break;
    }
  }

  return 1;
}

static void
btc_varint_update(hash256_t *ctx, uint64_t x) {
  uint8_t tmp[9];
  uint8_t *end = btc_varint_write(tmp, x);

  hash256_update(ctx, tmp, end - tmp);
}

static size_t
btc_size_size(size_t x) {
  return btc_varint_size(x);
}

static uint8_t *
btc_size_write(uint8_t *zp, size_t x) {
  return btc_varint_write(zp, x);
}

static int
btc_size_read(size_t *zp, const uint8_t **xp, size_t *xn) {
  uint64_t z;

  if (!btc_varint_read(&z, xp, xn))
    return 0;

  if (z > 0xffffffff)
    return 0;

  *zp = z;

  return 1;
}

static void
btc_size_update(hash256_t *ctx, size_t x) {
  return btc_varint_update(ctx, x);
}

static uint8_t *
btc_raw_write(uint8_t *zp, const uint8_t *xp, size_t xn) {
  if (xn > 0)
    memcpy(zp, xp, xn);

  return zp + xn;
}

static int
btc_raw_read(uint8_t *zp, size_t zn,
            const uint8_t **xp, size_t *xn) {
  if (*xn < zn)
    return 0;

  if (zn > 0) {
    memcpy(zp, *xp, zn);
    *xp += zn;
    *xn -= zn;
  }

  return 1;
}

static void
btc_raw_update(hash256_t *ctx, const uint8_t *xp, size_t xn) {
  hash256_update(ctx, xp, xn);
}

/*
 * Buffer
 */

DEFINE_SERIALIZABLE_OBJECT(btc_buffer, SCOPE_EXTERN)

void
btc_buffer_init(btc_buffer_t *z) {
  z->data = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
btc_buffer_clear(btc_buffer_t *z) {
  if (z->alloc > 0)
    free(z->data);

  z->data = NULL;
  z->alloc = 0;
  z->length = 0;
}

uint8_t *
btc_buffer_grow(btc_buffer_t *z, size_t zn) {
  if (zn > z->alloc) {
    uint8_t *zp = (uint8_t *)realloc(z->data, zn);

    CHECK(zp != NULL);

    z->data = zp;
    z->alloc = zn;
  }

  return z->data;
}

uint8_t *
btc_buffer_resize(btc_buffer_t *z, size_t zn) {
  btc_buffer_grow(z, zn);
  z->length = zn;
  return z->data;
}

void
btc_buffer_set(btc_buffer_t *z, const uint8_t *xp, size_t xn) {
  btc_buffer_grow(z, xn);

  if (xn > 0)
    memcpy(z->data, xp, xn);

  z->length = xn;
}

void
btc_buffer_copy(btc_buffer_t *z, const btc_buffer_t *x) {
  btc_buffer_set(z, x->data, x->length);
}

int
btc_buffer_equal(const btc_buffer_t *x, const btc_buffer_t *y) {
  if (x->length != y->length)
    return 0;

  if (x->length > 0) {
    if (memcmp(x->data, y->data, x->length) != 0)
      return 0;
  }

  return 1;
}

size_t
btc_buffer_size(const btc_buffer_t *x) {
  return btc_size_size(x->length) + x->length;
}

uint8_t *
btc_buffer_write(uint8_t *zp, const btc_buffer_t *x) {
  zp = btc_size_write(zp, x->length);
  zp = btc_raw_write(zp, x->data, x->length);
  return zp;
}

int
btc_buffer_read(btc_buffer_t *z, const uint8_t **xp, size_t *xn) {
  size_t zn;

  if (!btc_size_read(&zn, xp, xn))
    return 0;

  if (*xn < zn)
    return 0;

  btc_buffer_grow(z, zn);

  if (!btc_raw_read(z->data, zn, xp, xn))
    return 0;

  z->length = zn;

  return 1;
}

static void
btc_buffer_update(hash256_t *ctx, const btc_buffer_t *x) {
  btc_size_update(ctx, x->length);
  btc_raw_update(ctx, x->data, x->length);
}

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

DEFINE_SERIALIZABLE_VECTOR(btc_stack, btc_buffer, SCOPE_EXTERN)

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

int
btc_stack_push_data(btc_stack_t *stack, const uint8_t *data, size_t length) {
  btc_buffer_t *item = btc_buffer_create();
  btc_buffer_set(item, data, length);
  btc_stack_push(stack, item);
}

int
btc_stack_push_num(btc_stack_t *stack, int64_t num) {
  btc_buffer_t *item = btc_buffer_create();

  btc_buffer_grow(item, 9);

  item->length = btc_scriptnum_export(item->data, num);

  btc_stack_push(stack, item);
}

int
btc_stack_push_int(btc_stack_t *stack, int num) {
  btc_stack_push_num(stack, num);
}

int
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

static void
btc_state_init(btc_state_t *z) {
  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

static void
btc_state_clear(btc_state_t *z) {
  size_t i;

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

static void
btc_opcode_update(hash256_t *ctx, const btc_opcode_t *x) {
  (void)ctx;
  (void)x;
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

static void
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
    if (2 + script->data[1] != script->length)
      return 0;

    memcpy(data, script->data + 2, script->data[1]);

    *len = script->data[1];

    return 1;
  }

  if (script->length < 3)
    return 0;

  if (script->data[1] == BTC_OP_PUSHDATA1) {
    if (3 + script->data[2] != script->length)
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

  if (script->data[1] + 2 != script->length)
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

void
btc_script_is_p2wpkh(const btc_script_t *script) {
  return script->length == 22
      && script->data[0] == BTC_OP_0
      && script->data[1] == 20;
}

void
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

void
btc_script_is_p2wsh(const btc_script_t *script) {
  return script->length == 34
      && script->data[0] == BTC_OP_0
      && script->data[1] == 32;
}

void
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

    if (program.length == 32 && witness->items.length > 0) {
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
    return BTC_ERR_SUCCESS;

  if ((flags & BTC_SCRIPT_VERIFY_DERSIG)
      || (flags & BTC_SCRIPT_VERIFY_LOW_S)
      || (flags & BTC_SCRIPT_VERIFY_STRICTENC)) {
    if (!is_signature_encoding(sig))
      return BTC_ERR_SIG_DER;
  }

  if (flags & BTC_SCRIPT_VERIFY_LOW_S) {
    if (!is_low_der(sig))
      return BTC_ERR_SIG_HIGH_S;
  }

  if (flags & BTC_SCRIPT_VERIFY_STRICTENC) {
    if (!is_hash_type(sig))
      return BTC_ERR_SIG_HASHTYPE;
  }

  return BTC_ERR_SUCCESS;
}

static int
validate_key(const btc_buffer_t *key, unsigned int flags, int version) {
  if (flags & BTC_SCRIPT_VERIFY_STRICTENC) {
    if (!is_key_encoding(key))
      return BTC_ERR_PUBKEYTYPE;
  }

  if (version == 1) {
    if (flags & BTC_SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) {
      if (!is_compressed_encoding(key))
        return BTC_ERR_WITNESS_PUBKEYTYPE;
    }
  }

  return BTC_ERR_SUCCESS;
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
  int err = BTC_ERR_SUCCESS;
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
    return BTC_ERR_SCRIPT_SIZE;

  if (flags & BTC_SCRIPT_VERIFY_MINIMALDATA)
    minimal = 1;

  btc_state_init(&state);
  btc_stack_init(&alt);
  btc_script_init(&subscript);
  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    if (op.length > BTC_MAX_SCRIPT_PUSH)
      THROW(BTC_ERR_PUSH_SIZE);

    if (op.value > BTC_OP_16 && ++opcount > BTC_MAX_SCRIPT_OPS)
      THROW(BTC_ERR_OP_COUNT);

    if (btc_opcode_is_disabled(&op))
      THROW(BTC_ERR_DISABLED_OPCODE);

    if (negate && !btc_opcode_is_branch(&op)) {
      if (stack->length + alt.length > BTC_MAX_SCRIPT_STACK)
        THROW(BTC_ERR_STACK_SIZE);
      continue;
    }

    if (op.value <= BTC_OP_PUSHDATA4) {
      if (minimal && !btc_opcode_is_minimal(&op))
        THROW(BTC_ERR_MINIMALDATA);

      btc_stack_push_data(stack, op.data, op.length); /* no alloc */

      if (stack->length + alt.length > BTC_MAX_SCRIPT_STACK)
        THROW(BTC_ERR_STACK_SIZE);

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
            THROW(BTC_ERR_DISCOURAGE_UPGRADABLE_NOPS);
          break;
        }

        if (tx == NULL)
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (stack->length == 0)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&locktime, stack, -1, minimal, 5))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (locktime < 0)
          THROW(BTC_ERR_NEGATIVE_LOCKTIME);

        if (!btc_tx_verify_locktime(tx, index, locktime))
          THROW(BTC_ERR_UNSATISFIED_LOCKTIME);

        break;
      }
      case BTC_OP_CHECKSEQUENCEVERIFY: {
        int64_t locktime;

        /* OP_CHECKSEQUENCEVERIFY = OP_NOP3 */
        if (!(flags & BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
          if (flags & BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            THROW(BTC_ERR_DISCOURAGE_UPGRADABLE_NOPS);
          break;
        }

        if (tx == NULL)
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (stack->length == 0)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&locktime, stack, -1, minimal, 5))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (locktime < 0)
          THROW(BTC_ERR_NEGATIVE_LOCKTIME);

        if (!btc_tx_verify_sequence(tx, index, locktime))
          THROW(BTC_ERR_UNSATISFIED_LOCKTIME);

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
          THROW(BTC_ERR_DISCOURAGE_UPGRADABLE_NOPS);
        break;
      }
      case BTC_OP_IF:
      case BTC_OP_NOTIF: {
        int val = 0;

        if (!negate) {
          if (stack->length < 1)
            THROW(BTC_ERR_UNBALANCED_CONDITIONAL);

          if (version == 1 && (flags & BTC_SCRIPT_VERIFY_MINIMALIF)) {
            const btc_buffer_t *item = btc_stack_get(stack, -1);

            if (item->length > 1)
              THROW(BTC_ERR_MINIMALIF);

            if (item->length == 1 && item->data[0] != 1)
              THROW(BTC_ERR_MINIMALIF);
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
          THROW(BTC_ERR_UNBALANCED_CONDITIONAL);

        state.items[state.length - 1] = !state.items[state.length - 1];

        if (!state.items[state.length - 1])
          negate += 1;
        else
          negate -= 1;

        break;
      }
      case BTC_OP_ENDIF: {
        if (state.length == 0)
          THROW(BTC_ERR_UNBALANCED_CONDITIONAL);

        if (!btc_state_pop(&state))
          negate -= 1;

        break;
      }
      case BTC_OP_VERIFY: {
        if (stack->length == 0)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_bool(stack, -1))
          THROW(BTC_ERR_VERIFY);

        btc_stack_drop(stack);

        break;
      }
      case BTC_OP_RETURN: {
        THROW(BTC_ERR_OP_RETURN);
      }
      case BTC_OP_TOALTSTACK: {
        if (stack->length == 0)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        btc_stack_push(&alt, btc_stack_pop(stack));

        break;
      }
      case BTC_OP_FROMALTSTACK: {
        if (alt.length == 0)
          THROW(BTC_ERR_INVALID_ALTSTACK_OPERATION);

        btc_stack_push(stack, btc_stack_pop(&alt));

        break;
      }
      case BTC_OP_2DROP: {
        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        btc_stack_drop(stack);
        btc_stack_drop(stack);

        break;
      }
      case BTC_OP_2DUP: {
        const btc_buffer_t *v1, *v2;

        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -2);
        v2 = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_clone(v1)); /* no alloc */
        btc_stack_push(stack, btc_buffer_clone(v2)); /* no alloc */

        break;
      }
      case BTC_OP_3DUP: {
        const btc_buffer_t *v1, *v2, *v3;

        if (stack->length < 3)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -4);
        v2 = btc_stack_get(stack, -3);

        btc_stack_push(stack, btc_buffer_clone(v1)); /* no alloc */
        btc_stack_push(stack, btc_buffer_clone(v2)); /* no alloc */

        break;
      }
      case BTC_OP_2ROT: {
        const btc_buffer_t *v1, *v2;

        if (stack->length < 6)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -6);
        v2 = btc_stack_get(stack, -5);

        btc_stack_erase(stack, -6, -4);
        btc_stack_push(stack, v1);
        btc_stack_push(stack, v2);

        break;
      }
      case BTC_OP_2SWAP: {
        if (stack->length < 4)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        btc_stack_swap(stack, -4, -2);
        btc_stack_swap(stack, -3, -1);

        break;
      }
      case BTC_OP_IFDUP: {
        const btc_buffer_t *val;

        if (stack->length == 0)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        btc_stack_drop(stack);

        break;
      }
      case BTC_OP_DUP: {
        const btc_buffer_t *val;

        if (stack->length == 0)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_push(stack, btc_buffer_clone(val)); /* no alloc */

        break;
      }
      case BTC_OP_NIP: {
        const btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_remove(stack, -2);

        btc_buffer_destroy(val);

        break;
      }
      case BTC_OP_OVER: {
        const btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -2);

        btc_stack_push(stack, btc_buffer_clone(val)); /* no alloc */

        break;
      }
      case BTC_OP_PICK:
      case BTC_OP_ROLL: {
        const btc_buffer_t *val;
        int num;

        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_int(&num, stack, -1, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        btc_stack_drop(stack);

        if (num < 0 || (size_t)num >= stack->length)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -num - 1);

        if (op.value == BTC_OP_ROLL) {
          btc_stack_remove(stack, -num - 1);
          btc_stack_push(stack, val);
        } else {
          btc_stack_push(stack, btc_buffer_clone(val)); /* no alloc */
        }

        break;
      }
      case BTC_OP_ROT: {
        if (stack->length < 3)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        btc_stack_swap(stack, -3, -2);
        btc_stack_swap(stack, -2, -1);

        break;
      }
      case BTC_OP_SWAP: {
        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        btc_stack_swap(stack, -2, -1);

        break;
      }
      case BTC_OP_TUCK: {
        const btc_buffer_t *val;

        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_insert(stack, -2, btc_buffer_clone(val)); /* no alloc */

        break;
      }
      case BTC_OP_SIZE: {
        const btc_buffer_t *val;

        if (stack->length < 1)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        val = btc_stack_get(stack, -1);

        btc_stack_push_int(stack, val->length);

        break;
      }
      case BTC_OP_EQUAL:
      case BTC_OP_EQUALVERIFY: {
        const btc_buffer_t *v1, *v2;
        int res;

        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        v1 = btc_stack_get(stack, -2);
        v2 = btc_stack_get(stack, -1);

        res = btc_buffer_equal(v1, v2);

        btc_stack_drop(stack);
        btc_stack_drop(stack);

        btc_stack_push_bool(stack, res);

        if (op.value == BTC_OP_EQUALVERIFY) {
          if (!res)
            THROW(BTC_ERR_EQUALVERIFY);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&num, stack, -1, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&n1, stack, -2, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (!btc_stack_get_num(&n2, stack, -1, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

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
            THROW(BTC_ERR_NUMEQUALVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      case BTC_OP_WITHIN: {
        int64_t n1, n2, n3;
        int val;

        if (stack->length < 3)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_num(&n1, stack, -3, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (!btc_stack_get_num(&n2, stack, -2, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (!btc_stack_get_num(&n3, stack, -1, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (stack->length < 2)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
          if (sig.length != 0)
            THROW(BTC_ERR_NULLFAIL);
        }

        btc_stack_drop(stack);
        btc_stack_drop(stack);

        btc_stack_push_bool(stack, res);

        if (op.value == BTC_OP_CHECKSIGVERIFY) {
          if (!res)
            THROW(BTC_ERR_CHECKSIGVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      case BTC_OP_CHECKMULTISIG:
      case BTC_OP_CHECKMULTISIGVERIFY: {
        int i, j, n, okey, ikey, isig, res;
        const btc_buffer_t *sig, *key;
        unsigned int type;
        uint8_t hash[32];

        if (tx == NULL)
          THROW(BTC_ERR_UNKNOWN_ERROR);

        i = 1;

        if (stack->length < (size_t)i)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_int(&n, stack, -i, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        okey = n + 2;

        if (n < 0 || n > BTC_MAX_MULTISIG_PUBKEYS)
          THROW(BTC_ERR_PUBKEY_COUNT);

        opcount += n;

        if (opcount > BTC_MAX_SCRIPT_OPS)
          THROW(BTC_ERR_OP_COUNT);

        i += 1;
        ikey = i;
        i += n;

        if (stack->length < i)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (!btc_stack_get_int(&m, stack, -i, minimal, 4))
          THROW(BTC_ERR_UNKNOWN_ERROR);

        if (m < 0 || m > n)
          THROW(BTC_ERR_SIG_COUNT);

        i += 1;
        isig = i;
        i += m;

        if (stack->length < i)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

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
              THROW(BTC_ERR_NULLFAIL);
          }

          if (okey > 0)
            okey -= 1;

          btc_stack_drop(stack);

          i -= 1;
        }

        if (stack->length < 1)
          THROW(BTC_ERR_INVALID_STACK_OPERATION);

        if (flags & BTC_SCRIPT_VERIFY_NULLDUMMY) {
          if (btc_stack_get(stack, -1)->length != 0)
            THROW(BTC_ERR_SIG_NULLDUMMY);
        }

        btc_stack_drop(stack);
        btc_stack_push_bool(stack, res);

        if (op.value == BTC_OP_CHECKMULTISIGVERIFY) {
          if (!res)
            THROW(BTC_ERR_CHECKMULTISIGVERIFY);

          btc_stack_drop(stack);
        }

        break;
      }
      default: {
        THROW(BTC_ERR_BAD_OPCODE);
      }
    }

    if (stack->length + alt.length > BTC_MAX_SCRIPT_STACK)
      THROW(BTC_ERR_STACK_SIZE);
  }

  if (op.value == -1)
    THROW(BTC_ERR_BAD_OPCODE);

  if (state.length != 0)
    THROW(BTC_ERR_UNBALANCED_CONDITIONAL);

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
  int err = BTC_ERR_SUCCESS;
  btc_script_t *redeem = NULL;
  btc_program_t program;
  btc_stack_t stack;
  uint8_t hash[32];
  size_t i;

  CHECK((flags & BTC_SCRIPT_VERIFY_WITNESS) != 0);

  btc_stack_init(&stack);

  if (!btc_script_get_program(&program, output))
    THROW(BTC_ERR_WITNESS_PROGRAM_MISMATCH);

  btc_stack_copy(&stack, witness);

  if (program.version == 0) {
    if (program.length == 32) {
      if (stack.length == 0)
        THROW(BTC_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);

      redeem = btc_stack_pop(&stack);

      btc_sha256(hash, redeem->data, redeem->length);

      if (memcmp(hash, program.data, 32) != 0)
        THROW(BTC_ERR_WITNESS_PROGRAM_MISMATCH);
    } else if (program.length == 20) {
      if (stack.length != 2)
        THROW(BTC_ERR_WITNESS_PROGRAM_MISMATCH);

      redeem = btc_script_create();

      btc_script_set_p2pkh(redeem, program.data);
    } else {
      /* Failure on version=0 (bad program data length). */
      THROW(BTC_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
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
      THROW(BTC_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    goto done;
  }

  /* Witnesses still have push limits. */
  for (i = 0; i < stack.length; i++) {
    if (stack.items[i]->length > BTC_MAX_SCRIPT_PUSH)
      THROW(BTC_ERR_PUSH_SIZE);
  }

  /* Verify the redeem script. */
  if ((err = btc_script_execute(redeem, &stack, flags,
                                tx, index, value, 1, cache))) {
    goto done;
  }

  /* Verify the stack values. */
  if (stack.length != 1 || !btc_stack_get_bool(&stack, -1))
    THROW(BTC_ERR_EVAL_FALSE);

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
  int err = BTC_ERR_SUCCESS;
  btc_script_t *redeem = NULL;
  btc_stack_t stack, copy;
  btc_opcode_t op1, op2;
  int had_witness;

  /* Setup a stack. */
  btc_stack_init(&stack);
  btc_stack_init(&copy);
  btc_script_init(&redeem);

  if (flags & BTC_SCRIPT_VERIFY_SIGPUSHONLY) {
    if (!btc_script_is_push_only(input))
      THROW(BTC_ERR_SIG_PUSHONLY);
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
    THROW(BTC_ERR_EVAL_FALSE);

  /* Verify witness. */
  had_witness = 0;

  if ((flags & BTC_SCRIPT_VERIFY_WITNESS) && btc_script_is_program(output)) {
    had_witness = 1;

    /* Input script must be empty. */
    if (input->length != 0)
      THROW(BTC_ERR_WITNESS_MALLEATED);

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
      THROW(BTC_ERR_SIG_PUSHONLY);

    /* Reset the stack */
    btc_stack_copy(&stack, &copy);

    /* Stack should not be empty at this point. */
    if (stack.length == 0)
      THROW(BTC_ERR_EVAL_FALSE);

    /* Grab the real redeem script. */
    redeem = btc_stack_pop(&stack);

    /* Execute the redeem script. */
    if ((err = btc_script_execute(redeem, &stack, flags,
                                  tx, index, value, 0, cache))) {
      goto done;
    }

    /* Verify the the stack values. */
    if (stack.length == 0 || !btc_stack_get_bool(&stack, -1))
      THROW(BTC_ERR_EVAL_FALSE);

    if ((flags & BTC_SCRIPT_VERIFY_WITNESS) && btc_script_is_program(redeem)) {
      had_witness = 1;

      /* Input script must be exactly one push of the redeem script. */
      if (!btc_opcode_import(&op1, input->data, input->length))
        THROW(BTC_ERR_WITNESS_MALLEATED_P2SH);

      if (btc_opcode_size(&op1) != input->length)
        THROW(BTC_ERR_WITNESS_MALLEATED_P2SH);

      btc_opcode_set_push(&op2, redeem->data, redeem->length);

      if (!btc_opcode_equal(&op1, &op2))
        THROW(BTC_ERR_WITNESS_MALLEATED_P2SH);

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
      THROW(BTC_ERR_CLEANSTACK);
  }

  /* If we had a witness but no witness program, fail. */
  if (flags & BTC_SCRIPT_VERIFY_WITNESS) {
    CHECK((flags & BTC_SCRIPT_VERIFY_P2SH) != 0);
    if (!had_witness && witness->items.length > 0)
      THROW(BTC_ERR_WITNESS_UNEXPECTED);
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
btc_reader_init(btc_reader_t *z, const btc_script *x) {
  z->data = x->data;
  z->length = x->length;
  z->ip = -1;
}

int
btc_reader_next(btc_opcode *z, btc_reader_t *x) {
  int ret = btc_opcode_read(z, &x->data, &x->length);
  z->ip += ret;
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

/*
 * Outpoint
 */

DEFINE_SERIALIZABLE_OBJECT(btc_outpoint, SCOPE_EXTERN)

void
btc_outpoint_init(btc_outpoint_t *z) {
  memset(z->hash, 0, 32);
  z->index = (uint32_t)-1;
}

void
btc_outpoint_clear(btc_outpoint_t *z) {
  (void)z;
}

void
btc_outpoint_copy(btc_outpoint_t *z, const btc_outpoint_t *x) {
  memcpy(z->hash, x->hash, 32);
  z->index = x->index;
}

uint32_t
btc_outpoint_hash(const btc_outpoint_t *x) {
  uint8_t tmp[36];
  btc_outpoint_write(tmp, x);
  return murmur3_sum(tmp, 36, 0xfba4c795);
}

int
btc_outpoint_equal(const btc_outpoint_t *x, const btc_outpoint_t *y) {
  if (x->index != y->index)
    return 0;

  if (memcmp(x->hash, y->hash, 32) != 0)
    return 0;

  return 1;
}

int
btc_outpoint_is_null(const btc_tx_t *x) {
  static const btc_outpoint_t zero = {{0}, 0xffffffff};
  return btc_outpoint_equal(x, &zero);
}

size_t
btc_outpoint_size(const btc_outpoint_t *x) {
  (void)x;
  return 32 + 4;
}

uint8_t *
btc_outpoint_write(uint8_t *zp, const btc_outpoint_t *x) {
  zp = btc_raw_write(zp, x->hash, 32);
  zp = btc_uint32_write(zp, x->index);
  return zp;
}

int
btc_outpoint_read(btc_outpoint_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_raw_read(z->hash, 32, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->index, xp, xn))
    return 0;

  return 1;
}

static void
btc_outpoint_update(hash256_t *ctx, const btc_outpoint_t *x) {
  btc_raw_update(ctx, x->hash, 32);
  btc_uint32_update(ctx, x->index);
}

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
  btc_script_clear(&z->prevout);
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

static void
btc_input_update(hash256_t *ctx, const btc_input_t *x) {
  btc_outpoint_update(ctx, &x->prevout);
  btc_script_update(ctx, &x->script);
  btc_uint32_update(ctx, x->sequence);
}

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

/*
 * Output
 */

DEFINE_SERIALIZABLE_OBJECT(btc_output, SCOPE_EXTERN)

void
btc_output_init(btc_output_t *z) {
  z->value = 0;
  btc_script_init(&z->script);
}

void
btc_output_clear(btc_output_t *z) {
  btc_script_clear(&z->script);
}

void
btc_output_copy(btc_output_t *z, const btc_output_t *x) {
  btc_script_copy(&z->script, &x->script);
}

size_t
btc_output_size(const btc_output_t *x) {
  size_t size = 0;

  size += 8;
  size += btc_script_size(&x->script);

  return size;
}

uint8_t *
btc_output_write(uint8_t *zp, const btc_output_t *x) {
  zp = btc_int64_write(zp, x->value);
  zp = btc_script_write(zp, &x->script);
  return zp;
}

int
btc_output_read(btc_output_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_int64_read(&z->value, xp, xn))
    return 0;

  if (!btc_script_read(&z->script, xp, xn))
    return 0;

  return 1;
}

static void
btc_output_update(hash256_t *ctx, const btc_output_t *x) {
  btc_int64_update(ctx, x->value);
  btc_script_update(ctx, &x->script);
}

int64_t
btc_output_dust_threshold(const btc_output_t *x, int64_t rate) {
  int scale = BTC_WITNESS_SCALE_FACTOR;
  size_t size;

  if (btc_script_is_unspendable(&x->script))
    return 0;

  size = btc_output_size(x);

  if (btc_script_is_program(&x->script)) {
    /* 75% segwit discount applied to script size. */
    size += 32 + 4 + 1 + (107 / scale) + 4;
  } else {
    size += 32 + 4 + 1 + 107 + 4;
  }

  return 3 * btc_get_min_fee(size, rate);
}

int64_t
btc_output_is_dust(const btc_output_t *x, int64_t rate) {
  return x->value < btc_output_dust_threshold(x, rate);
}

/*
 * Input Vector
 */

DEFINE_SERIALIZABLE_VECTOR(btc_inpvec, btc_input, SCOPE_EXTERN)

/*
 * Output Vector
 */

DEFINE_SERIALIZABLE_VECTOR(btc_outvec, btc_output, SCOPE_EXTERN)

/*
 * Transaction
 */

DEFINE_SERIALIZABLE_OBJECT(btc_tx, SCOPE_EXTERN)

void
btc_tx_init(btc_tx_t *tx) {
  tx->version = 1;
  btc_inpvec_init(&tx->inputs);
  btc_outvec_init(&tx->outputs);
  tx->locktime = 0;
}

void
btc_tx_clear(btc_tx_t *tx) {
  btc_inpvec_clear(&tx->inputs);
  btc_outvec_clear(&tx->outputs);
}

void
btc_tx_copy(btc_tx_t *z, const btc_tx_t *x) {
  z->version = x->version;
  btc_inpvec_copy(&z->inputs, &x->inputs);
  btc_outvec_copy(&z->outputs, &x->outputs);
  z->locktime = x->locktime;
}

int
btc_tx_is_coinbase(const btc_tx_t *tx) {
  if (tx->inputs.length != 1)
    return 0;

  return btc_outpoint_is_null(&tx->inputs.items[0]->prevout);
}

int
btc_tx_has_witness(const btc_tx_t *tx) {
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    if (tx->inputs.items[i]->witness.length > 0)
      return 1;
  }

  return 0;
}

static void
btc_tx_digest(uint8_t *hash, const btc_tx_t *tx, int witness) {
  hash256_t hash;
  size_t i;

  if (witness)
    witness = btc_tx_has_witness(tx);

  hash256_init(&hash);

  btc_uint32_update(&hash, tx->version);

  if (witness) {
    btc_uint8_update(&hash, 0);
    btc_uint8_update(&hash, 1);
  }

  btc_inpvec_update(&hash, &tx->inputs);
  btc_outvec_update(&hash, &tx->outputs);
  btc_uint32_update(&hash, tx->locktime);

  if (witness) {
    for (i = 0; i < tx->inputs.length; i++)
      btc_stack_update(&hash, &tx->inputs.items[i]->witness);
  }

  hash256_final(&hash, hash);
}

void
btc_tx_txid(uint8_t *hash, const btc_tx_t *tx) {
  btc_tx_digest(hash, tx, 0);
}

void
btc_tx_wtxid(uint8_t *hash, const btc_tx_t *tx) {
  btc_tx_digest(hash, tx, 1);
}

static void
btc_tx_sighash_v0(uint8_t *hash,
                  const btc_tx_t *tx,
                  size_t index,
                  const btc_script_t *prev_,
                  unsigned int type) {
  const btc_input_t *input;
  const btc_output_t *output;
  btc_script_t prev;
  hash256_t ctx;
  size_t i;

  if ((type & 0x1f) == BTC_SIGHASH_SINGLE) {
    /* Bitcoind used to return 1 as an error code:
       it ended up being treated like a hash. */
    if (index >= tx->outputs.length) {
      memset(hash, 0, 32);
      hash[0] = 0x01;
      return;
    }
  }

  /* Remove all code separators. */
  btc_script_init(&prev);
  btc_script_remove_separators(&prev, prev_);

  /* Start hashing. */
  hash256_init(&ctx);

  btc_uint32_update(&ctx, tx->version);

  /* Serialize inputs. */
  if (type & BTC_SIGHASH_ANYONECANPAY) {
    /* Serialize only the current
       input if ANYONECANPAY. */
    input = tx->inputs.items[index];

    /* Count. */
    btc_size_update(&ctx, 1);

    /* Outpoint. */
    btc_outpoint_update(&ctx, &input->prevout);

    /* Replace script with previous
       output script if current index. */
    btc_script_update(&ctx, &prev);
    btc_uint32_update(&ctx, input->sequence);
  } else {
    btc_size_update(&ctx, tx->inputs.length);

    for (i = 0; i < tx->inputs.length; i++) {
      input = tx->inputs.items[i];

      /* Outpoint. */
      btc_outpoint_update(&ctx, &input->prevout);

      /* Replace script with previous
         output script if current index. */
      if (i == index) {
        btc_script_update(&ctx, &prev);
        btc_uint32_update(&ctx, input->sequence);
        continue;
      }

      /* Script is null. */
      btc_size_update(&ctx, 0);

      /* Sequences are 0 if NONE or SINGLE. */
      switch (type & 0x1f) {
        case BTC_SIGHASH_NONE:
        case BTC_SIGHASH_SINGLE:
          btc_uint32_update(&ctx, 0);
          break;
        default:
          btc_uint32_update(&ctx, input->sequence);
          break;
      }
    }
  }

  btc_script_clear(&prev);

  /* Serialize outputs. */
  switch (type & 0x1f) {
    case BTC_SIGHASH_NONE: {
      /* No outputs if NONE. */
      btc_size_update(&ctx, 0);
      break;
    }
    case BTC_SIGHASH_SINGLE: {
      output = tx->outputs.items[index];

      /* Drop all outputs after the
         current input index if SINGLE. */
      btc_size_update(&ctx, index + 1);

      for (i = 0; i < index; i++) {
        /* Null all outputs not at
           current input index. */
        btc_int64_update(&ctx, -1);
        btc_size_update(&ctx, 0);
      }

      /* Regular serialization
         at current input index. */
      btc_output_update(&ctx, output);

      break;
    }
    default: {
      /* Regular output serialization if ALL. */
      btc_size_update(&ctx, tx->outputs.length);

      for (i = 0; i < tx->outputs.length; i++) {
        output = tx->outputs.items[i];
        btc_output_update(&ctx, output);
      }

      break;
    }
  }

  btc_uint32_update(&ctx, tx->locktime);

  /* Append the hash type. */
  btc_uint32_update(&ctx, type);

  hash256_final(&ctx, hash);
}

static void
btc_tx_sighash_v1(uint8_t *hash,
                  const btc_tx_t *tx,
                  size_t index,
                  const btc_script_t *prev,
                  int64_t value,
                  unsigned int type,
                  btc_tx_cache_t *cache) {
  const btc_input_t *input = tx->inputs.items[index];
  uint8_t prevouts[32];
  uint8_t sequences[32];
  uint8_t outputs[32];
  hash256_t ctx;
  size_t i;

  memset(prevouts, 0, 32);
  memset(sequences, 0, 32);
  memset(outputs, 0, 32);

  if (!(type & BTC_SIGHASH_ANYONECANPAY)) {
    if (cache != NULL && cache->has_prevouts) {
      memcpy(prevouts, cache->prevouts, 32);
    } else {
      hash256_init(&ctx);

      for (i = 0; i < tx->inputs.length; i++)
        btc_outpoint_update(&ctx, &tx->inputs.items[i]->prevout);

      hash256_final(&ctx, prevouts);

      if (cache != NULL) {
        memcpy(cache->prevouts, prevouts, 32);
        cache->has_prevouts = 1;
      }
    }
  }

  if (!(type & BTC_SIGHASH_ANYONECANPAY)
      && (type & 0x1f) != BTC_SIGHASH_SINGLE
      && (type & 0x1f) != BTC_SIGHASH_NONE) {
    if (cache != NULL && cache->has_sequences) {
      memcpy(sequences, cache->sequences, 32);
    } else {
      hash256_init(&ctx);

      for (i = 0; i < tx->inputs.length; i++)
        btc_uint32_update(&ctx, tx->inputs.items[i]->sequence);

      hash256_final(&ctx, sequences);

      if (cache != NULL) {
        memcpy(cache->sequences, sequences, 32);
        cache->has_sequences = 1;
      }
    }
  }

  if ((type & 0x1f) != BTC_SIGHASH_SINGLE
      && (type & 0x1f) != BTC_SIGHASH_NONE) {
    if (cache != NULL && cache->has_outputs) {
      memcpy(outputs, cache->outputs, 32);
    } else {
      hash256_init(&ctx);

      for (i = 0; i < tx->outputs.length; i++)
        btc_output_update(&ctx, tx->outputs.items[i]);

      hash256_final(&ctx, outputs);

      if (cache != NULL) {
        memcpy(cache->outputs, outputs, 32);
        cache->has_outputs = 1;
      }
    }
  } else if ((type & 0x1f) == BTC_SIGHASH_SINGLE) {
    if (index < tx->outputs.length) {
      hash256_init(&ctx);
      btc_output_update(&ctx, tx->outputs.items[index]);
      hash256_final(&ctx, outputs);
    }
  }

  hash256_init(&ctx);

  btc_uint32_update(&ctx, tx->version);
  btc_raw_update(&ctx, prevouts, 32);
  btc_raw_update(&ctx, sequences, 32);
  btc_outpoint_update(&ctx, &input->prevout);
  btc_script_update(&ctx, prev);
  btc_int64_update(&ctx, value);
  btc_uint32_update(&ctx, input->sequence);
  btc_raw_update(&ctx, outputs, 32);
  btc_uint32_update(&ctx, tx->locktime);
  btc_uint32_update(&ctx, type);

  hash256_final(&ctx, hash);
}

void
btc_tx_sighash(uint8_t *hash,
               const btc_tx_t *tx,
               size_t index,
               const btc_script_t *prev,
               int64_t value,
               unsigned int type,
               int version,
               btc_tx_cache_t *cache) {
  /* Traditional sighashing. */
  if (version == 0) {
    btc_tx_sighash_v0(hash, tx, index, prev, type);
    return;
  }

  /* Segwit sighashing. */
  if (version == 1) {
    btc_tx_sighash_v1(hash, tx, index, prev, value, type, cache);
    return;
  }

  btc_abort(); /* LCOV_EXCL_LINE */
}

int
btc_tx_verify(const btc_tx_t *tx, btc_view_t *view, uint32_t flags) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  btc_tx_cache_t cache;
  size_t i;

  memset(&cache, 0, sizeof(cache));

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      return 0;

    if (!btc_tx_verify_input(tx, i, &coin->output, flags, &cache))
      return 0;
  }

  return 1;
}

int
btc_tx_verify_input(const btc_tx_t *tx,
                    size_t index,
                    const btc_output_t *coin,
                    uint32_t flags,
                    btc_tx_cache_t *cache) {
  const btc_input_t *input = tx->inputs.items[index];

  int ret = btc_script_verify(&input->script,
                              &input->witness,
                              &coin->script,
                              tx,
                              index,
                              coin->value,
                              flags,
                              cache);

  return ret == BTC_ERR_SUCCESS;
}

int
btc_tx_sign_input(btc_tx_t *tx,
                  uint32_t index,
                  const btc_output_t *coin,
                  const uint8_t *priv,
                  unsigned int type,
                  btc_tx_cache_t *cache) {
  const btc_script_t *script = &coin->script;
  btc_input_t *input = tx->inputs.items[index];
  int64_t value = coin->value;
  btc_writer_t writer;
  btc_script_t redeem;
  btc_script_t program;
  uint8_t pub65[65];
  uint8_t pub33[33];
  uint8_t hash65[20];
  uint8_t hash33[20];
  uint8_t msg[32];
  uint8_t hash[20];
  uint8_t pub[65];
  uint8_t der[73];
  size_t der_len;
  size_t len;

  if (!btc_ecdsa_pubkey_create(pub65, priv, 0))
    return 0;

  if (!btc_ecdsa_pubkey_convert(pub33, pub65, 65, 1))
    return 0;

  if (btc_script_get_p2pk(pub, &len, script)) {
    if ((len == 33 && memcmp(pub, pub33, 33) == 0)
        || (len == 65 && memcmp(pub, pub65, 65) == 0)) {
      btc_tx_sighash(msg, tx, index, script,
                     value, type, 0, cache);

      if (!btc_ecdsa_sign(der, &der_len, msg, priv))
        return 0;

      btc_writer_init(&writer);
      btc_writer_push_data(&writer, der, der_len);
      btc_writer_compile(&input->script, &writer);
      btc_writer_clear(&writer);

      return 1;
    }

    return 0;
  }

  btc_ripemd160(hash65, pub65, 65);
  btc_ripemd160(hash33, pub33, 33);

  if (btc_script_get_p2pkh(hash, script)) {
    if (memcmp(hash, hash33, 20) == 0 || memcmp(hash, hash65, 20) == 0) {
      btc_tx_sighash(msg, tx, index, script,
                     value, type, 0, cache);

      if (!btc_ecdsa_sign(der, &der_len, msg, priv))
        return 0;

      btc_writer_init(&writer);
      btc_writer_push_data(&writer, der, der_len);

      if (memcmp(hash, hash33, 20) == 0)
        btc_writer_push_data(&writer, pub33, 33);
      else
        btc_writer_push_data(&writer, pub65, 65);

      btc_writer_compile(&input->script, &writer);
      btc_writer_clear(&writer);

      return 1;
    }

    return 0;
  }

  if (btc_script_get_p2wpkh(hash, script)) {
    if (memcmp(hash, hash33, 20) != 0)
      return 0;

    btc_script_init(&redeem);
    btc_script_set_p2pkh(&redeem, hash);

    btc_tx_sighash(msg, tx, index, &redeem,
                   value, type, 1, cache);

    btc_script_clear(&redeem);

    if (!btc_ecdsa_sign(der, &der_len, msg, priv))
      return 0;

    btc_stack_reset(&input->witness);
    btc_stack_push_data(&input->witness, der, der_len);
    btc_stack_push_data(&input->witness, pub33, 33);

    return 1;
  }

  if (btc_script_get_p2sh(hash, script)) {
    btc_script_init(&program);
    btc_script_set_p2wpkh(&program, hash33);
    btc_script_hash160(msg, &program);

    if (memcmp(msg, hash, 20) != 0) {
      btc_script_clear(&program);
      return 0;
    }

    btc_writer_init(&writer);
    btc_writer_push_data(&writer, program->data, program->length);
    btc_writer_compile(&input->script, &writer);
    btc_writer_clear(&writer);
    btc_script_clear(&program);

    btc_script_init(&redeem);
    btc_script_set_p2pkh(&redeem, hash33);

    btc_tx_sighash(msg, tx, index, &redeem,
                   value, type, 1, cache);

    btc_script_clear(&redeem);

    if (!btc_ecdsa_sign(der, &der_len, msg, priv))
      return 0;

    btc_stack_reset(&input->witness);
    btc_stack_push_data(&input->witness, der, der_len);
    btc_stack_push_data(&input->witness, pub33, 33);

    return 1;
  }

  return 0;
}

int
btc_tx_is_rbf(const btc_tx *tx) {
  size_t i;

  if (tx->version == 2)
    return 0;

  for (i = 0; i < tx->inputs.length; i++) {
    if (tx->inputs.items[i]->sequence < 0xfffffffe)
      return 1;
  }

  return 0;
}

int
btc_tx_is_final(const btc_tx *tx, uint32_t height, uint32_t time) {
  size_t i;

  if (tx->locktime == 0)
    return 1;

  if (tx->locktime < (tx->locktime < BTC_LOCKTIME_THRESHOLD ? height : time))
    return 1;

  for (i = 0; i < tx->inputs.length; i++) {
    if (tx->inputs.items[i]->sequence != 0xffffffff)
      return 0;
  }

  return 1;
}

int
btc_tx_verify_locktime(const btc_tx *tx, size_t index, uint32_t predicate) {
  static const uint32_t threshold = BTC_LOCKTIME_THRESHOLD;
  const btc_input_t *input = tx->inputs.items[index];

  /* Locktimes must be of the same type (blocks or seconds). */
  if ((tx->locktime < threshold) != (predicate < threshold))
    return 0;

  if (predicate > tx->locktime)
    return 0;

  if (input->sequence == 0xffffffff)
    return 0;

  return 1;
}

int
btc_tx_verify_sequence(const btc_tx *tx, size_t index, uint32_t predicate) {
  static const uint32_t disable_flag = BTC_SEQUENCE_DISABLE_FLAG;
  static const uint32_t type_flag = BTC_SEQUENCE_TYPE_FLAG;
  static const uint32_t mask = BTC_SEQUENCE_MASK;
  const btc_input_t *input = tx->inputs.items[index];

  /* For future softfork capability. */
  if (predicate & disable_flag)
    return 1;

  /* Version must be >=2. */
  if (tx->version < 2)
    return 0;

  /* Cannot use the disable flag without
     the predicate also having the disable
     flag (for future softfork capability). */
  if (input->sequence & disable_flag)
    return 0;

  /* Locktimes must be of the same type (blocks or seconds). */
  if ((input->sequence & type_flag) != (predicate & type_flag))
    return 0;

  if ((predicate & mask) > (input->sequence & mask))
    return 0;

  return 1;
}

int64_t
btc_tx_input_value(const btc_tx *tx, btc_view_t *view) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  int64_t total = 0;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      return -1;

    total += coin->output.value;
  }

  return total;
}

int64_t
btc_tx_output_value(const btc_tx *tx) {
  int64_t total = 0;
  size_t i;

  for (i = 0; i < tx->outputs.length; i++) {
    total += tx->outputs.items[i]->value;

  return total;
}

int64_t
btc_tx_fee(const btc_tx *tx, btc_view_t *view) {
  int64_t value = btc_tx_input_value(tx, view);

  if (value < 0)
    return -1;

  return value - btc_tx_output_value(tx);
}

int
btc_tx_legacy_sigops(const btc_tx *tx) {
  const btc_input_t *input;
  const btc_output_t *output;
  int total = 0;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    total += btc_script_sigops(&input->script, 0);
  }

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];
    total += btc_script_sigops(&output->script, 0);
  }

  return total;
}

int
btc_tx_p2sh_sigops(const btc_tx *tx, btc_view_t *view) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  int total = 0;
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return 0;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      continue;

    if (!btc_script_is_p2sh(&coin->output.script))
      continue;

    total += btc_script_p2sh_sigops(&coin->output.script, &input->script);
  }

  return total;
}

int
btc_tx_witness_sigops(const btc_tx *tx, btc_view_t *view) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  int total = 0;
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return 0;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      continue;

    total += btc_script_witness_sigops(&coin->output.script,
                                       &input->script,
                                       &input->witness);
  }

  return total;
}

int
btc_tx_sigops_cost(const btc_tx *tx, btc_view_t *view, unsigned int flags) {
  int cost = btc_tx_legacy_sigops(tx) * BTC_WITNESS_SCALE_FACTOR;

  if (flags & BTC_SCRIPT_VERIFY_P2SH)
    cost += btc_tx_p2sh_sigops(tx, view) * BTC_WITNESS_SCALE_FACTOR;

  if (flags & BTC_SCRIPT_VERIFY_WITNESS)
    cost += btc_tx_witness_sigops(tx, view);

  return cost;
}

int
btc_tx_sigops(const btc_tx *tx, btc_view_t *view, unsigned int flags) {
  int cost = btc_tx_sigops_cost(tx, view, flags);
  return (cost + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

KHASH_SET_INIT_OUTPOINT(outpoints)

int
btc_tx_has_duplicate_inputs(const btc_tx_t *tx) {
  khash_t(outpoints) *set = kh_init(outpoints);
  const btc_input_t *input;
  size_t i;
  int ret;

  CHECK(set != NULL);

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    ret = -1;

    kh_put(outpoints, set, &input->prevout, &ret);

    CHECK(ret != -1);

    if (ret == 0) {
      kh_destroy(outpoints, set);
      return 1;
    }
  }

  kh_destroy(outpoints, set);

  return 0;
}

#define THROW(m, s) do { \
  if (err != NULL) {     \
    err->msg = (m);      \
    err->score = (s);    \
  }                      \
  return 0;              \
} while (0)

int
btc_tx_check_sanity(btc_verify_error_t *err, const btc_tx *tx) {
  const btc_input_t *input;
  const btc_output_t *output;
  int64_t total = 0;
  size_t i, size;

  if (tx->inputs.length == 0)
    THROW("bad-txns-vin-empty", 100);

  if (tx->outputs.length == 0)
    THROW("bad-txns-vout-empty", 100);

  if (btc_tx_base_size(tx) > BTC_MAX_BLOCK_SIZE)
    THROW("bad-txns-oversize", 100);

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];

    if (output->value < 0)
      THROW("bad-txns-vout-negative", 100);

    if (output->value > BTC_MAX_MONEY)
      THROW("bad-txns-vout-toolarge", 100);

    total += output->value;

    if (total < 0 || total > BTC_MAX_MONEY)
      THROW("bad-txns-txouttotal-toolarge", 100);
  }

  if (btc_tx_has_duplicate_inputs(tx))
    THROW("bad-txns-inputs-duplicate", 100);

  if (btc_tx_is_coinbase(tx)) {
    size = tx->inputs[0]->script.length;

    if (size < 2 || size > 100)
      THROW("bad-cb-length", 100);
  } else {
    for (i = 0; i < tx->inputs.length; i++) {
      input = tx->inputs.items[i];

      if (btc_outpoint_is_null(&input->prevout))
        THROW("bad-txns-prevout-null", 10);
    }
  }

  return 1;
}

int
btc_check_inputs(btc_verify_error_t *err,
                 const btc_tx *tx,
                 btc_view_t *view,
                 uint32_t height) {
  const btc_input_t *input;
  int64_t value, fee;
  int64_t total = 0;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      THROW("bad-txns-inputs-missingorspent", 0);

    if (coin->coinbase) {
      CHECK(height >= coin->height);

      if (height - coin->height < BTC_COINBASE_MATURITY)
        THROW("bad-txns-premature-spend-of-coinbase", 0);
    }

    if (coin->output.value < 0 || coin->output.value > BTC_MAX_MONEY)
      THROW("bad-txns-inputvalues-outofrange", 100);

    total += coin->output.value;

    if (total < 0 || total > BTC_MAX_MONEY)
      THROW("bad-txns-inputvalues-outofrange", 100);
  }

  /* Overflows already checked in `isSane()`. */
  value = btc_tx_output_value(tx);

  if (total < value)
    THROW("bad-txns-in-belowout", 100);

  fee = total - value;

  if (fee < 0)
    THROW("bad-txns-fee-negative", 100);

  if (fee > BTC_MAX_MONEY)
    THROW("bad-txns-fee-outofrange", 100);

  return 1;
}

#undef THROW

size_t
btc_tx_base_size(const btc_tx_t *tx) {
  size_t size = 0;
  size_t i;

  size += 4;
  size += btc_inpvec_size(&tx->inputs);
  size += btc_outvec_size(&tx->outputs);
  size += 4;

  return size;
}

size_t
btc_tx_witness_size(const btc_tx_t *tx) {
  size_t size = 0;
  size_t i;

  if (btc_tx_has_witness(tx)) {
    size += 2;

    for (i = 0; i < tx->inputs.length; i++)
      size += btc_stack_size(&tx->inputs.items[i]->witness);
  }

  return size;
}

size_t
btc_tx_size(const btc_tx_t *tx) {
  return btc_tx_base_size(tx) + btc_tx_witness_size(tx);
}

size_t
btc_tx_weight(const btc_tx_t *tx) {
  size_t base = btc_tx_base_size(tx);
  size_t wit = btc_tx_witness_size(tx);
  return (base * BTC_WITNESS_SCALE_FACTOR) + wit;
}

size_t
btc_tx_virtual_size(const btc_tx_t *tx) {
  size_t weight = btc_tx_weight(tx);
  return (weight + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

size_t
btc_tx_sigops_size(const btc_tx_t *tx, int sigops) {
  size_t weight = btc_tx_weight(tx);

  sigops *= BTC_BYTES_PER_SIGOP;

  if ((size_t)sigops > weight)
    weight = sigops;

  return (weight + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

uint8_t *
btc_tx_write(uint8_t *zp, const btc_tx_t *tx) {
  int witness = btc_tx_has_witness(tx);
  size_t i;

  zp = btc_uint32_write(zp, tx->version);

  if (witness) {
    zp = btc_uint8_write(zp, 0);
    zp = btc_uint8_write(zp, 1);
  }

  zp = btc_inpvec_write(zp, &tx->inputs);
  zp = btc_outvec_write(zp, &tx->outputs);
  zp = btc_uint32_write(zp, tx->locktime);

  if (witness) {
    for (i = 0; i < tx->inputs.length; i++)
      zp = btc_stack_write(zp, &tx->inputs.items[i]->witness);
  }

  return zp;
}

int
btc_tx_read(btc_tx_t *z, const uint8_t **xp, size_t *xn) {
  uint8_t flags = 0;
  size_t i;

  if (!btc_uint32_read(&z->version, xp, xn))
    return 0;

  if (*xn >= 2 && (*xp)[0] == 0 && (*xp)[1] != 0) {
    flags = (*xp)[1];
    *xp += 2;
    *xn -= 2;
  }

  if (!btc_uint8_read(&flags, xp, xn))
    return 0;

  if (!btc_inpvec_read(&z->inputs, xp, xn))
    return 0;

  if (!btc_outvec_read(&z->outputs, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->locktime, xp, xn))
    return 0;

  if (flags & 1) {
    flags ^= 1;

    for (i = 0; i < z->inputs.length; i++) {
      if (!btc_stack_read(&z->inputs.items[i]->witness, xp, xn))
        return 0;
    }
  }

  if (flags != 0)
    return 0;

  return 1;
}

btc_coin_t *
btc_tx_coin(const btc_tx_t *tx, uint32_t index, uint32_t height) {
  btc_coin_t *coin = btc_coin_create();

  coin->version = tx->version;
  coin->height = height;
  coin->coinbase = btc_tx_is_coinbase(tx);
  coin->output = tx->outputs.items[index];

  return coin;
}

/*
 * Transaction Vector
 */

DEFINE_SERIALIZABLE_VECTOR(btc_txvec, btc_tx, SCOPE_EXTERN)

/*
 * Header
 */

DEFINE_SERIALIZABLE_OBJECT(btc_header, SCOPE_EXTERN)

void
btc_header_init(btc_header_t *z) {
  z->version = 0;
  memset(z->prev_block, 0, 32);
  memset(z->merkle_root, 0, 32);
  z->time = 0;
  z->bits = 0;
  z->nonce = 0;
}

void
btc_header_clear(btc_header_t *z) {
  (void)z;
}

void
btc_header_copy(btc_header_t *z, const btc_header_t *x) {
  z->version = x->version;
  memcpy(z->prev_block, x->prev_block, 32);
  memcpy(z->merkle_root, x->merkle_root, 32);
  z->time = x->time;
  z->bits = x->bits;
  z->nonce = x->nonce;
}

size_t
btc_header_size(const btc_header_t *x) {
  size_t size = 0;

  (void)x;

  size += 4;
  size += 32;
  size += 32;
  size += 4;
  size += 4;
  size += 4;

  return size;
}

uint8_t *
btc_header_write(uint8_t *zp, const btc_header_t *x) {
  zp = btc_uint32_write(zp, x->version);
  zp = btc_raw_write(zp, x->prev_block, 32);
  zp = btc_raw_write(zp, x->merkle_root, 32);
  zp = btc_uint32_write(zp, x->time);
  zp = btc_uint32_write(zp, x->bits);
  zp = btc_uint32_write(zp, x->nonce);
  return zp;
}

int
btc_header_read(btc_header_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_uint32_read(&z->version, xp, xn))
    return 0;

  if (!btc_raw_read(z->prev_block, 32, xp, xn))
    return 0;

  if (!btc_raw_read(z->merkle_root, 32, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->time, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->bits, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->nonce, xp, xn))
    return 0;

  return 1;
}

void
btc_header_hash(uint8_t *hash, const btc_header_t *hdr) {
  hash256_init(&ctx);

  btc_uint32_update(&ctx, hdr->version);
  btc_raw_update(&ctx, hdr->prev_block, 32);
  btc_raw_update(&ctx, hdr->merkle_root, 32);
  btc_uint32_update(&ctx, hdr->time);
  btc_uint32_update(&ctx, hdr->bits);
  btc_uint32_update(&ctx, hdr->nonce);

  hash256_final(&ctx, hash);
}

int
btc_header_verify(const btc_header_t *hdr) {
  uint8_t target[32];
  uint8_t hash[32];

  if (!btc_compact_export(target, hdr->bits))
    return 0;

  btc_header_hash(hash, hdr);

  return btc_hash_compare(hash, target) <= 0;
}

/*
 * Block
 */

DEFINE_SERIALIZABLE_OBJECT(btc_block, SCOPE_EXTERN)

void
btc_block_init(btc_block_t *z) {
  btc_header_init(&z->header);
  btc_txvec_init(&z->txs);
}

void
btc_block_clear(btc_block_t *z) {
  btc_header_clear(&z->header);
  btc_txvec_clear(&z->txs);
}

void
btc_block_copy(btc_block_t *z, const btc_block_t *x) {
  btc_header_copy(&z->header, &x->header);
  btc_txvec_copy(&z->txs, &x->txs);
}

int
btc_block_has_witness(const btc_block_t *blk) {
  size_t i;

  for (i = 0; i < blk->txs.length; i++) {
    if (btc_tx_has_witness(blk->txs.items[i]))
      return 1;
  }

  return 0;
}

int
btc_block_merkle_root(uint8_t *root, const btc_block_t *blk) {
  size_t length = blk->txs.length;
  uint8_t *hashes = (uint8_t *)malloc(length * 32);
  size_t i;
  int ret;

  CHECK(hashes != NULL);

  for (i = 0; i < length; i++)
    btc_tx_txid(&hashes[i * 32], blk->txs.items[i]);

  ret = btc_merkle_root(root, hashes, length);

  free(hashes);

  return ret;
}

int
btc_block_witness_root(uint8_t *root, const btc_block_t *blk) {
  size_t length = blk->txs.length;
  uint8_t *hashes = (uint8_t *)malloc(length * 32);
  size_t i;
  int ret;

  CHECK(hashes != NULL);

  memset(hashes, 0, 32);

  for (i = 1; i < length; i++)
    btc_tx_wtxid(&hashes[i * 32], blk->txs.items[i]);

  ret = btc_merkle_root(root, hashes, length);

  free(hashes);

  return ret;
}

const uint8_t *
btc_block_witness_nonce(const btc_block_t *blk) {
  const btc_input_t *input;
  const btc_tx_t *tx;

  if (blk->txs.length == 0)
    return NULL;

  tx = blk->txs.items[0];

  if (tx->inputs.length != 1)
    return NULL;

  input = tx->inputs.items[0];

  if (input->witness.length != 1)
    return NULL;

  if (input->witness.items[0]->length != 32)
    return NULL;

  return input->witness.items[0]->data;
}

int
btc_block_create_commitment_hash(uint8_t *hash, const btc_block_t *blk) {
  const uint8_t *nonce = btc_block_witness_nonce(blk);
  uint8_t root[32];
  hash256_t ctx;

  if (nonce == NULL)
    return 0;

  if (!btc_block_witness_root(root, blk))
    return 0;

  hash256_init(&ctx);
  hash256_update(&ctx, root, 32);
  hash256_update(&ctx, nonce, 32);
  hash256_final(&ctx, hash);

  return 1;
}

int
btc_block_get_commitment_hash(uint8_t *hash /* maybe do zero copy */, const btc_block_t *blk) {
  const btc_output_t *output;
  const btc_tx_t *tx;
  size_t i;

  if (blk->txs.length == 0)
    return 0;

  tx = blk->txs.items[0];

  for (i = tx->outputs.length - 1; i != (size_t)-1; i--) {
    output = tx->outputs.items[i];

    if (btc_script_get_commitment(hash, &output->script))
      return 1;
  }

  return 0;
}

#define THROW(m, s) do { \
  if (err != NULL) {     \
    err->msg = (m);      \
    err->score = (s);    \
  }                      \
  return 0;              \
} while (0)

int
btc_block_check_body(btc_verify_error_t *err, const btc_block_t *blk) {
  const btc_tx_t *tx;
  uint8_t root[32];
  int sigops = 0;
  size_t i;

  /* Check base size. */
  if (blk->txs.length == 0
      || blk->txs.length > BTC_MAX_BLOCK_SIZE
      || btc_block_base_size(blk) > BTC_MAX_BLOCK_SIZE) {
    THROW("bad-blk-length", 100);
  }

  /* First TX must be a coinbase. */
  if (blk->txs.length == 0 || !btc_tx_is_coinbase(blk->txs.items[0]))
    THROW("bad-cb-missing", 100);

  /* If the merkle is mutated, we have duplicate txs. */
  if (!btc_block_merkle_root(root, blk))
    THROW("bad-txns-duplicate", 100);

  /* Check merkle root. */
  if (memcmp(blk->header.merkle_root, root, 32) != 0)
    THROW("bad-txnmrklroot", 100);

  /* Test all transactions. */
  sigops = 0;

  for (i = 0; i < blk->txs.length; i++) {
    tx = blk->txs.items[i];

    /* The rest of the txs must not be coinbases. */
    if (i > 0 && btc_tx_is_coinbase(tx))
      THROW("bad-cb-multiple", 100);

    /* Sanity checks. */
    if (!btc_tx_check_sanity(err, tx))
      return 0;

    /* Count legacy sigops (do not count scripthash or witness). */
    sigops += btc_tx_legacy_sigops(tx);

    if (sigops * BTC_WITNESS_SCALE_FACTOR > BTC_MAX_BLOCK_SIGOPS_COST)
      THROW("bad-blk-sigops", 100);
  }

  return 1;
}

#undef THROW

int
btc_block_coinbase_height(uint32_t *height, const btc_block_t *blk) {
  const btc_tx_t *tx;

  *height = (uint32_t)-1;

  if (blk->header.version < 2)
    return 0;

  if (blk->txs.length == 0)
    return 0;

  tx = blk->txs.items[0];

  if (tx->inputs.length == 0)
    return 0;

  return btc_script_get_height(height, &tx->inputs.items[0]->script);
}

int64_t
btc_block_claimed(const btc_block_t *blk) {
  CHECK(blk->txs.length > 0);
  CHECK(btc_tx_is_coinbase(blk->txs.items[0]));

  return btc_tx_output_value(blk->txs.items[0]);
}

size_t
btc_block_base_size(const btc_block_t *blk) {
  size_t size = 0;
  size_t i;

  size += btc_header_size(&blk->header);
  size += btc_size_size(blk->txs.length);

  for (i = 0; i < blk->txs.length; i++)
    size += btc_tx_base_size(blk->txs.items[i]);

  return size;
}

size_t
btc_block_witness_size(const btc_block_t *blk) {
  size_t size = 0;
  size_t i;

  for (i = 0; i < blk->txs.length; i++)
    size += btc_tx_witness_size(blk->txs.items[i]);

  return size;
}

size_t
btc_block_size(const btc_block_t *blk) {
  return btc_block_base_size(blk) + btc_block_witness_size(blk);
}

size_t
btc_block_weight(const btc_block_t *blk) {
  size_t base = btc_block_base_size(blk);
  size_t wit = btc_block_witness_size(blk);
  return (base * BTC_WITNESS_SCALE_FACTOR) + wit;
}

size_t
btc_block_virtual_size(const btc_block_t *blk) {
  size_t weight = btc_block_weight(blk);
  return (weight + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

uint8_t *
btc_block_write(uint8_t *zp, const btc_block_t *x) {
  zp = btc_header_write(zp, &x->header);
  zp = btc_txvec_write(zp, &x->txs);
  return zp;
}

int
btc_block_read(btc_block_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_header_read(&z->header, xp, xn))
    return 0;

  if (!btc_txvec_read(&z->txs, xp, xn))
    return 0;

  return 1;
}

/*
 * Chain Entry
 */

DEFINE_SERIALIZABLE_OBJECT(btc_entry, SCOPE_EXTERN)

void
btc_entry_init(btc_entry_t *z) {
  memset(z->hash, 0, 32);
  btc_header_init(&z->header);
  z->height = 0;
  memset(z->chainwork, 0, 32);
  z->prev = NULL;
  z->next = NULL;
}

void
btc_entry_clear(btc_entry_t *z) {
  btc_header_clear(&z->header);
}

void
btc_entry_copy(btc_entry_t *z, const btc_entry_t *x) {
  memcpy(z->hash, x->hash, 32);
  btc_header_copy(&z->header, &x->header);
  z->height = x->height;
  memcpy(z->chainwork, x->chainwork, 32);
}

size_t
btc_entry_size(const btc_entry_t *x) {
  size_t size = 0;

  size += btc_header_size(&x->header);
  size += 4;
  size += 32;

  return size;
}

uint8_t *
btc_entry_write(uint8_t *zp, const btc_entry_t *x) {
  zp = btc_header_write(zp, &x->header);
  zp = btc_uint32_write(zp, x->height);
  zp = btc_raw_write(zp, x->chainwork, 32);
  return zp;
}

int
btc_entry_read(btc_entry_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_header_read(&z->header, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->height, xp, xn))
    return 0;

  if (!btc_raw_read(z->chainwork, 32, xp, xn))
    return 0;

  btc_header_hash(z->hash, &z->header);

  z->prev = NULL;
  z->next = NULL;

  return 1;
}

void
btc_entry_get_chainwork(uint8_t *chainwork,
                        const btc_entry_t *entry,
                        const btc_entry_t *prev) {
#if MP_LIMB_BITS == 64
  static mp_limb_t limbs[5] = {0, 0, 0, 0, 1};
  static const mpz_t max = MPZ_ROINIT_N(limbs, 5);
#else
  static mp_limb_t limbs[9] = {0, 0, 0, 0, 0, 0, 0, 0, 1};
  static const mpz_t max = MPZ_ROINIT_N(limbs, 9);
#endif
  mpz_t work, target, proof;

  mpz_init(work);
  mpz_init(target);
  mpz_init(proof);

  if (prev != NULL)
    mpz_import(work, prev->chainwork, 32, -1);

  mpz_set_compact(target, entry->header.bits);

  CHECK(mpz_sgn(target) >= 0);
  CHECK(mpz_bitlen(target) <= 256);

  mpz_add_ui(target, target, 1);
  mpz_quo(proof, max, target);

  mpz_add(work, work, proof);
  mpz_export(chainwork, work, 32, -1);

  mpz_clear(work);
  mpz_clear(target);
  mpz_clear(proof);
}

void
btc_entry_set_header(btc_entry_t *entry,
                     const btc_header_t *hdr,
                     const btc_entry_t *prev) {
  btc_header_hash(entry->hash, hdr);

  entry->header = hdr;
  entry->height = prev->height + 1;

  btc_entry_get_chainwork(entry->chainwork, entry, prev);
}

void
btc_entry_set_block(btc_entry_t *entry,
                    const btc_block_t *block,
                    const btc_entry_t *prev) {
  btc_entry_set_header(entry, &block->header, prev);
}

/*
 * Coin
 */

DEFINE_SERIALIZABLE_OBJECT(btc_coin, SCOPE_EXTERN)

void
btc_coin_init(btc_coin_t *z) {
  z->version = 1;
  z->height = (uint32_t)-1;
  z->coinbase = 0;
  z->spent = 0;
  btc_output_init(&z->output);
}

void
btc_coin_clear(btc_coin_t *z) {
  btc_output_clear(&z->output);
}

void
btc_coin_copy(btc_coin_t *z, const btc_coin_t *x) {
  z->version = x->version;
  z->height = x->height;
  z->coinbase = x->coinbase;
  z->spent = x->spent;
  btc_output_copy(&z->output, &x->output);
}

size_t
btc_coin_size(const btc_coin_t *x) {
  size_t size = 0;

  size += btc_varint_size(x->version);
  size += 4;
  size += 1;
  size += btc_output_size(&x->output);

  return size;
}

uint8_t *
btc_coin_write(uint8_t *zp, const btc_coin_t *x) {
  zp = btc_varint_write(zp, x->version);
  zp = btc_uint32_write(zp, x->height);
  zp = btc_uint8_write(zp, x->coinbase);
  zp = btc_output_write(zp, &x->output);
  return zp;
}

int
btc_coin_read(btc_coin_t *z, const uint8_t **xp, size_t *xn) {
  uint64_t version;
  uint8_t flags;

  if (!btc_varint_read(&version, xp, xn))
    return 0;

  z->version = (uint32_t)version;

  if (!btc_uint32_read(&z->height, xp, xn))
    return 0;

  if (!btc_uint8_read(&flags, xp, xn))
    return 0;

  z->coinbase = flags & 1;
  z->spent = 0;

  if (!btc_output_read(&z->output, xp, xn))
    return 0;

  return 1;
}

/*
 * Coins
 */

KHASH_MAP_INIT_INT(coins, btc_coin_t *)

typedef struct btc_coins_s {
  uint8_t hash[32];
  khash_t(coins) *map;
} btc_coins_t;

static btc_coins_t *
btc_coins_create(void) {
  btc_coins_t *coins = (btc_coins_t *)malloc(sizeof(btc_coins_t));

  CHECK(coins != NULL);

  coins->map = kh_init(coins);

  CHECK(coins->map != NULL);

  return coins;
}

static void
btc_coins_destroy(btc_coins_t *coins) {
  khiter_t iter = kh_begin(coins->map);
  btc_coin_t *val;

  for (; iter != kh_end(coins->map); iter++) {
    if (kh_exist(coins->map, iter)) {
      val = kh_value(coins->map, iter);

      if (val != NULL)
        btc_coin_destroy(val);

      kh_value(coins->map, iter) = NULL;
    }
  }

  kh_destroy(coins, coins->map);

  free(coins);
}

static btc_coin_t *
btc_coins_get(btc_coins_t *coins, uint32_t index) {
  khiter_t iter = kh_get(coins, coins->map, index);

  if (iter == kh_end(coins->map))
    return 0;

  return kh_value(coins->map, iter);
}

static void
btc_coins_put(btc_coins_t *coins, uint32_t index, btc_coin_t *coin) {
  int ret = -1;
  khiter_t iter = kh_put(coins, coins->map, index, &ret);
  btc_coin_t *val;

  CHECK(ret != -1);

  if (ret == 0) {
    val = kh_value(coins->map, iter);

    if (val != NULL)
      btc_coin_destroy(val);
  }

  kh_value(coins->map, iter) = coin;
}

/*
 * Undo Coins
 */

DEFINE_SERIALIZABLE_VECTOR(btc_undo, btc_coin, SCOPE_EXTERN)

/*
 * Coin View
 */

KHASH_MAP_INIT_CONST_HASH(view, btc_coins_t *)

typedef struct btc_view_s {
  khash_t(view) *map;
  btc_undo_t undo;
} btc__view_t;

btc__view_t *
btc_view_create(void) {
  btc__view_t *view = (btc__view_t *)malloc(sizeof(btc__view_t));

  CHECK(view != NULL);

  view->map = kh_init(view);

  CHECK(view->map != NULL);

  btc_undo_init(&view->undo);

  return view;
}

void
btc_view_destroy(btc__view_t *view) {
  khiter_t iter = kh_begin(view->map);
  btc_coins_t *val;

  for (; iter != kh_end(view->map); iter++) {
    if (kh_exist(view->map, iter)) {
      val = kh_value(view->map, iter);

      if (val != NULL)
        btc_coins_destroy(val);

      kh_value(view->map, iter) = NULL;
    }
  }

  kh_destroy(view, view->map);

  btc_undo_clear(&view->undo);

  free(view);
}

static btc_coins_t *
btc_view_coins(btc__view_t *view, const uint8_t *hash) {
  khiter_t iter = kh_get(view, view->map, hash);

  if (iter == kh_end(view->map))
    return NULL;

  return kh_value(view->map, iter);
}

static btc_coins_t *
btc_view_ensure(btc__view_t *view, const uint8_t *hash) {
  int ret = -1;
  khiter_t iter = kh_put(view, view->map, hash, &ret);
  btc_coins_t *coins;

  CHECK(ret != -1);

  if (ret) {
    coins = btc_coins_create();

    memcpy(coins->hash, hash, 32);

    kh_key(view->map, iter) = coins->hash;
    kh_value(view->map, iter) = coins;
  } else {
    coins = kh_value(view->map, iter);

    CHECK(coins != NULL);
  }

  return coins;
}

const btc_coin_t *
btc_view_get(btc__view_t *view, const btc_outpoint_t *outpoint) {
  btc_coins_t *coins = btc_view_coins(view, outpoint->hash);

  if (coins == NULL)
    return NULL;

  return btc_coins_get(coins, outpoint->index);
}

void
btc_view_put(btc__view_t *view, const btc_outpoint_t *outpoint, btc_coin_t *coin) {
  btc_coins_t *coins = btc_view_ensure(view, outpoint->hash);
  btc_coins_put(coins, outpoint->index, coin);
}

int
btc_view_spend(btc__view_t *view,
              const btc_tx_t *tx,
              btc_coin_t *(*read_coin)(const btc_outpoint_t *, void *),
              void *arg) {
  const btc_outpoint_t *prevout;
  btc_coins_t *coins;
  btc_coin_t *coin;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    prevout = &tx->inputs[i]->prevout;
    coins = btc_view_ensure(view, prevout->hash);
    coin = btc_coins_get(coins, prevout->index);

    if (coin == NULL) {
      coin = read_coin(prevout, arg);

      if (coin == NULL)
        return 0;

      btc_coins_put(coins, prevout->index, coin);
    }

    if (coin->spent)
      return 0;

    coin->spent = 1;

    btc_undo_push(&view->undo, btc_coin_clone(coin));
  }

  return 1;
}

void
btc_view_add(btc__view_t *view, const btc_tx_t *tx, uint32_t height, int spent) {
  uint8_t hash[32];
  btc_coins_t *coins;
  btc_coin_t *coin;
  size_t i;

  btc_tx_txid(hash, tx);

  coins = btc_view_ensure(view, hash);

  for (i = 0; i < tx->outputs.length; i++) {
    coin = btc_tx_coin(tx, i, height);
    coin->spent = spent;

    btc_coins_put(coins, i, coin);
  }
}

void
btc_view_iterate(btc__view_t *view,
                void (*cb)(const uint8_t *,
                           uint32_t,
                           const btc_coin_t *,
                           void *),
                void *arg) {
  khiter_t view_iter = kh_begin(view->map);
  khiter_t coins_iter;
  btc_coins_t *coins;

  for (; view_iter != kh_end(view->map); view_iter++) {
    if (!kh_exist(view->map, view_iter))
      continue;

    coins = kh_value(view->map, view_iter);
    coins_iter = kh_begin(coins->map);

    for (; coins_iter != kh_end(coins->map); coins_iter++) {
      if (!kh_exist(coins->map, coins_iter))
        continue;

      cb(coins->hash, kh_key(coins->map, coins_iter),
                      kh_value(coins->map, coins_iter),
                      arg);
    }
  }
}

btc_undo_t *
btc_view_undo(btc__view_t *view) {
  return &view->undo;
}

/*
 * Mining / PoW
 */

int
btc_hash_compare(const uint8_t *x, const uint8_t *y) {
  int i;

  for (i = 32 - 1; i >= 0; i--) {
    if (x[i] != y[i])
      return (int)x[i] - (int)y[i];
  }

  return 0;
}

int
btc_mine(btc_header_t *hdr,
         const uint8_t *target,
         uint64_t limit,
         uint32_t (*adjtime)(void *),
         void *arg) {
  uint64_t attempt = 0;
  hash256_t pre, ctx;
  uint8_t hash[32];

  memset(&pre, 0, sizeof(pre));

  for (;;) {
    hdr->time = adjtime(arg);

    hash256_init(&pre);

    btc_uint32_update(&pre, hdr->version);
    btc_raw_update(&pre, hdr->prev_block, 32);
    btc_raw_update(&pre, hdr->merkle_root, 32);
    btc_uint32_update(&pre, hdr->time);
    btc_uint32_update(&pre, hdr->bits);

    do {
      ctx = pre;

      btc_uint32_update(&ctx, hdr->nonce);

      hash256_final(&ctx, hash);

      if (btc_hash_compare(hash, target) <= 0)
        return 1;

      hdr->nonce++;

      if (limit > 0 && ++attempt == limit)
        return 0;
    } while (hdr->nonce != 0);
  }
}

/*
 * Compact
 */

static void
mpz_set_compact(mpz_t z, uint32_t bits) {
  uint32_t exponent, negative, mantissa;

  if (bits == 0) {
    mpz_set_ui(z, 0);
    return;
  }

  exponent = bits >> 24;
  negative = (bits >> 23) & 1;
  mantissa = bits & 0x7fffff;

  if (exponent <= 3) {
    mantissa >>= 8 * (3 - exponent);
    mpz_set_ui(z, mantissa);
  } else {
    mpz_set_ui(z, mantissa);
    mpz_mul_2exp(z, z, 8 * (exponent - 3));
  }

  if (negative)
    mpz_neg(z, z);
}

static uint32_t
mpz_get_compact(const mpz_t x) {
  uint32_t bits, exponent, negative, mantissa;
  mpz_t t;

  if (mpz_sgn(x) == 0)
    return 0;

  exponent = mpz_bytelen(x);
  negative = mpz_sgn(x) < 0;

  if (exponent <= 3) {
    mantissa = mpz_get_ui(x);
    mantissa <<= 8 * (3 - exponent);
  } else {
    mpz_init(t);
    mpz_quo_2exp(t, x, 8 * (exponent - 3));
    mantissa = mpz_get_ui(t);
    mpz_clear(t);
  }

  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent += 1;
  }

  bits = (exponent << 24) | mantissa;

  if (negative)
    bits |= 0x800000;

  return bits;
}

int
btc_compact_export(uint8_t *target, uint32_t bits) {
  int ret = 0;
  mpz_t z;

  mpz_init(z);
  mpz_set_compact(z, bits);

  if (mpz_sgn(z) <= 0)
    goto fail;

  if (mpz_bitlen(z) > 256)
    goto fail;

  mpz_export(target, z, 32, -1);
  ret = 1;
fail:
  mpz_clear(z);
  return ret;
}

uint32_t
btc_compact_import(const uint8_t *target) {
  uint32_t bits;
  mpz_t x;

  mpz_init(x);
  mpz_import(x, target, 32, -1);

  bits = mpz_get_compact(x);

  mpz_clear(x);

  return bits;
}

#define SCOPE_STATIC static
#define SCOPE_EXTERN

/*
 * Object
 */

#define DEFINE_OBJECT(name, scope)                          \
scope void                                                  \
name ## _init(name ## _t *z);                               \
                                                            \
scope void                                                  \
name ## _clear(name ## _t *z);                              \
                                                            \
scope void                                                  \
name ## _copy(name ## _t *x, const name ## _t *y);          \
                                                            \
scope name ## _t *                                          \
name ## _create(void) {                                     \
  name ## _t *z = (name ## _t *)malloc(sizeof(name ## _t)); \
                                                            \
  CHECK(z != NULL);                                         \
                                                            \
  name ## _init(z);                                         \
                                                            \
  return z;                                                 \
}                                                           \
                                                            \
scope void                                                  \
name ## _destroy(name ## _t *z) {                           \
  name ## _clear(z);                                        \
  free(z);                                                  \
}                                                           \
                                                            \
scope name ## _t *                                          \
name ## _clone(const name ## _t *x) {                       \
  name ## _t *z = name ## _create();                        \
  name ## _copy(z, x);                                      \
  return z;                                                 \
}

/*
 * Vector
 */

#define DEFINE_VECTOR(name, child, scope)                            \
DEFINE_OBJECT(name, scope)                                           \
                                                                     \
scope void                                                           \
name ## _init(name ## _t *z) {                                       \
  z->items = NULL;                                                   \
  z->alloc = 0;                                                      \
  z->length = 0;                                                     \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _clear(name ## _t *z) {                                      \
  size_t i;                                                          \
                                                                     \
  for (i = 0; i < z->length; i++)                                    \
    child ## _destroy(z->items[i]);                                  \
                                                                     \
  if (z->alloc > 0)                                                  \
    free(z->items);                                                  \
                                                                     \
  z->items = NULL;                                                   \
  z->alloc = 0;                                                      \
  z->length = 0;                                                     \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _reset(name ## _t *z) {                                      \
  size_t i;                                                          \
                                                                     \
  for (i = 0; i < z->length; i++)                                    \
    child ## _destroy(z->items[i]);                                  \
                                                                     \
  z->length = 0;                                                     \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _grow(name ## _t *z, size_t zn) {                            \
  if (zn > z->alloc) {                                               \
    child ## _t **zp =                                               \
      (child ## _t **)realloc(z->items, zn * sizeof(child ## _t *)); \
                                                                     \
    CHECK(zp != NULL);                                               \
                                                                     \
    z->items = zp;                                                   \
    z->alloc = zn;                                                   \
  }                                                                  \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _push(name ## _t *z, child ## _t *x) {                       \
  if (z->length == z->alloc)                                         \
    name ## _grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));          \
                                                                     \
  z->items[z->length++] = x;                                         \
}                                                                    \
                                                                     \
scope child ## _t *                                                  \
name ## _pop(name ## _t *z) {                                        \
  CHECK(z->length > 0);                                              \
  return z->items[--z->length];                                      \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _drop(name ## _t *z) {                                       \
  child ## _destroy(name ## _pop(z));                                \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _resize(name ## _t *z, size_t zn) {                          \
  if (z->length < zn) {                                              \
    name ## _grow(z, zn);                                            \
    z->length = zn;                                                  \
  } else {                                                           \
    while (z->length > zn)                                           \
      name ## _drop(z);                                              \
  }                                                                  \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _copy(name ## _t *x, const name ## _t *y) {                  \
  size_t i;                                                          \
                                                                     \
  name ## _reset(x);                                                 \
                                                                     \
  for (i = 0; i < y->length; i++)                                    \
    name ## _push(x, child ## _clone(y->items[i]));                  \
}

/*
 * Serializable (abstract)
 */

#define DEFINE_SERIALIZABLE(name, scope)                         \
scope name ## _t *                                               \
name ## _create(void);                                           \
                                                                 \
scope void                                                       \
name ## _destroy(name ## _t *z);                                 \
                                                                 \
scope size_t                                                     \
name ## _size(const name ## _t *x);                              \
                                                                 \
scope uint8_t *                                                  \
name ## _write(uint8_t *zp, const name ## _t *x);                \
                                                                 \
scope int                                                        \
name ## _read(name ## _t *z, const uint8_t **xp, size_t *xn);    \
                                                                 \
scope void                                                       \
name ## _export(uint8_t *zp, const name ## _t *x) {              \
  name ## _write(zp, x);                                         \
}                                                                \
                                                                 \
scope void                                                       \
name ## _encode(uint8_t **zp, size_t *zn, const name ## _t *x) { \
  *zn = name ## _size(x);                                        \
  *zp = (uint8_t *)malloc(*zn);                                  \
                                                                 \
  CHECK(*zp != NULL);                                            \
                                                                 \
  name ## _export(*zp, x);                                       \
}                                                                \
                                                                 \
scope int                                                        \
name ## _import(name ## _t *z, const uint8_t *xp, size_t xn) {   \
  return name ## _read(z, &xp, &xn);                             \
}                                                                \
                                                                 \
scope name ## _t *                                               \
name ## _decode(const uint8_t *xp, size_t xn) {                  \
  name ## _t *z = name ## _create();                             \
                                                                 \
  if (!name ## _import(z, xp, xn)) {                             \
    name ## _destroy(z);                                         \
    return NULL;                                                 \
  }                                                              \
                                                                 \
  return z;                                                      \
}

/*
 * Serializable Object
 */

#define DEFINE_SERIALIZABLE_OBJECT(name, scope) \
DEFINE_OBJECT(name, scope)                      \
DEFINE_SERIALIZABLE(name, scope)

/*
 * Serializable Vector
 */

#define DEFINE_SERIALIZABLE_VECTOR(name, child, scope)         \
DEFINE_VECTOR(name, child, scope)                              \
DEFINE_SERIALIZABLE(name, scope)                               \
                                                               \
scope size_t                                                   \
name ## _size(const name ## _t *x) {                           \
  size_t size = 0;                                             \
  size_t i;                                                    \
                                                               \
  size += btc_size_size(x->length);                            \
                                                               \
  for (i = 0; i < x->length; i++)                              \
    size += child ## _size(x->items[i]);                       \
                                                               \
  return size;                                                 \
}                                                              \
                                                               \
scope uint8_t *                                                \
name ## _write(uint8_t *zp, const name ## _t *x) {             \
  size_t i;                                                    \
                                                               \
  zp = btc_size_write(zp, x->length);                          \
                                                               \
  for (i = 0; i < x->length; i++)                              \
    zp = child ## _write(zp, x->items[i]);                     \
                                                               \
  return zp;                                                   \
}                                                              \
                                                               \
scope int                                                      \
name ## _read(name ## _t *z, const uint8_t **xp, size_t *xn) { \
  child ## _t *item;                                           \
  size_t i, count;                                             \
                                                               \
  if (!btc_size_read(&count, xp, xn))                          \
    return 0;                                                  \
                                                               \
  for (i = 0; i < count; i++) {                                \
    item = child ## _create();                                 \
                                                               \
    if (!child ## _read(item, xp, xn)) {                       \
      child ## _destroy(item);                                 \
      return 0;                                                \
    }                                                          \
                                                               \
    name ## _push(z, item);                                    \
  }                                                            \
                                                               \
  return 1;                                                    \
}
