/*!
 * types.h - types for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_TYPES_H
#define BTC_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"

/*
 * Types
 */

typedef struct btc_buffer_s {
  uint8_t *data;
  size_t alloc;
  size_t length;
} btc_buffer_t;

typedef struct btc_stack_s {
  btc_buffer_t **items;
  size_t alloc;
  size_t length;
} btc_stack_t;

typedef struct btc_opcode_s {
  int value;
  const uint8_t *data;
  size_t length;
} btc_opcode_t;

typedef btc_buffer_t btc_script_t;

typedef struct btc_reader_s {
  const uint8_t *data;
  size_t length;
  int ip;
} btc_reader_t;

typedef struct btc_writer_s {
  btc_opcode_t **items;
  size_t alloc;
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
  uint8_t data[40];
  size_t length;
} btc_program_t;

typedef struct btc_inpvec_s {
  btc_input_t **items;
  size_t alloc;
  size_t length;
} btc_inpvec_t;

typedef struct btc_outvec_s {
  btc_output_t **items;
  size_t alloc;
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
  size_t alloc;
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
  size_t alloc;
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

struct btc_view_s;
typedef struct btc_view_s btc_view_t;

struct sha256_s;
typedef struct sha256_s btc_hash256_t;

#endif /* BTC_TYPES_H */
