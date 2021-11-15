/*!
 * inspect.c - inspect functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mako/address.h>
#include <mako/block.h>
#include <mako/buffer.h>
#include <mako/coins.h>
#include <mako/encoding.h>
#include <mako/entry.h>
#include <mako/header.h>
#include <mako/json.h>
#include <mako/netaddr.h>
#include <mako/network.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>

#include "internal.h"

/*
 * JSON Options
 */

static const json_serialize_opts json_options = {
  json_serialize_mode_multiline,
  json_serialize_opt_pack_brackets,
  2
};

/*
 * Inspect
 */

void
btc_hash_inspect(const uint8_t *xp) {
  char zp[64 + 1];

  btc_hash_export(zp, xp);

  puts(zp);
}

void
btc_amount_inspect(int64_t x) {
  char zp[BTC_AMOUNT_LEN + 1];

  btc_amount_export(zp, x);

  puts(zp);
}

void
btc_buffer_inspect(const btc_buffer_t *item) {
  char *zp = btc_malloc(item->length * 2 + 1);

  btc_base16_encode(zp, item->data, item->length);

  puts(zp);
  free(zp);
}

void
btc_address_inspect(const btc_address_t *addr, const btc_network_t *network) {
  char zp[BTC_ADDRESS_MAXLEN + 1];

  btc_address_get_str(zp, addr, network);

  puts(zp);
}

void
btc_stack_inspect(const btc_stack_t *stack) {
  json_value *obj = json_stack_new(stack);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_scriptsig_inspect(const btc_script_t *script) {
  json_value *obj = json_scriptsig_new(script);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_script_inspect(const btc_script_t *script, const btc_network_t *network) {
  json_value *obj = json_script_new(script, network);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_coin_inspect(const btc_coin_t *coin, const btc_network_t *network) {
  json_value *obj = json_coin_new(coin, network);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_outpoint_inspect(const btc_outpoint_t *outpoint) {
  json_value *obj = json_outpoint_new(outpoint);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_input_inspect(const btc_input_t *input,
                  const btc_view_t *view,
                  const btc_network_t *network) {
  json_value *obj = json_input_new(input, view, network);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_output_inspect(const btc_output_t *output, const btc_network_t *network) {
  json_value *obj = json_output_new(output, network);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_tx_inspect(const btc_tx_t *tx,
               const btc_view_t *view,
               const btc_network_t *network) {
  json_value *obj = json_tx_new(tx, view, network);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_header_inspect(const btc_header_t *hdr) {
  json_value *obj = json_header_new(hdr);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_block_inspect(const btc_block_t *block,
                  const btc_view_t *view,
                  const btc_network_t *network) {
  json_value *obj = json_block_new(block, view, network);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}

void
btc_entry_inspect(const btc_entry_t *entry) {
  json_value *obj = json_entry_new(entry);
  json_print_ex(obj, puts, json_options);
  json_builder_free(obj);
}
