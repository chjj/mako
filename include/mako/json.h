/*!
 * json.h - json functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_JSON_H
#define BTC_JSON_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "json/json_parser.h"
#include "json/json_builder.h"
#include "types.h"

#define json_boolean_get btc_json_boolean_get
#define json_signed_get btc_json_signed_get
#define json_unsigned_get btc_json_unsigned_get
#define json_double_get btc_json_double_get
#define json_object_get btc_json_object_get
#define json_object_pluck btc_json_object_pluck
#define json_encode btc_json_encode
#define json_encode_ex btc_json_encode_ex
#define json_decode btc_json_decode
#define json_decode_ex btc_json_decode_ex
#define json_print btc_json_print
#define json_print_ex btc_json_print_ex

#define json_hash_new btc_json_hash_new
#define json_hash_get btc_json_hash_get
#define json_amount_get btc_json_amount_get
#define json_buffer_new btc_json_buffer_new
#define json_buffer_get btc_json_buffer_get
#define json_address_new btc_json_address_new
#define json_address_get btc_json_address_get
#define json_netaddr_new btc_json_netaddr_new
#define json_netaddr_get btc_json_netaddr_get
#define json_stack_new btc_json_stack_new
#define json_scriptsig_new btc_json_scriptsig_new
#define json_script_new btc_json_script_new
#define json_coin_new btc_json_coin_new
#define json_outpoint_new btc_json_outpoint_new
#define json_input_new btc_json_input_new
#define json_output_new btc_json_output_new
#define json_output_new_ex btc_json_output_new_ex
#define json_tx_new btc_json_tx_new
#define json_tx_new_ex btc_json_tx_new_ex
#define json_header_new btc_json_header_new
#define json_block_new btc_json_block_new
#define json_entry_new btc_json_entry_new
#define json_entry_new_ex btc_json_entry_new_ex
#define json_block_new_ex btc_json_block_new_ex

#define json_tx_base btc_json_tx_base
#define json_tx_raw btc_json_tx_raw
#define json_header_raw btc_json_header_raw
#define json_block_base btc_json_block_base
#define json_block_raw btc_json_block_raw

#ifdef __cplusplus
extern "C" {
#endif

/*
 * JSON Extras
 */

BTC_EXTERN int
json_boolean_get(int *z, const json_value *obj);

BTC_EXTERN int
json_signed_get(int *z, const json_value *obj);

BTC_EXTERN int
json_unsigned_get(int *z, const json_value *obj);

BTC_EXTERN int
json_double_get(double *z, const json_value *obj);

BTC_EXTERN json_value *
json_object_get(const json_value *obj, const char *name);

BTC_EXTERN json_value *
json_object_pluck(json_value *obj, const char *name);

BTC_EXTERN json_char *
json_encode(json_value *value);

BTC_EXTERN json_char *
json_encode_ex(json_value *value, json_serialize_opts opts);

BTC_EXTERN json_value *
json_decode(const json_char *json, size_t length);

BTC_EXTERN json_value *
json_decode_ex(json_settings *settings,
               const json_char *json,
               size_t length,
               char *error_buf);

BTC_EXTERN void
json_print(json_value *value, int (*json_puts)(const char *));

BTC_EXTERN void
json_print_ex(json_value *value,
              int (*json_puts)(const char *),
              json_serialize_opts opts);

/*
 * JSON Objects
 */

BTC_EXTERN json_value *
json_hash_new(const uint8_t *hash);

BTC_EXTERN int
json_hash_get(uint8_t *hash, const json_value *obj);

BTC_EXTERN int
json_amount_get(int64_t *z, const json_value *obj);

BTC_EXTERN json_value *
json_buffer_new(const btc_buffer_t *item);

BTC_EXTERN int
json_buffer_get(btc_buffer_t *item, const json_value *obj);

BTC_EXTERN json_value *
json_address_new(const btc_address_t *addr, const btc_network_t *network);

BTC_EXTERN int
json_address_get(btc_address_t *addr,
                 const json_value *obj,
                 const btc_network_t *network);

BTC_EXTERN json_value *
json_netaddr_new(const btc_netaddr_t *addr);

BTC_EXTERN int
json_netaddr_get(btc_netaddr_t *addr, const json_value *obj);

BTC_EXTERN json_value *
json_stack_new(const btc_stack_t *stack);

BTC_EXTERN json_value *
json_scriptsig_new(const btc_script_t *script);

BTC_EXTERN json_value *
json_script_new(const btc_script_t *script, const btc_network_t *network);

BTC_EXTERN json_value *
json_coin_new(const btc_coin_t *coin, const btc_network_t *network);

BTC_EXTERN json_value *
json_outpoint_new(const btc_outpoint_t *outpoint);

BTC_EXTERN json_value *
json_input_new(const btc_input_t *input,
               const btc_view_t *view,
               const btc_network_t *network);

BTC_EXTERN json_value *
json_output_new(const btc_output_t *output,
                const btc_network_t *network);

BTC_EXTERN json_value *
json_output_new_ex(const btc_output_t *output,
                   size_t index,
                   const btc_network_t *network);

BTC_EXTERN json_value *
json_tx_new(const btc_tx_t *tx,
            const btc_view_t *view,
            const btc_network_t *network);

BTC_EXTERN json_value *
json_tx_new_ex(const btc_tx_t *tx,
               const btc_view_t *view,
               const uint8_t *block,
               int include_hex,
               const btc_network_t *network);

BTC_EXTERN json_value *
json_header_new(const btc_header_t *hdr);

BTC_EXTERN json_value *
json_block_new(const btc_block_t *block,
               const btc_view_t *view,
               const btc_network_t *network);

BTC_EXTERN json_value *
json_entry_new(const btc_entry_t *entry);

BTC_EXTERN json_value *
json_entry_new_ex(const btc_entry_t *entry,
                  int confirmations,
                  const uint8_t *next);

BTC_EXTERN json_value *
json_block_new_ex(const btc_block_t *block,
                  const btc_entry_t *entry,
                  const btc_view_t *view,
                  int confirmations,
                  const uint8_t *next,
                  int details,
                  const btc_network_t *network);

/*
 * Hexification
 */

BTC_EXTERN json_value *
json_tx_base(const btc_tx_t *tx);

BTC_EXTERN json_value *
json_tx_raw(const btc_tx_t *tx);

BTC_EXTERN json_value *
json_header_raw(const btc_header_t *hdr);

BTC_EXTERN json_value *
json_block_base(const btc_block_t *block);

BTC_EXTERN json_value *
json_block_raw(const btc_block_t *block);

#ifdef __cplusplus
}
#endif

#endif /* BTC_JSON_H */
