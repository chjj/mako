/*!
 * json.c - json functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/address.h>
#include <mako/block.h>
#include <mako/coins.h>
#include <mako/consensus.h>
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
 * JSON Objects
 */

json_value *
json_raw_new(const uint8_t *xp, size_t xn) {
  char *zp = btc_malloc(xn * 2 + 1);

  btc_base16_encode(zp, xp, xn);

  return json_string_new_nocopy(xn * 2, zp);
}

int
json_raw_get(uint8_t *zp, size_t *zn, const json_value *obj) {
  const char *ptr;
  size_t len;

  if (obj->type != json_string)
    return 0;

  ptr = obj->u.string.ptr;
  len = obj->u.string.length;

  if ((len & 1) || (len >> 1) > *zn)
    return 0;

  if (!btc_base16_decode(zp, ptr, len))
    return 0;

  *zn = len / 2;

  return 1;
}

json_value *
json_hash_new(const uint8_t *hash) {
  char str[64 + 1];

  if (hash == NULL)
    return json_null_new();

  btc_hash_export(str, hash);

  return json_string_new_length(64, str);
}

int
json_hash_get(uint8_t *hash, const json_value *obj) {
  if (obj->type != json_string)
    return 0;

  if (obj->u.string.length != 64)
    return 0;

  return btc_base16le_decode(hash, obj->u.string.ptr, 64);
}

int
json_amount_get(int64_t *z, const json_value *obj) {
  if (obj->type == json_amount) {
    int64_t x = obj->u.integer;

    if (x < 0 || x > BTC_MAX_MONEY)
      return 0;

    *z = x;

    return 1;
  }

  if (obj->type == json_integer) {
    int64_t x = obj->u.integer;

    if (x < 0 || x > (BTC_MAX_MONEY / BTC_COIN))
      return 0;

    *z = x * BTC_COIN;

    return 1;
  }

  if (obj->type == json_double) {
    int64_t x;

    if (!btc_amount_from_double(&x, obj->u.dbl))
      return 0;

    if (x < 0)
      return 0;

    *z = x;

    return 1;
  }

  if (obj->type == json_string) {
    int64_t x;

    if (!btc_amount_import(&x, obj->u.string.ptr))
      return 0;

    if (x < 0)
      return 0;

    *z = x;

    return 1;
  }

  return 0;
}

json_value *
json_buffer_new(const btc_buffer_t *item) {
  return json_raw_new(item->data, item->length);
}

int
json_buffer_get(btc_buffer_t *item, const json_value *obj) {
  const char *ptr;
  size_t len;

  if (obj->type != json_string)
    return 0;

  ptr = obj->u.string.ptr;
  len = obj->u.string.length;

  if (len & 1)
    return 0;

  btc_buffer_grow(item, len / 2);

  if (!btc_base16_decode(item->data, ptr, len))
    return 0;

  item->length = len / 2;

  return 1;
}

json_value *
json_address_new(const btc_address_t *addr, const btc_network_t *network) {
  char str[BTC_ADDRESS_MAXLEN + 1];

  btc_address_get_str(str, addr, network);

  return json_string_new(str);
}

int
json_address_get(btc_address_t *addr,
                 const json_value *obj,
                 const btc_network_t *network) {
  if (obj->type != json_string)
    return 0;

  return btc_address_set_str(addr, obj->u.string.ptr, network);
}

json_value *
json_netaddr_new(const btc_netaddr_t *addr) {
  char str[BTC_ADDRSTRLEN + 1];

  btc_netaddr_get_str(str, addr);

  return json_string_new(str);
}

int
json_netaddr_get(btc_netaddr_t *addr, const json_value *obj) {
  if (obj->type != json_string)
    return 0;

  return btc_netaddr_set_str(addr, obj->u.string.ptr);
}

json_value *
json_stack_new(const btc_stack_t *stack) {
  json_value *obj = json_array_new(stack->length);
  size_t i;

  for (i = 0; i < stack->length; i++)
    json_array_push(obj, json_buffer_new(stack->items[i]));

  return obj;
}

static json_value *
json_script_type_new(const btc_script_t *script) {
  if (btc_script_is_p2pk(script))
    return json_string_new("pubkey");

  if (btc_script_is_p2pkh(script))
    return json_string_new("pubkeyhash");

  if (btc_script_is_p2sh(script))
    return json_string_new("scripthash");

  if (btc_script_is_multisig(script))
    return json_string_new("multisig");

  if (btc_script_is_nulldata(script))
    return json_string_new("nulldata");

  if (btc_script_is_p2wpkh(script))
    return json_string_new("witness_v0_keyhash");

  if (btc_script_is_p2wsh(script))
    return json_string_new("witness_v0_scripthash");

  if (btc_script_is_program(script))
    return json_string_new("witness_unknown");

  return json_string_new("nonstandard");
}

static json_value *
json_script_asm_new(const btc_script_t *script) {
  char *str = btc_script_asm(script);
  size_t len = strlen(str);

  return json_string_new_nocopy(len, str);
}

json_value *
json_scriptsig_new(const btc_script_t *script) {
  json_value *obj = json_object_new(2);

  json_object_push(obj, "asm", json_script_asm_new(script));
  json_object_push(obj, "hex", json_buffer_new(script));

  return obj;
}

json_value *
json_script_new(const btc_script_t *script, const btc_network_t *network) {
  btc_address_t addr;
  size_t length = 3;
  int has_addr = 0;
  json_value *obj;

  if (btc_address_set_script(&addr, script)) {
    has_addr = 1;
    length += 1;
  }

  obj = json_object_new(length);

  json_object_push(obj, "asm", json_script_asm_new(script));
  json_object_push(obj, "hex", json_buffer_new(script));

  if (has_addr)
    json_object_push(obj, "address", json_address_new(&addr, network));

  json_object_push(obj, "type", json_script_type_new(script));

  return obj;
}

json_value *
json_coin_new(const btc_coin_t *coin, const btc_network_t *network) {
  json_value *obj = json_object_new(4);

  json_object_push(obj, "generated", json_boolean_new(coin->coinbase));
  json_object_push(obj, "height", json_integer_new(coin->height));
  json_object_push(obj, "value", json_amount_new(coin->output.value));
  json_object_push(obj, "scriptPubKey", json_script_new(&coin->output.script,
                                                        network));

  return obj;
}

json_value *
json_outpoint_new(const btc_outpoint_t *outpoint) {
  json_value *obj = json_object_new(2);

  json_object_push(obj, "txid", json_hash_new(outpoint->hash));
  json_object_push(obj, "vout", json_integer_new(outpoint->index));

  return obj;
}

int
json_outpoint_get(btc_outpoint_t *outpoint, const json_value *obj) {
  const json_value *txid, *vout;
  int index;

  if (obj->type != json_object)
    return 0;

  if (obj->u.object.length > 3)
    return 0;

  txid = json_object_get(obj, "txid");
  vout = json_object_get(obj, "vout");

  if (txid == NULL || vout == NULL)
    return 0;

  if (!json_hash_get(outpoint->hash, txid))
    return 0;

  if (!json_unsigned_get(&index, vout))
    return 0;

  outpoint->index = index;

  return 1;
}

json_value *
json_input_new(const btc_input_t *input,
               const btc_view_t *view,
               const btc_network_t *network) {
  const btc_coin_t *coin = NULL;
  size_t length = 0;
  json_value *obj;

  if (view != NULL)
    coin = btc_view_get(view, &input->prevout);

  if (btc_outpoint_is_null(&input->prevout))
    length += 1;
  else
    length += 3;

  if (input->witness.length > 0)
    length += 1;

  if (coin != NULL)
    length += 1;

  length += 1;

  obj = json_object_new(length);

  if (btc_outpoint_is_null(&input->prevout)) {
    json_object_push(obj, "coinbase", json_buffer_new(&input->script));
  } else {
    json_object_push(obj, "txid", json_hash_new(input->prevout.hash));
    json_object_push(obj, "vout", json_integer_new(input->prevout.index));
    json_object_push(obj, "scriptSig", json_scriptsig_new(&input->script));
  }

  if (input->witness.length > 0)
    json_object_push(obj, "txinwitness", json_stack_new(&input->witness));

  if (coin != NULL)
    json_object_push(obj, "prevout", json_coin_new(coin, network));

  json_object_push(obj, "sequence", json_integer_new(input->sequence));

  return obj;
}

json_value *
json_output_new(const btc_output_t *output, const btc_network_t *network) {
  json_value *obj = json_object_new(2 + 1);

  json_object_push(obj, "value", json_amount_new(output->value));
  json_object_push(obj, "scriptPubKey", json_script_new(&output->script,
                                                        network));

  return obj;
}

json_value *
json_output_new_ex(const btc_output_t *output,
                   size_t index,
                   const btc_network_t *network) {
  json_value *obj = json_output_new(output, network);
  json_object_push(obj, "n", json_integer_new(index));
  return obj;
}

json_value *
json_tx_new(const btc_tx_t *tx,
            const btc_view_t *view,
            const btc_network_t *network) {
  json_value *obj = json_object_new(10 + 2);
  json_value *vin, *vout;
  size_t base = btc_tx_base_size(tx);
  size_t wit = btc_tx_witness_size(tx);
  size_t size = base + wit;
  size_t weight = (base * BTC_WITNESS_SCALE_FACTOR) + wit;
  size_t vsize = weight;
  size_t i;

  vsize += (BTC_WITNESS_SCALE_FACTOR - 1);
  vsize /= BTC_WITNESS_SCALE_FACTOR;

  json_object_push(obj, "txid", json_hash_new(tx->hash));
  json_object_push(obj, "hash", json_hash_new(tx->whash));
  json_object_push(obj, "version", json_integer_new(tx->version));
  json_object_push(obj, "size", json_integer_new(size));
  json_object_push(obj, "vsize", json_integer_new(vsize));
  json_object_push(obj, "weight", json_integer_new(weight));
  json_object_push(obj, "locktime", json_integer_new(tx->locktime));

  if (view != NULL) {
    int64_t fee = btc_tx_fee(tx, view);

    if (fee != -1)
      json_object_push(obj, "fee", json_amount_new(fee));
  }

  vin = json_array_new(tx->inputs.length);

  for (i = 0; i < tx->inputs.length; i++)
    json_array_push(vin, json_input_new(tx->inputs.items[i], view, network));

  json_object_push(obj, "vin", vin);

  vout = json_array_new(tx->outputs.length);

  for (i = 0; i < tx->outputs.length; i++)
    json_array_push(vout, json_output_new_ex(tx->outputs.items[i], i, network));

  json_object_push(obj, "vout", vout);

  return obj;
}

json_value *
json_tx_new_ex(const btc_tx_t *tx,
               const btc_view_t *view,
               const uint8_t *block,
               int include_hex,
               const btc_network_t *network) {
  json_value *obj = json_tx_new(tx, view, network);

  if (block != NULL)
    json_object_push(obj, "blockhash", json_hash_new(block));

  if (include_hex)
    json_object_push(obj, "hex", json_tx_raw(tx));

  return obj;
}

json_value *
json_header_new(const btc_header_t *hdr) {
  json_value *obj = json_object_new(7 + 5);
  uint8_t hash[32];

  btc_header_hash(hash, hdr);

  json_object_push(obj, "hash", json_hash_new(hash));
  json_object_push(obj, "version", json_integer_new(hdr->version));
  json_object_push(obj, "previousblockhash", json_hash_new(hdr->prev_block));
  json_object_push(obj, "merkleroot", json_hash_new(hdr->merkle_root));
  json_object_push(obj, "time", json_integer_new(hdr->time));
  json_object_push(obj, "bits", json_integer_new(hdr->bits));
  json_object_push(obj, "nonce", json_integer_new(hdr->nonce));

  return obj;
}

json_value *
json_block_new(const btc_block_t *block,
               const btc_view_t *view,
               const btc_network_t *network) {
  json_value *obj = json_header_new(&block->header);
  json_value *txs = json_array_new(block->txs.length);
  size_t base = btc_block_base_size(block);
  size_t wit = btc_block_witness_size(block);
  size_t size = base + wit;
  size_t weight = (base * BTC_WITNESS_SCALE_FACTOR) + wit;
  size_t i;

  json_object_push(obj, "strippedsize", json_integer_new(base));
  json_object_push(obj, "size", json_integer_new(size));
  json_object_push(obj, "weight", json_integer_new(weight));
  json_object_push(obj, "nTx", json_integer_new(block->txs.length));

  for (i = 0; i < block->txs.length; i++)
    json_array_push(txs, json_tx_new(block->txs.items[i], view, network));

  json_object_push(obj, "tx", txs);

  return obj;
}

json_value *
json_entry_new(const btc_entry_t *entry) {
  json_value *obj = json_object_new(10 + 4 + 5);
  const btc_header_t *hdr = &entry->header;

  json_object_push(obj, "hash", json_hash_new(entry->hash));
  json_object_push(obj, "height", json_integer_new(entry->height));
  json_object_push(obj, "version", json_integer_new(hdr->version));
  json_object_push(obj, "previousblockhash", json_hash_new(hdr->prev_block));
  json_object_push(obj, "merkleroot", json_hash_new(hdr->merkle_root));
  json_object_push(obj, "time", json_integer_new(hdr->time));
  json_object_push(obj, "bits", json_integer_new(hdr->bits));
  json_object_push(obj, "nonce", json_integer_new(hdr->nonce));
  json_object_push(obj, "chainwork", json_hash_new(entry->chainwork));

  return obj;
}

json_value *
json_entry_new_ex(const btc_entry_t *entry,
                  int confirmations,
                  const uint8_t *next) {
  json_value *obj = json_entry_new(entry);
  int64_t mtp = btc_entry_median_time(entry);
  double diff = btc_difficulty(entry->header.bits);

  json_object_push(obj, "mediantime", json_integer_new(mtp));
  json_object_push(obj, "difficulty", json_double_new(diff));
  json_object_push(obj, "confirmations", json_integer_new(confirmations));
  json_object_push(obj, "nextblockhash", json_hash_new(next));

  return obj;
}

json_value *
json_block_new_ex(const btc_block_t *block,
                  const btc_entry_t *entry,
                  const btc_view_t *view,
                  int confirmations,
                  const uint8_t *next,
                  int details,
                  const btc_network_t *network) {
  json_value *obj = json_entry_new_ex(entry, confirmations, next);
  json_value *txs = json_array_new(block->txs.length);
  size_t base = btc_block_base_size(block);
  size_t wit = btc_block_witness_size(block);
  size_t size = base + wit;
  size_t weight = (base * BTC_WITNESS_SCALE_FACTOR) + wit;
  size_t i;

  json_object_push(obj, "strippedsize", json_integer_new(base));
  json_object_push(obj, "size", json_integer_new(size));
  json_object_push(obj, "weight", json_integer_new(weight));
  json_object_push(obj, "nTx", json_integer_new(block->txs.length));

  if (details) {
    for (i = 0; i < block->txs.length; i++)
      json_array_push(txs, json_tx_new(block->txs.items[i], view, network));
  } else {
    for (i = 0; i < block->txs.length; i++)
      json_array_push(txs, json_hash_new(block->txs.items[i]->hash));
  }

  json_object_push(obj, "tx", txs);

  return obj;
}

/*
 * Hexification
 */

json_value *
json_tx_base(const btc_tx_t *tx) {
  size_t size = btc_tx_base_size(tx);
  uint8_t *raw = btc_malloc(size);
  char *str = btc_malloc(size * 2 + 1);

  btc_tx_base_write(raw, tx);
  btc_base16_encode(str, raw, size);
  btc_free(raw);

  return json_string_new_nocopy(size * 2, str);
}

int
json_tx_base_get(btc_tx_t **tx, const json_value *obj) {
  btc_buffer_t tmp;

  btc_buffer_init(&tmp);

  if (json_buffer_get(&tmp, obj))
    *tx = btc_tx_base_decode(tmp.data, tmp.length);
  else
    *tx = NULL;

  btc_buffer_clear(&tmp);

  return *tx != NULL;
}

json_value *
json_tx_raw(const btc_tx_t *tx) {
  size_t size = btc_tx_size(tx);
  uint8_t *raw = btc_malloc(size);
  char *str = btc_malloc(size * 2 + 1);

  btc_tx_write(raw, tx);
  btc_base16_encode(str, raw, size);
  btc_free(raw);

  return json_string_new_nocopy(size * 2, str);
}

int
json_tx_get(btc_tx_t **tx, const json_value *obj) {
  btc_buffer_t tmp;

  btc_buffer_init(&tmp);

  if (json_buffer_get(&tmp, obj))
    *tx = btc_tx_decode(tmp.data, tmp.length);
  else
    *tx = NULL;

  btc_buffer_clear(&tmp);

  return *tx != NULL;
}

json_value *
json_header_raw(const btc_header_t *hdr) {
  char str[80 * 2 + 1];
  uint8_t raw[80];

  btc_header_write(raw, hdr);
  btc_base16_encode(str, raw, 80);

  return json_string_new_length(80 * 2, str);
}

int
json_header_get(btc_header_t *hdr, const json_value *obj) {
  btc_buffer_t tmp;
  int ret = 0;

  btc_buffer_init(&tmp);

  if (json_buffer_get(&tmp, obj))
    ret = btc_header_import(hdr, tmp.data, tmp.length);

  btc_buffer_clear(&tmp);

  return ret;
}

json_value *
json_block_base(const btc_block_t *block) {
  size_t size = btc_block_base_size(block);
  uint8_t *raw = btc_malloc(size);
  char *str = btc_malloc(size * 2 + 1);

  btc_block_base_write(raw, block);
  btc_base16_encode(str, raw, size);
  btc_free(raw);

  return json_string_new_nocopy(size * 2, str);
}

json_value *
json_block_raw(const btc_block_t *block) {
  size_t size = btc_block_size(block);
  uint8_t *raw = btc_malloc(size);
  char *str = btc_malloc(size * 2 + 1);

  btc_block_write(raw, block);
  btc_base16_encode(str, raw, size);
  btc_free(raw);

  return json_string_new_nocopy(size * 2, str);
}

int
json_block_get(btc_block_t **block, const json_value *obj) {
  btc_buffer_t tmp;

  btc_buffer_init(&tmp);

  if (json_buffer_get(&tmp, obj))
    *block = btc_block_decode(tmp.data, tmp.length);
  else
    *block = NULL;

  btc_buffer_clear(&tmp);

  return *block != NULL;
}
