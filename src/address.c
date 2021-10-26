/*!
 * address.c - address for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/address.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/encoding.h>
#include <satoshi/network.h>
#include <satoshi/script.h>
#include <satoshi/util.h>
#include "bio.h"
#include "impl.h"
#include "internal.h"

/*
 * Address
 */

DEFINE_OBJECT(btc_address, SCOPE_EXTERN)

void
btc_address_init(btc_address_t *z) {
  z->type = BTC_ADDRESS_P2PKH;
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

static int
set_base58(btc_address_t *addr, const char *str, const btc_network_t *network) {
  size_t len = btc_strnlen(str, 56);
  enum btc_address_type type;
  uint8_t data[55];

  if (len > sizeof(data))
    return 0;

  if (!btc_base58_decode(data, &len, str, len))
    return 0;

  if (len != 25)
    return 0;

  if (data[0] == network->address.p2pkh)
    type = BTC_ADDRESS_P2PKH;
  else if (data[0] == network->address.p2sh)
    type = BTC_ADDRESS_P2SH;
  else
    return 0;

  if (btc_read32le(data + 21) != btc_checksum(data, 21))
    return 0;

  addr->type = (unsigned int)type;
  addr->version = 0;
  addr->length = 20;

  memcpy(addr->hash, data + 1, 20);
  memset(addr->hash + 20, 0, 20);

  return 1;
}

static int
set_bech32(btc_address_t *addr, const char *str, const btc_network_t *network) {
  const char *expect = network->address.bech32;
  unsigned int version;
  char hrp[83 + 1];
  uint8_t hash[83];
  size_t length;

  memset(hash, 0, 40);

  if (!btc_bech32_decode(hrp, &version, hash, &length, str))
    return 0;

  if (version == 0) {
    if (length != 20 && length != 32)
      return 0;
  }

  if (strcmp(hrp, expect) != 0)
    return 0;

  addr->type = BTC_ADDRESS_WITNESS;
  addr->version = version;
  addr->length = length;

  memcpy(addr->hash, hash, 40);

  return 1;
}

int
btc_address_set_str(btc_address_t *addr,
                    const char *str,
                    const btc_network_t *network) {
  return set_bech32(addr, str, network)
      || set_base58(addr, str, network);
}

void
btc_address_get_str(char *str,
                    const btc_address_t *addr,
                    const btc_network_t *network) {
  switch (addr->type) {
    case BTC_ADDRESS_P2PKH:
    case BTC_ADDRESS_P2SH: {
      uint8_t data[25];

      CHECK(addr->length == 20);

      data[0] = addr->type == BTC_ADDRESS_P2PKH
              ? network->address.p2pkh
              : network->address.p2sh;

      memcpy(data + 1, addr->hash, 20);

      btc_write32le(data + 21, btc_checksum(data, 21));

      btc_base58_encode(str, data, 25);

      break;
    }

    case BTC_ADDRESS_WITNESS: {
      const char *hrp = network->address.bech32;

      CHECK(btc_bech32_encode(str, hrp, addr->version,
                                        addr->hash,
                                        addr->length));

      break;
    }

    default: {
      btc_abort(); /* LCOV_EXCL_LINE */
      break;
    }
  }
}

int
btc_address_set_script(btc_address_t *addr, const btc_script_t *script) {
  btc_program_t program;
  uint8_t pub[65];
  size_t len;

  btc_address_init(addr);

  if (btc_script_get_program(&program, script))
    return btc_address_set_program(addr, &program);

  if (btc_script_get_p2sh(addr->hash, script)) {
    addr->type = BTC_ADDRESS_P2SH;
    return 1;
  }

  if (btc_script_get_p2pkh(addr->hash, script))
    return 1;

  if (btc_script_get_p2pk(pub, &len, script)) {
    btc_hash160(addr->hash, pub, len);
    return 1;
  }

  if (btc_script_is_multisig(script)) {
    addr->type = BTC_ADDRESS_P2SH;
    btc_hash160(addr->hash, script->data, script->length);
    return 1;
  }

  return 0;
}

void
btc_address_get_script(btc_script_t *script, const btc_address_t *addr) {
  switch (addr->type) {
    case BTC_ADDRESS_P2PKH: {
      CHECK(addr->length == 20);
      btc_script_set_p2pkh(script, addr->hash);
      break;
    }

    case BTC_ADDRESS_P2SH: {
      CHECK(addr->length == 20);
      btc_script_set_p2sh(script, addr->hash);
      break;
    }

    case BTC_ADDRESS_WITNESS: {
      btc_program_t program;
      btc_address_get_program(&program, addr);
      btc_script_set_program(script, &program);
      break;
    }

    default: {
      btc_abort(); /* LCOV_EXCL_LINE */
      break;
    }
  }
}

int
btc_address_set_program(btc_address_t *addr, const btc_program_t *program) {
  if (program->version == 0) {
    if (program->length != 20 && program->length != 32)
      return 0;
  }

  addr->type = BTC_ADDRESS_WITNESS;
  addr->version = program->version;
  addr->length = program->length;

  memset(addr->hash, 0, 40);
  memcpy(addr->hash, program->data, program->length);

  return 1;
}

void
btc_address_get_program(btc_program_t *program, const btc_address_t *addr) {
  CHECK(addr->type == BTC_ADDRESS_WITNESS);

  program->version = addr->version;
  program->length = addr->length;

  memset(program->data, 0, 40);
  memcpy(program->data, addr->hash, addr->length);
}
