/*!
 * address.c - address for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/address.h>
#include <satoshi/crypto.h>
#include <satoshi/network.h>
#include <satoshi/script.h>
#include <torsion/encoding.h>
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

int
btc_address_set_str(btc_address_t *addr,
                    const char *str,
                    const btc_network_t *network) {
  const char *expect = network->address.bech32;
  char hrp[BECH32_MAX_HRP_SIZE + 1];
  uint8_t checksum[32];
  uint8_t data[55];
  size_t len;

  btc_address_init(addr);

  if (bech32_decode(hrp, &addr->version, addr->hash, &addr->length, str)) {
    if (addr->version > 16)
      return 0;

    if (addr->version == 0) {
      if (addr->length != 20 && addr->length != 32)
        return 0;
    }

    if (strcmp(hrp, expect) != 0)
      return 0;

    addr->type = BTC_ADDRESS_WITNESS;

    return 1;
  }

  len = strlen(str);

  if (len > sizeof(data))
    return 0;

  if (!base58_decode(data, &len, str, len))
    return 0;

  if (len != 25)
    return 0;

  if (data[0] == network->address.p2pkh)
    addr->type = BTC_ADDRESS_P2PKH;
  else if (data[0] == network->address.p2sh)
    addr->type = BTC_ADDRESS_P2SH;
  else
    return 0;

  addr->version = 0;

  memcpy(addr->hash, data + 1, 20);

  btc_hash256(checksum, data, 21);

  return memcmp(data + 21, checksum, 4) == 0;
}

void
btc_address_get_str(char *str,
                    const btc_address_t *addr,
                    const btc_network_t *network) {
  switch (addr->type) {
    case BTC_ADDRESS_P2PKH:
    case BTC_ADDRESS_P2SH: {
      uint8_t checksum[32];
      uint8_t data[25];

      CHECK(addr->length == 20);

      data[0] = addr->type == BTC_ADDRESS_P2PKH
              ? network->address.p2pkh
              : network->address.p2sh;

      memcpy(data + 1, addr->hash, 20);

      btc_hash256(checksum, data, 21);

      memcpy(data + 21, checksum, 4);

      CHECK(base58_encode(str, NULL, data, 25));

      break;
    }

    case BTC_ADDRESS_WITNESS: {
      const char *hrp = network->address.bech32;
      CHECK(bech32_encode(str, hrp, addr->version, addr->hash, addr->length));
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
  btc_address_init(addr);

  if (program->version == 0) {
    if (program->length != 20 && program->length != 32)
      return 0;
  }

  addr->type = BTC_ADDRESS_WITNESS;
  addr->version = program->version;
  addr->length = program->length;

  memcpy(addr->hash, program->data, program->length);

  return 1;
}

void
btc_address_get_program(btc_program_t *program, const btc_address_t *addr) {
  CHECK(addr->type == BTC_ADDRESS_WITNESS);

  program->version = addr->version;
  program->length = addr->length;

  memcpy(program->data, addr->hash, addr->length);
}
