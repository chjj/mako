/*!
 * t-address.c - address tests for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/address.h>
#include <mako/network.h>
#include <mako/script.h>
#include <mako/util.h>
#include "lib/tests.h"

/*
 * Vectors
 */

static const struct addr_vector {
  btc_address_t data;
  const char *expect;
  enum btc_network_type network;
} addr_vectors[] = {
  {
    {
      BTC_ADDRESS_P2PKH,
      0,
      {
        0xe3, 0x4c, 0xce, 0x70, 0xc8, 0x63, 0x73, 0x27, 0x3e, 0xfc,
        0xc5, 0x4c, 0xe7, 0xd2, 0xa4, 0x91, 0xbb, 0x4a, 0x0e, 0x84
      },
      20
    },
    "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX",
    BTC_NETWORK_MAINNET
  },
  {
    {
      BTC_ADDRESS_P2PKH,
      0,
      {
        0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b, 0xf4,
        0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad, 0xaa
      },
      20
    },
    "12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG",
    BTC_NETWORK_MAINNET
  },
  {
    {
      BTC_ADDRESS_P2PKH,
      0,
      {
        0x78, 0xb3, 0x16, 0xa0, 0x86, 0x47, 0xd5, 0xb7, 0x72, 0x83,
        0xe5, 0x12, 0xd3, 0x60, 0x3f, 0x1f, 0x1c, 0x8d, 0xe6, 0x8f
      },
      20
    },
    "mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
    BTC_NETWORK_TESTNET
  },
  {
    {
      BTC_ADDRESS_P2SH,
      0,
      {
        0xf8, 0x15, 0xb0, 0x36, 0xd9, 0xbb, 0xbc, 0xe5, 0xe9, 0xf2,
        0xa0, 0x0a, 0xbd, 0x1b, 0xf3, 0xdc, 0x91, 0xe9, 0x55, 0x10
      },
      20
    },
    "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
    BTC_NETWORK_MAINNET
  },
  {
    {
      BTC_ADDRESS_P2SH,
      0,
      {
        0xe8, 0xc3, 0x00, 0xc8, 0x79, 0x86, 0xef, 0xa8, 0x4c, 0x37,
        0xc0, 0x51, 0x99, 0x29, 0x01, 0x9e, 0xf8, 0x6e, 0xb5, 0xb4
      },
      20
    },
    "3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8",
    BTC_NETWORK_MAINNET
  },
  {
    {
      BTC_ADDRESS_P2SH,
      0,
      {
        0xc5, 0x79, 0x34, 0x2c, 0x2c, 0x4c, 0x92, 0x20, 0x20, 0x5e,
        0x2c, 0xdc, 0x28, 0x56, 0x17, 0x04, 0x0c, 0x92, 0x4a, 0x0a
      },
      20
    },
    "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
    BTC_NETWORK_TESTNET
  },
  {
    {
      BTC_ADDRESS_WITNESS,
      0,
      {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
      },
      20
    },
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    BTC_NETWORK_MAINNET
  },
  {
    {
      BTC_ADDRESS_WITNESS,
      0,
      {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
      },
      20
    },
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    BTC_NETWORK_TESTNET
  },
  {
    {
      BTC_ADDRESS_WITNESS,
      0,
      {
        0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68,
        0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
        0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
        0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62
      },
      32
    },
    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
    BTC_NETWORK_MAINNET
  },
  {
    {
      BTC_ADDRESS_WITNESS,
      0,
      {
        0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68,
        0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
        0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
        0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62
      },
      32
    },
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
    BTC_NETWORK_TESTNET
  },
  {
    {
      BTC_ADDRESS_WITNESS,
      0,
      {
        0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
        0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
        0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
        0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33
      },
      32
    },
    "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
    BTC_NETWORK_TESTNET
  }
};

static const char *invalid_vectors[] = {
  "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", /* invalid hrp */
  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", /* invalid checksum */
  "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", /* invalid version */
  "bc1rw5uspcuh", /* invalid program length */
  ("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw5" /* invalid program length */
   "08d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90"),
  "tb1pw508d6qejxtdg4y5r3zarqfsj6c3", /* invalid program length */
  ("tb1qrp33g0q5c5txsp9arysrx4k6zdk" /* mixed case */
   "fs4nce4xj0gdcccefvpysxf3q0sL5k7"),
  "tb1pw508d6qejxtdg4y5r3zarqfsj6c3", /* zero padding of more than 4 bits */
  ("tb1qrp33g0q5c5txsp9arysrx4k6zdk" /* non-zero padding in 8-to-5 conversion */
   "fs4nce4xj0gdcccefvpysxf3pjxtptv")
};

/*
 * Tests
 */

static void
test_valid(void) {
  char str[BTC_ADDRESS_MAXLEN + 1];
  btc_program_t program;
  btc_script_t script;
  btc_address_t addr;
  size_t i;

  for (i = 0; i < lengthof(addr_vectors); i++) {
    const struct addr_vector *item = &addr_vectors[i];
    const btc_network_t *network = btc_mainnet;

    if (item->network == BTC_NETWORK_TESTNET)
      network = btc_testnet;

    switch (item->data.type) {
      case BTC_ADDRESS_P2PKH:
        btc_address_set_p2pkh(&addr, item->data.hash);
        ASSERT(btc_address_is_p2pkh(&addr));
        break;
      case BTC_ADDRESS_P2SH:
        btc_address_set_p2sh(&addr, item->data.hash);
        ASSERT(btc_address_is_p2sh(&addr));
        break;
      case BTC_ADDRESS_WITNESS:
        ASSERT(item->data.version == 0);
        ASSERT(item->data.length == 20 || item->data.length == 32);

        if (item->data.length == 20) {
          btc_address_set_p2wpkh(&addr, item->data.hash);
          ASSERT(btc_address_is_p2wpkh(&addr));
        } else {
          btc_address_set_p2wsh(&addr, item->data.hash);
          ASSERT(btc_address_is_p2wsh(&addr));
        }

        ASSERT(btc_address_is_program(&addr));

        break;
      default:
        ASSERT(0);
        break;
    }

    ASSERT(btc_address_equal(&addr, &item->data));

    btc_address_get_str(str, &addr, network);

    ASSERT(strcmp(str, item->expect) == 0);

    btc_address_clear(&addr);
    btc_address_init(&addr);

    ASSERT(btc_address_set_str(&addr, str, network));
    ASSERT(btc_address_equal(&addr, &item->data));

    btc_script_init(&script);

    btc_address_get_script(&script, &addr);

    switch (item->data.type) {
      case BTC_ADDRESS_P2PKH:
        ASSERT(btc_script_is_p2pkh(&script));
        break;
      case BTC_ADDRESS_P2SH:
        ASSERT(btc_script_is_p2sh(&script));
        break;
      case BTC_ADDRESS_WITNESS:
        ASSERT(btc_script_is_program(&script));

        if (item->data.length == 20)
          ASSERT(btc_script_is_p2wpkh(&script));
        else
          ASSERT(btc_script_is_p2wsh(&script));

        break;
      default:
        ASSERT(0);
        break;
    }

    btc_address_init(&addr);

    ASSERT(btc_address_set_script(&addr, &script));
    ASSERT(btc_address_equal(&addr, &item->data));

    btc_script_clear(&script);

    if (addr.type == BTC_ADDRESS_WITNESS) {
      btc_address_get_program(&program, &addr);

      ASSERT(program.version == addr.version);
      ASSERT(program.length == addr.length);
      ASSERT(memcmp(program.data, addr.hash, addr.length) == 0);

      btc_address_init(&addr);

      ASSERT(btc_address_set_program(&addr, &program));
      ASSERT(btc_address_equal(&addr, &item->data));
    }

    btc_address_init(&addr);

    ASSERT(!btc_address_equal(&addr, &item->data));

    btc_address_copy(&addr, &item->data);

    ASSERT(btc_address_equal(&addr, &item->data));
  }
}

static void
test_invalid(void) {
  size_t i;

  for (i = 0; i < lengthof(invalid_vectors); i++) {
    const char *str = invalid_vectors[i];
    const btc_network_t *network = btc_mainnet;
    btc_address_t addr;

    if (str[0] == 't' && str[1] == 'b')
      network = btc_testnet;

    ASSERT(!btc_address_set_str(&addr, str, network));
  }
}

static void
test_from_script(void) {
  static const uint8_t code[] = {
    0x52, 0x41, 0x04, 0x91, 0xbb, 0xa2, 0x51, 0x09,
    0x12, 0xa5, 0xbd, 0x37, 0xda, 0x1f, 0xb5, 0xb1,
    0x67, 0x30, 0x10, 0xe4, 0x3d, 0x2c, 0x6d, 0x81,
    0x2c, 0x51, 0x4e, 0x91, 0xbf, 0xa9, 0xf2, 0xeb,
    0x12, 0x9e, 0x1c, 0x18, 0x33, 0x29, 0xdb, 0x55,
    0xbd, 0x86, 0x8e, 0x20, 0x9a, 0xac, 0x2f, 0xbc,
    0x02, 0xcb, 0x33, 0xd9, 0x8f, 0xe7, 0x4b, 0xf2,
    0x3f, 0x0c, 0x23, 0x5d, 0x61, 0x26, 0xb1, 0xd8,
    0x33, 0x4f, 0x86, 0x41, 0x04, 0x86, 0x5c, 0x40,
    0x29, 0x3a, 0x68, 0x0c, 0xb9, 0xc0, 0x20, 0xe7,
    0xb1, 0xe1, 0x06, 0xd8, 0xc1, 0x91, 0x6d, 0x3c,
    0xef, 0x99, 0xaa, 0x43, 0x1a, 0x56, 0xd2, 0x53,
    0xe6, 0x92, 0x56, 0xda, 0xc0, 0x9e, 0xf1, 0x22,
    0xb1, 0xa9, 0x86, 0x81, 0x8a, 0x7c, 0xb6, 0x24,
    0x53, 0x2f, 0x06, 0x2c, 0x1d, 0x1f, 0x87, 0x22,
    0x08, 0x48, 0x61, 0xc5, 0xc3, 0x29, 0x1c, 0xcf,
    0xfe, 0xf4, 0xec, 0x68, 0x74, 0x41, 0x04, 0x8d,
    0x24, 0x55, 0xd2, 0x40, 0x3e, 0x08, 0x70, 0x8f,
    0xc1, 0xf5, 0x56, 0x00, 0x2f, 0x1b, 0x6c, 0xd8,
    0x3f, 0x99, 0x2d, 0x08, 0x50, 0x97, 0xf9, 0x97,
    0x4a, 0xb0, 0x8a, 0x28, 0x83, 0x8f, 0x07, 0x89,
    0x6f, 0xba, 0xb0, 0x8f, 0x39, 0x49, 0x5e, 0x15,
    0xfa, 0x6f, 0xad, 0x6e, 0xdb, 0xfb, 0x1e, 0x75,
    0x4e, 0x35, 0xfa, 0x1c, 0x78, 0x44, 0xc4, 0x1f,
    0x32, 0x2a, 0x18, 0x63, 0xd4, 0x62, 0x13, 0x53,
    0xae
  };

  static const char *expect = "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC";

  char str[BTC_ADDRESS_MAXLEN + 1];
  btc_script_t script;
  btc_address_t addr;

  btc_script_init(&script);

  btc_script_set(&script, code, sizeof(code));

  ASSERT(btc_address_set_script(&addr, &script));

  btc_address_get_str(str, &addr, btc_mainnet);

  ASSERT(strcmp(str, expect) == 0);

  btc_script_clear(&script);
}

/*
 * Main
 */

int main(void) {
  test_valid();
  test_invalid();
  test_from_script();
  return 0;
}
