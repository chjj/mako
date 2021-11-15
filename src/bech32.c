/*!
 * bech32.c - bech32 encoding for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 *
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 *   https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
 *   https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/encoding.h>
#include "internal.h"

/*
 * Bech32
 */

static const char *bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t bech32_table[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,
   7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1
};

static uint32_t
bech32_polymod(uint32_t c) {
  uint32_t b = c >> 25;

  return ((c & UINT32_C(0x1ffffff)) << 5)
    ^ (UINT32_C(0x3b6a57b2) & -((b >> 0) & 1))
    ^ (UINT32_C(0x26508e6d) & -((b >> 1) & 1))
    ^ (UINT32_C(0x1ea119fa) & -((b >> 2) & 1))
    ^ (UINT32_C(0x3d4233dd) & -((b >> 3) & 1))
    ^ (UINT32_C(0x2a1462b3) & -((b >> 4) & 1));
}

static int
bech32_serialize(char *str,
                 const char *hrp,
                 const uint8_t *data,
                 size_t data_len) {
  uint32_t chk = 1;
  size_t i, hlen;
  size_t j = 0;
  int ch;

  for (hlen = 0; hlen < 83; hlen++) {
    ch = hrp[hlen];

    if (ch == '\0')
      break;

    if (ch < '!' || ch > '~')
      return 0;

    if (ch >= 'A' && ch <= 'Z')
      return 0;

    chk = bech32_polymod(chk) ^ (ch >> 5);
  }

  if (hlen == 0 || hrp[hlen] != '\0')
    return 0;

  if (hlen + 1 + data_len + 6 > 90)
    return 0;

  chk = bech32_polymod(chk);

  for (i = 0; i < hlen; i++) {
    ch = hrp[i];

    chk = bech32_polymod(chk) ^ (ch & 0x1f);

    str[j++] = ch;
  }

  str[j++] = '1';

  for (i = 0; i < data_len; i++) {
    ch = data[i];

    if (ch >> 5)
      return 0;

    chk = bech32_polymod(chk) ^ ch;

    str[j++] = bech32_charset[ch];
  }

  for (i = 0; i < 6; i++)
    chk = bech32_polymod(chk);

  chk ^= 1;

  for (i = 0; i < 6; i++)
    str[j++] = bech32_charset[(chk >> ((5 - i) * 5)) & 0x1f];

  str[j] = '\0';

  return 1;
}

static int
bech32_deserialize(char *hrp,
                   uint8_t *data,
                   size_t *data_len,
                   const char *str) {
  uint32_t chk = 1;
  size_t hlen = 0;
  size_t i, slen;
  int lower = 0;
  int upper = 0;
  size_t j = 0;
  int ch;

  for (slen = 0; slen < 90; slen++) {
    ch = str[slen];

    if (ch == '\0')
      break;

    if (ch < '!' || ch > '~')
      return 0;

    if (ch >= 'a' && ch <= 'z')
      lower = 1;
    else if (ch >= 'A' && ch <= 'Z')
      upper = 1;
    else if (ch == '1')
      hlen = slen;
  }

  if (slen < 8 || str[slen] != '\0')
    return 0;

  if (hlen == 0)
    return 0;

  if (slen - (hlen + 1) < 6)
    return 0;

  if (lower && upper)
    return 0;

  for (i = 0; i < hlen; i++) {
    ch = str[i];

    if (ch >= 'A' && ch <= 'Z')
      ch += 32;

    chk = bech32_polymod(chk) ^ (ch >> 5);

    hrp[i] = ch;
  }

  hrp[i] = '\0';

  chk = bech32_polymod(chk);

  for (i = 0; i < hlen; i++)
    chk = bech32_polymod(chk) ^ (str[i] & 0x1f);

  for (i = hlen + 1; i < slen; i++) {
    ch = bech32_table[str[i] & 0xff];

    if (ch < 0)
      return 0;

    chk = bech32_polymod(chk) ^ ch;

    if (i < slen - 6)
      data[j++] = ch;
  }

  if (chk != 1)
    return 0;

  *data_len = j;

  return 1;
}

static int
bech32_convert_bits(uint8_t *dst,
                    size_t *dstlen,
                    size_t dstbits,
                    const uint8_t *src,
                    size_t srclen,
                    size_t srcbits,
                    int pad) {
  uint32_t mask = (UINT32_C(1) << dstbits) - 1;
  uint32_t acc = 0;
  size_t bits = 0;
  size_t j = 0;
  size_t i, left;

  for (i = 0; i < srclen; i++) {
    acc = (acc << srcbits) | src[i];
    bits += srcbits;

    while (bits >= dstbits) {
      bits -= dstbits;
      dst[j++] = (acc >> bits) & mask;
    }
  }

  left = dstbits - bits;

  if (pad) {
    if (bits)
      dst[j++] = (acc << left) & mask;
  } else {
    if (((acc << left) & mask) || bits >= srcbits)
      return 0;
  }

  if (dstlen != NULL)
    *dstlen = j;

  return 1;
}

int
btc_bech32_encode(char *addr,
                  const char *hrp,
                  unsigned int version,
                  const uint8_t *hash,
                  size_t hash_len) {
  uint8_t data[65];
  size_t data_len;

  if (version > 16)
    return 0;

  if (hash_len < 2 || hash_len > 40)
    return 0;

  data[0] = version;

  if (!bech32_convert_bits(data + 1, &data_len, 5, hash, hash_len, 8, 1))
    return 0;

  data_len += 1;

  return bech32_serialize(addr, hrp, data, data_len);
}

int
btc_bech32_decode(char *hrp,
                  unsigned int *version,
                  uint8_t *hash,
                  size_t *hash_len,
                  const char *addr) {
  uint8_t data[83];
  size_t data_len;

  if (!bech32_deserialize(hrp, data, &data_len, addr))
    return 0;

  if (data_len == 0 || data_len > 65)
    return 0;

  if (data[0] > 16)
    return 0;

  if (!bech32_convert_bits(hash, hash_len, 8, data + 1, data_len - 1, 5, 0))
    return 0;

  if (*hash_len < 2 || *hash_len > 40)
    return 0;

  *version = data[0];

  return 1;
}

int
btc_bech32_test(const char *addr) {
  char hrp[83 + 1];
  unsigned int version;
  uint8_t hash[40];
  size_t hash_len;

  return btc_bech32_decode(hrp, &version, hash, &hash_len, addr);
}
