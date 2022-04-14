/*!
 * bip39.c - bip39 for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/bip32.h>
#include <mako/bip39.h>
#include <mako/crypto/hash.h>
#include <mako/crypto/rand.h>
#include <mako/util.h>
#include "impl.h"
#include "internal.h"
#include "words.h"

/*
 * Constants
 */

/* Current values:
 *
 * BIP39_MIN_WORDS = 12
 * BIP39_MAX_WORDS = 48
 * BIP39_MIN_BYTES = 17
 * BIP39_MAX_BYTES = 66
 */
#define BIP39_MIN_ENTROPY 128
#define BIP39_MAX_ENTROPY 512
#define BIP39_MIN_WORDS ((BIP39_MIN_ENTROPY + (BIP39_MIN_ENTROPY / 32)) / 11)
#define BIP39_MAX_WORDS ((BIP39_MAX_ENTROPY + (BIP39_MAX_ENTROPY / 32)) / 11)
#define BIP39_MIN_BYTES ((BIP39_MIN_WORDS * 11 + 7) / 8)
#define BIP39_MAX_BYTES ((BIP39_MAX_WORDS * 11 + 7) / 8)
#define BIP39_MAX_WORDLEN 8

/*
 * Globals
 */

const btc_mnemonic_t btc_mnemonic_null = {
  /* .words = */ {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  },
  /* .length = */ 12
};

/*
 * Mnemonic
 */

void
btc_mnemonic_init(btc_mnemonic_t *mn) {
  memset(mn, 0, sizeof(*mn));
}

void
btc_mnemonic_clear(btc_mnemonic_t *mn) {
  btc_memzero(mn, sizeof(*mn));
}

void
btc_mnemonic_copy(btc_mnemonic_t *z, const btc_mnemonic_t *x) {
  int i;

  for (i = 0; i < BIP39_MAX_WORDS; i++)
    z->words[i] = x->words[i];

  z->length = x->length;
}

int
btc_mnemonic_equal(const btc_mnemonic_t *x, const btc_mnemonic_t *y) {
  uint32_t z = 0;
  int i;

  for (i = 0; i < BIP39_MAX_WORDS; i++)
    z |= x->words[i] ^ y->words[i];

  z |= x->length ^ y->length;

  return (z - 1) >> 31;
}

int
btc_mnemonic_is_null(const btc_mnemonic_t *mn) {
  return mn->length == 0;
}

void
btc_mnemonic_set(btc_mnemonic_t *mn, const uint8_t *entropy, size_t length) {
  uint8_t data[(BIP39_MAX_ENTROPY / 8) + 32];
  int i, j, bits, wbits;

  CHECK(length >= BIP39_MIN_ENTROPY / 8);
  CHECK(length <= BIP39_MAX_ENTROPY / 8);
  CHECK((length & 3) == 0);

  /* Include the first `ENT / 32` bits
     of the hash (the checksum). */
  bits = length * 8;
  wbits = bits + (bits / 32);

  /* Append the hash to the entropy to
     make things easy when grabbing
     the checksum bits. */
  memcpy(data, entropy, length);

  btc_sha256(data + length, entropy, length);

  /* Build the mnemonic by reading
     11 bit indices from the entropy. */
  memset(mn, 0, sizeof(*mn));

  for (i = 0; i < wbits / 11; i++) {
    int index = 0;

    for (j = 0; j < 11; j++) {
      int pos = i * 11 + j;

      index <<= 1;
      index |= (data[pos >> 3] >> (7 - (pos & 7))) & 1;
    }

    mn->words[mn->length++] = index;
  }

  btc_memzero(data, sizeof(data));
}

void
btc_mnemonic_generate(btc_mnemonic_t *mn, unsigned int bits) {
  uint8_t entropy[BIP39_MAX_ENTROPY / 8];

  CHECK(bits >= BIP39_MIN_ENTROPY);
  CHECK(bits <= BIP39_MAX_ENTROPY);
  CHECK((bits & 31) == 0);

  btc_getrandom(entropy, bits / 8);
  btc_mnemonic_set(mn, entropy, bits / 8);

  btc_memzero(entropy, sizeof(entropy));
}

static int
btc_mnemonic_verify(const btc_mnemonic_t *mn) {
  int wbits = mn->length * 11;
  int cbits = wbits % 32;
  int bits = wbits - cbits;
  uint8_t data[BIP39_MAX_BYTES];
  uint8_t chk2[32];
  uint8_t *chk1;
  int i, j;

  if (bits < BIP39_MIN_ENTROPY)
    return 0;

  if (bits > BIP39_MAX_ENTROPY)
    return 0;

  if (cbits != (bits / 32))
    return 0;

  /* Rebuild entropy bytes. */
  memset(data, 0, sizeof(data));

  for (i = 0; i < mn->length; i++) {
    int index = mn->words[i];

    for (j = 0; j < 11; j++) {
      int pos = i * 11 + j;
      int val = (index >> (10 - j)) & 1;

      data[pos >> 3] |= val << (7 - (pos & 7));
    }
  }

  /* Verify checksum. */
  chk1 = data + (bits / 8);

  btc_sha256(chk2, data, bits / 8);

  for (i = 0; i < cbits; i++) {
    int b1 = (chk1[i >> 3] >> (7 - (i & 7))) & 1;
    int b2 = (chk2[i >> 3] >> (7 - (i & 7))) & 1;

    if (b1 != b2)
      return 0;
  }

  btc_memzero(data, sizeof(data));

  return 1;
}

static int
space_p(int ch) {
  switch (ch) {
    case '\t':
    case '\n':
    case '\v':
    case '\f':
    case '\r':
    case ' ':
      return 1;
  }
  return 0;
}

static int
eat_space(const char **xp) {
  while (space_p(**xp))
    *xp += 1;
  return **xp;
}

static int
next_word(char *zp, const char **xp) {
  int i = 0;

  while (**xp) {
    int ch = **xp;

    if (space_p(ch))
      break;

    if (i == BIP39_MAX_WORDLEN)
      return 0;

    zp[i++] = ch | 32;

    *xp += 1;
  }

  zp[i] = '\0';

  return i;
}

static int
find_word(const char *word) {
  int end = lengthof(bip39_words) - 1;
  int start = 0;
  int pos, cmp;

  while (start <= end) {
    pos = (start + end) >> 1;
    cmp = strcmp(bip39_words[pos], word);

    if (cmp == 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  return -1;
}

int
btc_mnemonic_set_phrase(btc_mnemonic_t *mn, const char *phrase) {
  char word[BIP39_MAX_WORDLEN + 1];
  int index;

  memset(mn, 0, sizeof(*mn));

  while (eat_space(&phrase)) {
    if (!next_word(word, &phrase))
      return 0;

    index = find_word(word);

    if (index < 0)
      return 0;

    if (mn->length == BIP39_MAX_WORDS)
      return 0;

    mn->words[mn->length++] = index;
  }

  btc_memzero(word, sizeof(word));

  return btc_mnemonic_verify(mn);
}

void
btc_mnemonic_get_phrase(char *phrase, const btc_mnemonic_t *mn) {
  int i;

  if (mn->length == 0) {
    *phrase = '\0';
    return;
  }

  for (i = 0; i < mn->length; i++) {
    const char *word = bip39_words[mn->words[i]];

    while (*word)
      *phrase++ = *word++;

    *phrase++ = ' ';
  }

  *--phrase = '\0';
}

void
btc_mnemonic_seed(uint8_t *seed, const btc_mnemonic_t *mn, const char *pass) {
  char phrase[BTC_PHRASE_MAX + 1];
  char passwd[8 + 1024 + 1];

  btc_mnemonic_get_phrase(phrase, mn);

  memcpy(passwd, "mnemonic", 8 + 1);

  if (pass != NULL) {
    size_t len = btc_strnlen(pass, 1025);

    if (len > 1024)
      btc_abort(); /* LCOV_EXCL_LINE */

    memcpy(passwd + 8, pass, len + 1);
  }

  btc_pbkdf512_derive(seed, (const uint8_t *)phrase, strlen(phrase),
                            (const uint8_t *)passwd, strlen(passwd),
                            2048, 64);

  btc_memzero(phrase, sizeof(phrase));
  btc_memzero(passwd, sizeof(passwd));
}

size_t
btc_mnemonic_size(const btc_mnemonic_t *mn) {
  return 1 + mn->length * 2;
}

uint8_t *
btc_mnemonic_write(uint8_t *zp, const btc_mnemonic_t *mn) {
  int i;

  zp = btc_uint8_write(zp, mn->length);

  for (i = 0; i < mn->length; i++)
    zp = btc_uint16_write(zp, mn->words[i]);

  return zp;
}

int
btc_mnemonic_read(btc_mnemonic_t *mn, const uint8_t **xp, size_t *xn) {
  uint8_t length;
  int i;

  if (!btc_uint8_read(&length, xp, xn))
    return 0;

  if (length > BIP39_MAX_WORDS)
    return 0;

  memset(mn, 0, sizeof(*mn));

  for (i = 0; i < (int)length; i++) {
    uint16_t index;

    if (!btc_uint16_read(&index, xp, xn))
      return 0;

    if (index >= (1 << 11))
      return 0;

    mn->words[i] = index;
  }

  mn->length = length;

  return btc_mnemonic_verify(mn);
}

size_t
btc_mnemonic_export(uint8_t *zp, const btc_mnemonic_t *mn) {
  return btc_mnemonic_write(zp, mn) - zp;
}

int
btc_mnemonic_import(btc_mnemonic_t *mn, const uint8_t *xp, size_t xn) {
  return btc_mnemonic_read(mn, &xp, &xn);
}

/*
 * HD Private
 */

int
btc_hdpriv_set_mnemonic(btc_hdnode_t *node,
                        enum btc_bip32_type type,
                        const btc_mnemonic_t *mn,
                        const char *pass) {
  uint8_t seed[64];
  int ret = 1;

  btc_mnemonic_seed(seed, mn, pass);

  ret &= btc_hdpriv_set_seed(node, type, seed, 64);

  btc_memzero(seed, sizeof(seed));

  return ret;
}
