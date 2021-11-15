/*!
 * ecc.c - elliptic curves for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Formulas from DJB and Tanja Lange [EFD].
 *
 * References:
 *
 *   [GECC] Guide to Elliptic Curve Cryptography
 *     D. Hankerson, A. Menezes, and S. Vanstone
 *     https://tinyurl.com/guide-to-ecc
 *
 *   [GLV] Faster Point Multiplication on Elliptic Curves
 *     R. Gallant, R. Lambert, and S. Vanstone
 *     https://link.springer.com/content/pdf/10.1007/3-540-44647-8_11.pdf
 *
 *   [SEC1] SEC 1: Elliptic Curve Cryptography, Version 2.0
 *     Certicom Research
 *     http://www.secg.org/sec1-v2.pdf
 *
 *   [EFD] Explicit-Formulas Database
 *     Daniel J. Bernstein, Tanja Lange
 *     https://hyperelliptic.org/EFD/index.html
 *
 *   [H2EC] Hashing to Elliptic Curves
 *     A. Faz-Hernandez, S. Scott, N. Sullivan, R. S. Wahby, C. A. Wood
 *     https://git.io/JeWz6
 *     https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
 *
 *   [SVDW1] Construction of Rational Points on Elliptic Curves
 *     A. Shallue, C. E. van de Woestijne
 *     https://works.bepress.com/andrew_shallue/1/download/
 *
 *   [SVDW2] Indifferentiable Hashing to Barreto-Naehrig Curves
 *     Pierre-Alain Fouque, Mehdi Tibouchi
 *     https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf
 *
 *   [SVDW3] Covert ECDH over secp256k1
 *     Pieter Wuille
 *     https://gist.github.com/sipa/29118d3fcfac69f9930d57433316c039
 *
 *   [SQUARED] Elligator Squared
 *     Mehdi Tibouchi
 *     https://eprint.iacr.org/2014/043.pdf
 *
 *   [SIDE1] Weierstrass Elliptic Curves and Side-Channel Attacks
 *     Eric Brier, Marc Joye
 *     http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.2.273&rep=rep1&type=pdf
 *
 *   [SIDE2] Unified Point Addition Formulae and Side-Channel Attacks
 *     Douglas Stebila, Nicolas Theriault
 *     https://eprint.iacr.org/2005/419.pdf
 *
 *   [BIP340] Schnorr Signatures for secp256k1
 *     Pieter Wuille, Jonas Nick, Tim Ruffing
 *     https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 *
 *   [JCEN12] Efficient Software Implementation of Public-Key Cryptography
 *            on Sensor Networks Using the MSP430X Microcontroller
 *     C. P. L. Gouvea, L. B. Oliveira, J. Lopez
 *     http://conradoplg.cryptoland.net/files/2010/12/jcen12.pdf
 *
 *   [FIPS186] Federal Information Processing Standards Publication
 *     National Institute of Standards and Technology
 *     https://tinyurl.com/fips-186-3
 *
 *   [FIPS186] Suite B Implementer's Guide to FIPS 186-3 (ECDSA)
 *     https://tinyurl.com/fips186-guide
 *
 *   [RFC6979] Deterministic Usage of the Digital Signature
 *             Algorithm (DSA) and Elliptic Curve Digital
 *             Signature Algorithm (ECDSA)
 *     T. Pornin
 *     https://tools.ietf.org/html/rfc6979
 *
 *   [ECPM] Elliptic Curve Point Multiplication (wikipedia)
 *     https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
 */

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/crypto/drbg.h>
#include <mako/crypto/ecc.h>
#include <mako/crypto/hash.h>
#include <mako/mpi.h>
#include <mako/util.h>

#include "asn1.h"
#include "../internal.h"

#if defined(BTC_HAVE_INT128)
typedef uint64_t fe_word_t;
#  define FIELD_WORD_BITS 64
#  define FIELD_WORDS 6
#else
typedef uint32_t fe_word_t;
#  define FIELD_WORD_BITS 32
#  define FIELD_WORDS 12
#endif

BTC_BARRIER(int, int)
BTC_BARRIER(fe_word_t, fe_word)

#define FIELD_LIMBS (256 / MP_LIMB_BITS)

#define SCALAR_LIMBS (256 / MP_LIMB_BITS)
#define REDUCE_LIMBS (SCALAR_LIMBS * 2 + 2)
#define ENDO_BITS 129

#define FIXED_WIDTH 4
#define FIXED_SIZE (1 << FIXED_WIDTH) /* 16 */
#define FIXED_STEPS ((256 + FIXED_WIDTH - 1) / FIXED_WIDTH) /* 64 */
#define FIXED_LENGTH (FIXED_STEPS * FIXED_SIZE) /* 1024 */

#define WND_WIDTH 4
#define WND_SIZE (1 << WND_WIDTH) /* 16 */
#define WND_STEPS ((ENDO_BITS + WND_WIDTH - 1) / WND_WIDTH) /* 64 */

#define NAF_WIDTH 5
#define NAF_SIZE (1 << (NAF_WIDTH - 2)) /* 8 */

#define NAF_WIDTH_PRE 12
#define NAF_SIZE_PRE (1 << (NAF_WIDTH_PRE - 2)) /* 1024 */

#define JSF_SIZE 4

#define ECC_MIN(x, y) ((x) < (y) ? (x) : (y))
#define ECC_MAX(x, y) ((x) > (y) ? (x) : (y))

#define cleanse btc_memzero

/*
 * Types
 */

typedef mp_limb_t sc_t[SCALAR_LIMBS];
typedef fe_word_t fe_t[FIELD_WORDS];

typedef struct wge_s {
  fe_t x;
  fe_t y;
  int inf;
} wge_t;

typedef struct jge_s {
  fe_t x;
  fe_t y;
  fe_t z;
  int inf;
  int aff;
} jge_t;

typedef struct wei_scratch_s {
  size_t size;
  jge_t *wnd;
  jge_t **wnds;
  int *naf;
  int **nafs;
  wge_t *points;
  sc_t *coeffs;
} wei_scratch_t;

/*
 * SECP256K1
 */

#if FIELD_WORD_BITS == 64
#  include "fields/secp256k1_64.h"
#else
#  include "fields/secp256k1_32.h"
#endif

#include "secp256k1.h"

/*
 * Helpers
 */

static int
bytes_lt(const unsigned char *xp, const unsigned char *yp, size_t n) {
  /* Compute (x < y) in constant time. */
  uint32_t eq = 1;
  uint32_t lt = 0;
  uint32_t a, b;
  size_t i;

  for (i = 0; i < n; i++) {
    a = xp[i];
    b = yp[i];
    lt |= eq & ((a - b) >> 31);
    eq &= ((a ^ b) - 1) >> 31;
  }

  return lt & (eq ^ 1);
}

static void
reverse_copy(unsigned char *zp, const unsigned char *xp, size_t n) {
  xp += n;

  while (n--)
    *zp++ = *--xp;
}

static void
reverse_bytes(unsigned char *zp, size_t n) {
  size_t i = 0;
  size_t j = n - 1;
  unsigned char zpi;

  n >>= 1;

  while (n--) {
    zpi = zp[i];
    zp[i++] = zp[j];
    zp[j--] = zpi;
  }
}

static void *
checked_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    btc_abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

/*
 * Scalar
 */

static void
fe_export(unsigned char *zp, const fe_t x);

static void
sc_zero(sc_t z) {
  mpn_zero(z, SCALAR_LIMBS);
}

static void
sc_cleanse(sc_t z) {
  cleanse(z, SCALAR_LIMBS * sizeof(mp_limb_t));
}

static void
sc_set(sc_t z, const sc_t x) {
  mpn_copyi(z, x, SCALAR_LIMBS);
}

static void
sc_set_word(sc_t z, mp_limb_t x) {
  mpn_set_1(z, SCALAR_LIMBS, x);
}

static void
sc_select(sc_t z, const sc_t x, const sc_t y, int flag) {
  mpn_cnd_select(z, x, y, SCALAR_LIMBS, flag);
}

static void
sc_select_zero(sc_t z, const sc_t x, int flag) {
  mpn_cnd_zero(z, x, SCALAR_LIMBS, flag);
}

static int
sc_is_zero(const sc_t x) {
  return mpn_sec_zero_p(x, SCALAR_LIMBS);
}

static int
sc_cmp_var(const sc_t x, const sc_t y) {
  return mpn_cmp(x, y, SCALAR_LIMBS);
}

static int
sc_is_canonical(const sc_t x) {
  return mpn_sec_lt_p(x, scalar_n, SCALAR_LIMBS);
}

static int
sc_is_high(const sc_t x) {
  return mpn_sec_gt_p(x, scalar_nh, SCALAR_LIMBS);
}

static int
sc_is_high_var(const sc_t x) {
  return mpn_cmp(x, scalar_nh, SCALAR_LIMBS) > 0;
}

static mp_bits_t
sc_bitlen_var(const sc_t x) {
  return mpn_bitlen(x, SCALAR_LIMBS);
}

static mp_limb_t
sc_get_bit(const sc_t x, mp_bits_t pos) {
  return mpn_getbit(x, SCALAR_LIMBS, pos);
}

static mp_limb_t
sc_get_bits(const sc_t x, mp_bits_t pos, mp_bits_t width) {
  return mpn_getbits(x, SCALAR_LIMBS, pos, width);
}

static int
sc_reduce_weak(sc_t z, const sc_t x, mp_limb_t hi) {
  mp_limb_t scratch[MPN_REDUCE_WEAK_ITCH(SCALAR_LIMBS)]; /* 144 bytes */

  return mpn_reduce_weak(z, x, scalar_n, SCALAR_LIMBS, hi, scratch);
}

static void
sc_add(sc_t z, const sc_t x, const sc_t y) {
  mp_limb_t c = mpn_add_n(z, x, y, SCALAR_LIMBS);

  sc_reduce_weak(z, z, c);
}

static void
sc_neg(sc_t z, const sc_t x) {
  int zero = sc_is_zero(x);

  ASSERT(mpn_sub_n(z, scalar_n, x, SCALAR_LIMBS) == 0);

  sc_select_zero(z, z, zero);
}

static void
sc_neg_cond(sc_t z, const sc_t x, int flag) {
  sc_t y;
  sc_neg(y, x);
  sc_select(z, x, y, flag);
}

static void
sc_reduce(sc_t z, const mp_limb_t *xp) {
  /* Barrett reduction (264 bytes). */
  mp_limb_t scratch[MPN_REDUCE_ITCH(SCALAR_LIMBS, REDUCE_LIMBS)];

  mpn_reduce(z, xp, scalar_m, scalar_n, SCALAR_LIMBS, REDUCE_LIMBS, scratch);
}

static void
sc_mul(sc_t z, const sc_t x, const sc_t y) {
  mp_limb_t zp[REDUCE_LIMBS]; /* 160 bytes */
  mp_size_t zn = SCALAR_LIMBS * 2;

  mpn_mul_n(zp, x, y, SCALAR_LIMBS);

  mpn_zero(zp + zn, REDUCE_LIMBS - zn);

  sc_reduce(z, zp);
}

BTC_UNUSED static void
sc_sqr(sc_t z, const sc_t x) {
  mp_limb_t scratch[MPN_SQR_ITCH(SCALAR_LIMBS)]; /* 144 bytes */
  mp_limb_t zp[REDUCE_LIMBS]; /* 160 bytes */
  mp_size_t zn = SCALAR_LIMBS * 2;

  mpn_sqr(zp, x, SCALAR_LIMBS, scratch);

  mpn_zero(zp + zn, REDUCE_LIMBS - zn);

  sc_reduce(z, zp);
}

static void
sc_mulshift(sc_t z, const sc_t x, const sc_t y, mp_bits_t shift) {
  mp_limb_t scratch[MPN_MULSHIFT_ITCH(SCALAR_LIMBS)]; /* 144 bytes */

  ASSERT(mpn_mulshift(z, x, y, SCALAR_LIMBS, shift, scratch) == 0);
}

static void
sc_montmul(sc_t z, const sc_t x, const sc_t y) {
  mp_limb_t scratch[MPN_MONTMUL_ITCH(SCALAR_LIMBS)]; /* 144 bytes */

  mpn_sec_montmul(z, x, y, scalar_n, SCALAR_LIMBS, scalar_k, scratch);
}

static void
sc_montsqr(sc_t z, const sc_t x) {
  sc_montmul(z, x, x);
}

static void
sc_montsqrn(sc_t z, const sc_t x, int n) {
  int i;

  ASSERT(n > 0);

  sc_montsqr(z, x);

  for (i = 1; i < n; i++)
    sc_montsqr(z, z);
}

static void
sc_mont(sc_t z, const sc_t x) {
  sc_montmul(z, x, scalar_r2);
}

static void
sc_normal(sc_t z, const sc_t x) {
  sc_montmul(z, x, scalar_one);
}

static void
sc_import_raw(sc_t z, const unsigned char *xp) {
  mpn_import(z, SCALAR_LIMBS, xp, 32, 1);
}

static int
sc_import(sc_t z, const unsigned char *xp) {
  int ret = 1;

  sc_import_raw(z, xp);

  ret &= sc_is_canonical(z);

  sc_select_zero(z, z, ret ^ 1);

  return ret;
}

static int
sc_import_weak(sc_t z, const unsigned char *xp) {
  sc_import_raw(z, xp);

  return sc_reduce_weak(z, z, 0) ^ 1;
}

static void
sc_export(unsigned char *zp, const sc_t x) {
  mpn_export(zp, 32, x, SCALAR_LIMBS, 1);
}

static int
sc_set_fe(sc_t z, const fe_t x) {
  unsigned char raw[32];

  fe_export(raw, x);

  return sc_import_weak(z, raw);
}

static int
sc_invert_var(sc_t z, const sc_t x) {
  mp_limb_t scratch[MPN_INVERT_ITCH(SCALAR_LIMBS)]; /* 320 bytes */

  return mpn_invert_n(z, x, scalar_n, SCALAR_LIMBS, scratch);
}

static int
sc_invert(sc_t z, const sc_t x) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_scalar_inversion */
  /* https://github.com/bitcoin-core/secp256k1/blob/master/src/scalar_impl.h */
  sc_t x2, x3, x6, x8, x14, x28, x56, x112, x126;
  sc_t u1, u2, u5, u9, u11, u13;

  sc_mont(u1, x);

  sc_montsqr(u2, u1);
  sc_montmul(x2, u2, u1);
  sc_montmul(u5, u2, x2);
  sc_montmul(x3, u5, u2);
  sc_montmul(u9, x3, u2);
  sc_montmul(u11, u9, u2);
  sc_montmul(u13, u11, u2);

  sc_montsqr(x6, u13);
  sc_montsqr(x6, x6);
  sc_montmul(x6, x6, u11);

  sc_montsqr(x8, x6);
  sc_montsqr(x8, x8);
  sc_montmul(x8, x8,  x2);

  sc_montsqr(x14, x8);
  sc_montsqrn(x14, x14, 5);
  sc_montmul(x14, x14, x6);

  sc_montsqr(x28, x14);
  sc_montsqrn(x28, x28, 13);
  sc_montmul(x28, x28, x14);

  sc_montsqr(x56, x28);
  sc_montsqrn(x56, x56, 27);
  sc_montmul(x56, x56, x28);

  sc_montsqr(x112, x56);
  sc_montsqrn(x112, x112, 55);
  sc_montmul(x112, x112, x56);

  sc_montsqr(x126, x112);
  sc_montsqrn(x126, x126, 13);
  sc_montmul(z, x126, x14);

  sc_montsqrn(z, z, 0 + 3); /* 101 */
  sc_montmul(z, z, u5);
  sc_montsqrn(z, z, 1 + 3); /* 0111 */
  sc_montmul(z, z, x3);
  sc_montsqrn(z, z, 1 + 3); /* 0101 */
  sc_montmul(z, z, u5);
  sc_montsqrn(z, z, 1 + 4); /* 01011 */
  sc_montmul(z, z, u11);
  sc_montsqrn(z, z, 0 + 4); /* 1011 */
  sc_montmul(z, z, u11);
  sc_montsqrn(z, z, 1 + 3); /* 0111 */
  sc_montmul(z, z, x3);
  sc_montsqrn(z, z, 2 + 3); /* 00111 */
  sc_montmul(z, z, x3);
  sc_montsqrn(z, z, 2 + 4); /* 001101 */
  sc_montmul(z, z, u13);
  sc_montsqrn(z, z, 1 + 3); /* 0101 */
  sc_montmul(z, z, u5);
  sc_montsqrn(z, z, 0 + 3); /* 111 */
  sc_montmul(z, z, x3);
  sc_montsqrn(z, z, 1 + 4); /* 01001 */
  sc_montmul(z, z, u9);
  sc_montsqrn(z, z, 3 + 3); /* 000101 */
  sc_montmul(z, z, u5);
  sc_montsqrn(z, z, 7 + 3); /* 0000000111 */
  sc_montmul(z, z, x3);
  sc_montsqrn(z, z, 1 + 3); /* 0111 */
  sc_montmul(z, z, x3);
  sc_montsqrn(z, z, 1 + 8); /* 011111111 */
  sc_montmul(z, z, x8);
  sc_montsqrn(z, z, 1 + 4); /* 01001 */
  sc_montmul(z, z, u9);
  sc_montsqrn(z, z, 2 + 4); /* 001011 */
  sc_montmul(z, z, u11);
  sc_montsqrn(z, z, 0 + 4); /* 1101 */
  sc_montmul(z, z, u13);
  sc_montsqrn(z, z, 0 + 5); /* 11 */
  sc_montmul(z, z, x2);
  sc_montsqrn(z, z, 2 + 4); /* 001101 */
  sc_montmul(z, z, u13);
  sc_montsqrn(z, z, 6 + 4); /* 0000001101 */
  sc_montmul(z, z, u13);
  sc_montsqrn(z, z, 0 + 4); /* 1001 */
  sc_montmul(z, z, u9);
  sc_montsqrn(z, z, 5 + 1); /* 000001 */
  sc_montmul(z, z, u1);
  sc_montsqrn(z, z, 2 + 6); /* 00111111 */
  sc_montmul(z, z, x6);

  sc_normal(z, z);

  sc_cleanse(u1);

  return sc_is_zero(z) ^ 1;
}

static int
sc_minimize(sc_t z, const sc_t x) {
  int high = sc_is_high(x);

  sc_neg_cond(z, x, high);

  return high;
}

static int
sc_minimize_var(sc_t z, const sc_t x) {
  int high = sc_is_high_var(x);

  if (high)
    sc_neg(z, x);
  else
    sc_set(z, x);

  return high;
}

static mp_bits_t
sc_naf_var0(int *naf, const sc_t k, int sign, mp_bits_t width, mp_bits_t max) {
  /* Computing the width-w NAF of a positive integer.
   *
   * [GECC] Algorithm 3.35, Page 100, Section 3.3.
   *
   * The above document describes a rather abstract
   * method of recoding. The more optimal method
   * below was ported from libsecp256k1.
   */
  mp_bits_t bits = sc_bitlen_var(k) + 1;
  mp_bits_t len = 0;
  mp_bits_t i = 0;
  int carry = 0;
  int word;

  ASSERT(bits <= max);

  while (max--)
    naf[max] = 0;

  while (i < bits) {
    if (sc_get_bit(k, i) == (mp_limb_t)carry) {
      i += 1;
      continue;
    }

    word = sc_get_bits(k, i, width) + carry;
    carry = (word >> (width - 1)) & 1;
    word -= (carry << width);

    naf[i] = sign * word;

    len = i + 1;

    i += width;
  }

  ASSERT(carry == 0);

  return len;
}

static mp_bits_t
sc_naf_var(int *naf1, int *naf2, const sc_t k1, const sc_t k2, mp_bits_t width) {
  mp_bits_t len1, len2;
  sc_t c1, c2;
  int s1, s2;

  /* Minimize scalars. */
  s1 = sc_minimize_var(c1, k1) ? -1 : 1;
  s2 = sc_minimize_var(c2, k2) ? -1 : 1;

  /* Calculate NAFs. */
  len1 = sc_naf_var0(naf1, c1, s1, width, ENDO_BITS + 1);
  len2 = sc_naf_var0(naf2, c2, s2, width, ENDO_BITS + 1);

  return ECC_MAX(len1, len2);
}

static mp_bits_t
sc_jsf_var0(int *naf,
            const sc_t k1,
            int s1,
            const sc_t k2,
            int s2,
            mp_bits_t max) {
  /* Joint sparse form.
   *
   * [GECC] Algorithm 3.50, Page 111, Section 3.3.
   */
  mp_bits_t bits1 = sc_bitlen_var(k1) + 1;
  mp_bits_t bits2 = sc_bitlen_var(k2) + 1;
  mp_bits_t bits = ECC_MAX(bits1, bits2);
  mp_bits_t i;
  int d1 = 0;
  int d2 = 0;

  /* JSF->NAF conversion table. */
  static const int table[9] = {
    -3, /* -1 -1 */
    -1, /* -1  0 */
    -5, /* -1  1 */
    -7, /*  0 -1 */
     0, /*  0  0 */
     7, /*  0  1 */
     5, /*  1 -1 */
     1, /*  1  0 */
     3  /*  1  1 */
  };

  ASSERT(bits <= max);

  for (i = 0; i < bits; i++) {
    int b1 = sc_get_bits(k1, i, 3);
    int b2 = sc_get_bits(k2, i, 3);

    /* First phase. */
    int m14 = ((b1 & 3) + d1) & 3;
    int m24 = ((b2 & 3) + d2) & 3;
    int u1 = 0;
    int u2 = 0;

    if (m14 == 3)
      m14 = -1;

    if (m24 == 3)
      m24 = -1;

    if (m14 & 1) {
      int m8 = ((b1 & 7) + d1) & 7;

      if ((m8 == 3 || m8 == 5) && m24 == 2)
        u1 = -m14;
      else
        u1 = m14;
    }

    if (m24 & 1) {
      int m8 = ((b2 & 7) + d2) & 7;

      if ((m8 == 3 || m8 == 5) && m14 == 2)
        u2 = -m24;
      else
        u2 = m24;
    }

    /* JSF -> NAF conversion. */
    naf[i] = table[(u1 * s1 + 1) * 3 + (u2 * s2 + 1)];

    /* Second phase. */
    if (2 * d1 == 1 + u1)
      d1 = 1 - d1;

    if (2 * d2 == 1 + u2)
      d2 = 1 - d2;
  }

  while (bits < max)
    naf[bits++] = 0;

  while (i > 0 && naf[i - 1] == 0)
    i -= 1;

  return i;
}

static mp_bits_t
sc_jsf_var(int *naf, const sc_t k1, const sc_t k2) {
  sc_t c1, c2;
  int s1, s2;

  /* Minimize scalars. */
  s1 = sc_minimize_var(c1, k1) ? -1 : 1;
  s2 = sc_minimize_var(c2, k2) ? -1 : 1;

  return sc_jsf_var0(naf, c1, s1, c2, s2, ENDO_BITS + 1);
}

static void
sc_random(sc_t z, btc_drbg_t *rng) {
  int ok;

  do {
    ok = 1;

    mpn_random(z, SCALAR_LIMBS, btc_drbg_rng, rng);

    ok &= sc_is_canonical(z);
    ok &= sc_is_zero(z) ^ 1;
  } while (!ok);
}

/*
 * Field Element
 */

static void
fe_zero(fe_t z) {
  int i;

  for (i = 0; i < FIELD_WORDS; i++)
    z[i] = 0;
}

static void
fe_cleanse(fe_t z) {
  cleanse(z, FIELD_WORDS * sizeof(fe_word_t));
}

static int
fe_import(fe_t z, const unsigned char *xp) {
  unsigned char tmp[32];
  int ret = 1;

  /* Ensure 0 <= x < p. */
  ret &= bytes_lt(xp, field_raw, 32);

  /* Swap endianness if necessary. */
  reverse_copy(tmp, xp, 32);

  /* Deserialize. */
  fiat_secp256k1_from_bytes(z, tmp);

  return ret;
}

static void
fe_export(unsigned char *zp, const fe_t x) {
  fiat_secp256k1_to_bytes(zp, x);
  reverse_bytes(zp, 32);
}

static void
fe_select(fe_t z, const fe_t x, const fe_t y, int flag) {
  fiat_secp256k1_selectznz(z, flag != 0, x, y);
}

static void
fe_set(fe_t z, const fe_t x) {
  int i;

  for (i = 0; i < FIELD_WORDS; i++)
    z[i] = x[i];
}

static int
fe_set_limbs(fe_t z, const mp_limb_t *xp) {
  unsigned char tmp[32];

  mpn_export(tmp, 32, xp, FIELD_LIMBS, 1);

  return fe_import(z, tmp);
}

static void
fe_get_limbs(mp_limb_t *zp, const fe_t x) {
  unsigned char tmp[32];

  fe_export(tmp, x);

  mpn_import(zp, FIELD_LIMBS, tmp, 32, 1);
}

static int
fe_set_sc(fe_t z, const sc_t x) {
  unsigned char raw[32];

  mpn_export(raw, 32, x, SCALAR_LIMBS, 1);

  return fe_import(z, raw);
}

static int
fe_is_zero(const fe_t x) {
  unsigned char tmp[32];
  fe_word_t z = 0;
  size_t i;

  fiat_secp256k1_to_bytes(tmp, x);

  for (i = 0; i < 32; i++)
    z |= (fe_word_t)tmp[i];

  return (z - 1) >> (FIELD_WORD_BITS - 1);
}

static int
fe_equal(const fe_t x, const fe_t y) {
  unsigned char u[32];
  unsigned char v[32];
  fe_word_t z = 0;
  size_t i;

  fiat_secp256k1_to_bytes(u, x);
  fiat_secp256k1_to_bytes(v, y);

  for (i = 0; i < 32; i++)
    z |= (fe_word_t)u[i] ^ (fe_word_t)v[i];

  return (z - 1) >> (FIELD_WORD_BITS - 1);
}

static int
fe_is_odd(const fe_t x) {
  unsigned char tmp[32];

  fiat_secp256k1_to_bytes(tmp, x);

  return tmp[0] & 1;
}

static BTC_INLINE void
fe_carry(fe_t z, const fe_t x) {
  fiat_secp256k1_carry(z, x);
}

static BTC_INLINE void
fe_neg(fe_t z, const fe_t x) {
  fiat_secp256k1_opp(z, x);
  fiat_secp256k1_carry(z, z);
}

BTC_UNUSED static BTC_INLINE void
fe_neg_nc(fe_t z, const fe_t x) {
  fiat_secp256k1_opp(z, x);
}

static void
fe_neg_cond(fe_t z, const fe_t x, int flag) {
  fe_t y;
  fe_neg(y, x);
  fe_select(z, x, y, flag);
}

static void
fe_set_odd(fe_t z, const fe_t x, int odd) {
  fe_neg_cond(z, x, fe_is_odd(x) ^ (odd != 0));
}

static BTC_INLINE void
fe_add(fe_t z, const fe_t x, const fe_t y) {
  fiat_secp256k1_add(z, x, y);
  fiat_secp256k1_carry(z, z);
}

static BTC_INLINE void
fe_sub(fe_t z, const fe_t x, const fe_t y) {
  fiat_secp256k1_sub(z, x, y);
  fiat_secp256k1_carry(z, z);
}

static BTC_INLINE void
fe_add_nc(fe_t z, const fe_t x, const fe_t y) {
  fiat_secp256k1_add(z, x, y);
}

static BTC_INLINE void
fe_sub_nc(fe_t z, const fe_t x, const fe_t y) {
  fiat_secp256k1_sub(z, x, y);
}

static BTC_INLINE void
fe_mul(fe_t z, const fe_t x, const fe_t y) {
  fiat_secp256k1_carry_mul(z, x, y);
}

static BTC_INLINE void
fe_sqr(fe_t z, const fe_t x) {
  fiat_secp256k1_carry_square(z, x);
}

static BTC_INLINE void
fe_sqrn(fe_t z, const fe_t x, int n) {
  int i;

  fiat_secp256k1_carry_square(z, x);

  for (i = 1; i < n; i++)
    fiat_secp256k1_carry_square(z, z);
}

static BTC_INLINE void
fe_mul3(fe_t z, const fe_t x) {
  fiat_secp256k1_carry_scmul_3(z, x);
}

static BTC_INLINE void
fe_mul4(fe_t z, const fe_t x) {
  fiat_secp256k1_carry_scmul_4(z, x);
}

static BTC_INLINE void
fe_mul8(fe_t z, const fe_t x) {
  fiat_secp256k1_carry_scmul_8(z, x);
}

static int
fe_invert_var(fe_t z, const fe_t x) {
  mp_limb_t scratch[MPN_INVERT_ITCH(FIELD_LIMBS)]; /* 320 bytes */
  mp_limb_t zp[FIELD_LIMBS];
  int ret = 1;

  fe_get_limbs(zp, x);

  ret &= mpn_invert_n(zp, zp, field_p, FIELD_LIMBS, scratch);

  ASSERT(fe_set_limbs(z, zp));

  return ret;
}

static void
fe_pow_core(fe_t z, const fe_t x1, const fe_t x2) {
  /* Exponent: (p - 47) / 64 */
  /* Bits: 223x1 1x0 22x1 4x0 */
  fe_t t1, t2, t3, t4;

  /* x3 = x2^(2^1) * x1 */
  fe_sqr(t1, x2);
  fe_mul(t1, t1, x1);

  /* x6 = x3^(2^3) * x3 */
  fe_sqrn(t2, t1, 3);
  fe_mul(t2, t2, t1);

  /* x9 = x6^(2^3) * x3 */
  fe_sqrn(t3, t2, 3);
  fe_mul(t3, t3, t1);

  /* x11 = x9^(2^2) * x2 */
  fe_sqrn(t2, t3, 2);
  fe_mul(t2, t2, x2);

  /* x22 = x11^(2^11) * x11 */
  fe_sqrn(t3, t2, 11);
  fe_mul(t3, t3, t2);

  /* x44 = x22^(2^22) * x22 */
  fe_sqrn(t2, t3, 22);
  fe_mul(t2, t2, t3);

  /* x88 = x44^(2^44) * x44 */
  fe_sqrn(t4, t2, 44);
  fe_mul(t4, t4, t2);

  /* x176 = x88^(2^88) * x88 */
  fe_sqrn(z, t4, 88);
  fe_mul(z, z, t4);

  /* x220 = x176^(2^44) * x44 */
  fe_sqrn(z, z, 44);
  fe_mul(z, z, t2);

  /* x223 = x220^(2^3) * x3 */
  fe_sqrn(z, z, 3);
  fe_mul(z, z, t1);

  /* z = x223^(2^1) */
  fe_sqr(z, z);

  /* z = z^(2^22) * x22 */
  fe_sqrn(z, z, 22);
  fe_mul(z, z, t3);

  /* z = z^(2^4) */
  fe_sqrn(z, z, 4);
}

static void
fe_pow_pm3d4(fe_t z, const fe_t x) {
  /* Exponent: (p - 3) / 4 */
  /* Bits: 223x1 1x0 22x1 4x0 1x1 1x0 2x1 */
  fe_t x1, x2;

  /* x1 = x */
  fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  fe_sqr(x2, x1);
  fe_mul(x2, x2, x1);

  /* z = x1^((p - 47) / 64) */
  fe_pow_core(z, x1, x2);

  /* z = z^(2^1) * x1 */
  fe_sqr(z, z);
  fe_mul(z, z, x1);

  /* z = z^(2^1) */
  fe_sqr(z, z);

  /* z = z^(2^2) * x2 */
  fe_sqrn(z, z, 2);
  fe_mul(z, z, x2);
}

static int
fe_invert(fe_t z, const fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 223x1 1x0 22x1 4x0 1x1 1x0 2x1 1x0 1x1 */
  fe_t x1, x2;

  /* x1 = x */
  fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  fe_sqr(x2, x1);
  fe_mul(x2, x2, x1);

  /* z = x1^((p - 47) / 64) */
  fe_pow_core(z, x1, x2);

  /* z = z^(2^1) * x1 */
  fe_sqr(z, z);
  fe_mul(z, z, x1);

  /* z = z^(2^1) */
  fe_sqr(z, z);

  /* z = z^(2^2) * x2 */
  fe_sqrn(z, z, 2);
  fe_mul(z, z, x2);

  /* z = z^(2^1) */
  fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  fe_sqr(z, z);
  fe_mul(z, z, x1);

  return fe_is_zero(z) ^ 1;
}

static int
fe_sqrt(fe_t z, const fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 223x1 1x0 22x1 4x0 2x1 2x0 */
  fe_t x1, x2;

  /* x1 = x */
  fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  fe_sqr(x2, x1);
  fe_mul(x2, x2, x1);

  /* z = x1^((p - 47) / 64) */
  fe_pow_core(z, x1, x2);

  /* z = z^(2^2) * x2 */
  fe_sqrn(z, z, 2);
  fe_mul(z, z, x2);

  /* z = z^(2^2) */
  fe_sqrn(z, z, 2);

  /* z^2 == x1 */
  fe_sqr(x2, z);

  return fe_equal(x2, x1);
}

static int
fe_is_square(const fe_t x) {
  fe_t z;
  return fe_sqrt(z, x);
}

static int
fe_isqrt(fe_t z, const fe_t u, const fe_t v) {
  fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  fe_sqr(t, u);       /* u^2 */
  fe_mul(c, t, u);    /* u^3 */
  fe_mul(t, t, c);    /* u^5 */
  fe_sqr(x, v);       /* v^2 */
  fe_mul(x, x, v);    /* v^3 */
  fe_mul(x, x, t);    /* v^3 * u^5 */
  fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  fe_sqr(c, x);
  fe_mul(c, c, v);

  ret = fe_equal(c, u);

  fe_set(z, x);

  return ret;
}

BTC_UNUSED static void
fe_random(fe_t z, btc_drbg_t *rng) {
  unsigned char bytes[32];
  int ok;

  do {
    ok = 1;

    btc_drbg_generate(rng, bytes, 32);

    ok &= fe_import(z, bytes);
    ok &= fe_is_zero(z) ^ 1;
  } while (!ok);

  cleanse(bytes, 32);
}

/*
 * Short Weierstrass
 */

static void
wei_solve_y2(fe_t y2, const fe_t x);

static int
wei_validate_xy(const fe_t x, const fe_t y);

static void
jge_zero(jge_t *r);

static void
jge_set(jge_t *r, const jge_t *p);

static int
jge_is_zero(const jge_t *p);

static void
jge_dbl_var(jge_t *p3, const jge_t *p);

static void
jge_add_var(jge_t *p3, const jge_t *p1, const jge_t *p2);

static void
jge_mixed_addsub_var(jge_t *p3, const jge_t *p1,
                     const fe_t x2, const fe_t y2, int sign);

static void
jge_mixed_add_var(jge_t *p3, const jge_t *p1, const wge_t *p2);

static void
jge_mixed_sub_var(jge_t *p3, const jge_t *p1, const wge_t *p2);

static void
jge_set_wge(jge_t *r, const wge_t *p);

/*
 * Short Weierstrass Affine Point
 */

static void
wge_zero(wge_t *r) {
  fe_zero(r->x);
  fe_zero(r->y);

  r->inf = 1;
}

static void
wge_cleanse(wge_t *r) {
  fe_cleanse(r->x);
  fe_cleanse(r->y);

  r->inf = 1;
}

BTC_UNUSED static int
wge_validate(const wge_t *p) {
  return wei_validate_xy(p->x, p->y) | p->inf;
}

static int
wge_set_x(wge_t *r, const fe_t x, int sign) {
  int ret = 1;
  fe_t y;

  wei_solve_y2(y, x);

  ret &= fe_sqrt(y, y);

  if (sign != -1)
    fe_set_odd(y, y, sign);

  fe_select(r->x, x, field_zero, ret ^ 1);
  fe_select(r->y, y, field_zero, ret ^ 1);

  r->inf = ret ^ 1;

  return ret;
}

static int
wge_set_xy(wge_t *r, const fe_t x, const fe_t y) {
  int ret = wei_validate_xy(x, y);

  fe_select(r->x, x, field_zero, ret ^ 1);
  fe_select(r->y, y, field_zero, ret ^ 1);

  r->inf = ret ^ 1;

  return ret;
}

static int
wge_import(wge_t *r, const unsigned char *raw, size_t len) {
  /* [SEC1] Page 11, Section 2.3.4. */
  int ret = 1;
  fe_t x, y;
  int form;

  if (len == 0)
    goto fail;

  form = raw[0];

  switch (form) {
    case 0x02:
    case 0x03: {
      if (len != 1 + 32)
        goto fail;

      ret &= fe_import(x, raw + 1);
      ret &= wge_set_x(r, x, form & 1);

      return ret;
    }

    case 0x04:
    case 0x06:
    case 0x07: {
      if (len != 1 + 32 * 2)
        goto fail;

      ret &= fe_import(x, raw + 1);
      ret &= fe_import(y, raw + 1 + 32);
      ret &= (form == 0x04) | (form == (0x06 | fe_is_odd(y)));
      ret &= wge_set_xy(r, x, y);

      return ret;
    }
  }

fail:
  wge_zero(r);
  return 0;
}

static int
wge_export(unsigned char *raw, const wge_t *p, int compact) {
  /* [SEC1] Page 10, Section 2.3.3. */
  if (compact) {
    raw[0] = 0x02 | fe_is_odd(p->y);

    fe_export(raw + 1, p->x);
  } else {
    raw[0] = 0x04;

    fe_export(raw + 1, p->x);
    fe_export(raw + 1 + 32, p->y);
  }

  return p->inf ^ 1;
}

static int
wge_import_even(wge_t *r, const unsigned char *raw) {
  /* [BIP340] "Specification". */
  int ret = 1;
  fe_t x;

  ret &= fe_import(x, raw);
  ret &= wge_set_x(r, x, 0);

  return ret;
}

static int
wge_export_x(unsigned char *raw, const wge_t *p) {
  /* [BIP340] "Specification". */
  fe_export(raw, p->x);

  return p->inf ^ 1;
}

static void
wge_select(wge_t *p3,
           const wge_t *p1,
           const wge_t *p2,
           int flag) {
  int m = -int_barrier(flag != 0);

  fe_select(p3->x, p1->x, p2->x, flag);
  fe_select(p3->y, p1->y, p2->y, flag);

  p3->inf = (p1->inf & ~m) | (p2->inf & m);
}

static void
wge_set(wge_t *r, const wge_t *p) {
  fe_set(r->x, p->x);
  fe_set(r->y, p->y);

  r->inf = p->inf;
}

BTC_UNUSED static int
wge_equal(const wge_t *p1, const wge_t *p2) {
  int ret = 1;

  /* P != O, Q != O */
  ret &= (p1->inf | p2->inf) ^ 1;

  /* X1 = X2 */
  ret &= fe_equal(p1->x, p2->x);

  /* Y1 = Y2 */
  ret &= fe_equal(p1->y, p2->y);

  return ret | (p1->inf & p2->inf);
}

static int
wge_is_zero(const wge_t *p) {
  return p->inf;
}

static int
wge_is_even(const wge_t *p) {
  return (fe_is_odd(p->y) ^ 1) & (p->inf ^ 1);
}

static int
wge_equal_x(const wge_t *p, const fe_t x) {
  return fe_equal(p->x, x) & (p->inf ^ 1);
}

static void
wge_neg(wge_t *r, const wge_t *p) {
  fe_set(r->x, p->x);
  fe_neg(r->y, p->y);

  r->inf = p->inf;
}

static void
wge_dbl_var(wge_t *p3, const wge_t *p1) {
  /* [GECC] Page 80, Section 3.1.2.
   *
   * Addition Law (doubling):
   *
   *   l = (3 * x1^2 + a) / (2 * y1)
   *   x3 = l^2 - 2 * x1
   *   y3 = l * (x1 - x3) - y1
   *
   * 1I + 2M + 2S + 3A + 2*2 + 1*3
   */
  fe_t z, l, x3, y3;

  /* P = O */
  if (p1->inf) {
    wge_zero(p3);
    return;
  }

  /* L = (3 * X1^2 + a) / (2 * Y1) */
  fe_add(z, p1->y, p1->y);
  ASSERT(fe_invert_var(z, z));
  fe_sqr(l, p1->x);
  fe_mul3(l, l);
  fe_mul(l, l, z);

  /* X3 = L^2 - 2 * X1 */
  fe_sqr(x3, l);
  fe_sub(x3, x3, p1->x);
  fe_sub(x3, x3, p1->x);

  /* Y3 = L * (X1 - X3) - Y1 */
  fe_sub_nc(y3, p1->x, x3);
  fe_mul(y3, y3, l);
  fe_sub(y3, y3, p1->y);

  fe_set(p3->x, x3);
  fe_set(p3->y, y3);

  p3->inf = 0;
}

static void
wge_add_var(wge_t *p3, const wge_t *p1, const wge_t *p2) {
  /* [GECC] Page 80, Section 3.1.2.
   *
   * Addition Law:
   *
   *   l = (y1 - y2) / (x1 - x2)
   *   x3 = l^2 - x1 - x2
   *   y3 = l * (x1 - x3) - y1
   *
   * 1I + 2M + 1S + 6A
   */
  fe_t z, l, x3, y3;

  /* O + P = P */
  if (p1->inf) {
    wge_set(p3, p2);
    return;
  }

  /* P + O = P */
  if (p2->inf) {
    wge_set(p3, p1);
    return;
  }

  /* P + P, P + -P */
  if (fe_equal(p1->x, p2->x)) {
    if (fe_equal(p1->y, p2->y)) {
      /* P + P = 2P */
      wge_dbl_var(p3, p1);
    } else {
      /* P + -P = O */
      wge_zero(p3);
    }
    return;
  }

  /* X1 != X2, Y1 = Y2 */
  if (fe_equal(p1->y, p2->y)) {
    /* X3 = -X1 - X2 */
    fe_neg(x3, p1->x);
    fe_sub(x3, x3, p2->x);

    /* Y3 = -Y1 */
    fe_neg(y3, p1->y);

    /* Skip the inverse. */
    fe_set(p3->x, x3);
    fe_set(p3->y, y3);

    p3->inf = 0;

    return;
  }

  /* L = (Y1 - Y2) / (X1 - X2) */
  fe_sub(z, p1->x, p2->x);
  ASSERT(fe_invert_var(z, z));
  fe_sub_nc(l, p1->y, p2->y);
  fe_mul(l, l, z);

  /* X3 = L^2 - X1 - X2 */
  fe_sqr(x3, l);
  fe_sub(x3, x3, p1->x);
  fe_sub(x3, x3, p2->x);

  /* Y3 = L * (X1 - X3) - Y1 */
  fe_sub_nc(y3, p1->x, x3);
  fe_mul(y3, y3, l);
  fe_sub(y3, y3, p1->y);

  fe_set(p3->x, x3);
  fe_set(p3->y, y3);

  p3->inf = 0;
}

BTC_UNUSED static void
wge_sub_var(wge_t *p3, const wge_t *p1, const wge_t *p2) {
  wge_t p4;
  wge_neg(&p4, p2);
  wge_add_var(p3, p1, &p4);
}

BTC_UNUSED static void
wge_dbl(wge_t *p3, const wge_t *p1) {
  /* [GECC] Page 80, Section 3.1.2.
   *
   * Addition Law (doubling):
   *
   *   l = (3 * x1^2 + a) / (2 * y1)
   *   x3 = l^2 - 2 * x1
   *   y3 = l * (x1 - x3) - y1
   *
   * 1I + 2M + 2S + 3A + 2*2 + 1*3
   */
  int inf = p1->inf;
  fe_t z, l, x3, y3;

  /* L = (3 * X1^2 + a) / (2 * Y1) */
  fe_add_nc(z, p1->y, p1->y);
  fe_invert(z, z);
  fe_sqr(l, p1->x);
  fe_mul3(l, l);
  fe_mul(l, l, z);

  /* X3 = L^2 - 2 * X1 */
  fe_sqr(x3, l);
  fe_sub(x3, x3, p1->x);
  fe_sub(x3, x3, p1->x);

  /* Y3 = L * (X1 - X3) - Y1 */
  fe_sub_nc(y3, p1->x, x3);
  fe_mul(y3, y3, l);
  fe_sub(y3, y3, p1->y);

  /* Ensure (0, 0) for infinity. */
  fe_select(p3->x, x3, field_zero, inf);
  fe_select(p3->y, y3, field_zero, inf);

  p3->inf = inf;
}

static void
wge_add(wge_t *p3, const wge_t *p1, const wge_t *p2) {
  /* [SIDE1] Page 5, Section 3.
   * [SIDE2] Page 4, Section 3.
   *
   * Addition Law (unified):
   *
   *   l = ((x1 + x2)^2 - (x1 * x2) + a) / (y1 + y2)
   *   x3 = l^2 - x1 - x2
   *   y3 = l * (x1 - x3) - y1
   *
   * If x1 != x2 and y1 = -y2, we switch
   * back to the regular addition lambda:
   *
   *   l = (y1 - y2) / (x1 - x2)
   *
   * This case specifically occurs when:
   *
   *   x2 = (-x1 - sqrt(-3 * x1^2 - 4 * a)) / 2
   *   y2 = -y1
   *
   * Which causes the lambda to evaluate to `0 / 0`.
   *
   * 1I + 3M + 2S + 10A
   */
  int degenerate, zero, neg, inf;
  fe_t m, l, r, x3, y3;

  /* M = Y1 + Y2 */
  fe_add(m, p1->y, p2->y);

  /* R = (X1 + X2)^2 - X1 * X2 + a */
  fe_mul(l, p1->x, p2->x);
  fe_add_nc(r, p1->x, p2->x);
  fe_sqr(r, r);
  fe_sub(r, r, l);

  /* Check for degenerate case (X1 != X2, Y1 = -Y2). */
  degenerate = fe_is_zero(m) & fe_is_zero(r);

  /* M = X1 - X2 (if degenerate) */
  fe_sub_nc(l, p1->x, p2->x);
  fe_select(m, m, l, degenerate);

  /* R = Y1 - Y2 = 2 * Y1 (if degenerate) */
  fe_add_nc(l, p1->y, p1->y);
  fe_select(r, r, l, degenerate);

  /* L = R / M */
  zero = fe_invert(m, m) ^ 1;
  fe_mul(l, r, m);

  /* Check for negation (X1 = X2, Y1 = -Y2). */
  neg = zero & ((p1->inf | p2->inf) ^ 1);

  /* X3 = L^2 - X1 - X2 */
  fe_sqr(x3, l);
  fe_sub(x3, x3, p1->x);
  fe_sub(x3, x3, p2->x);

  /* Y3 = L * (X1 - X3) - Y1 */
  fe_sub_nc(y3, p1->x, x3);
  fe_mul(y3, y3, l);
  fe_sub(y3, y3, p1->y);

  /* Check for infinity. */
  inf = neg | (p1->inf & p2->inf);

  /* Case 1: O + P = P */
  fe_select(x3, x3, p2->x, p1->inf);
  fe_select(y3, y3, p2->y, p1->inf);

  /* Case 2: P + O = P */
  fe_select(x3, x3, p1->x, p2->inf);
  fe_select(y3, y3, p1->y, p2->inf);

  /* Case 3 & 4: P + -P = O, O + O = O */
  fe_select(x3, x3, field_zero, inf);
  fe_select(y3, y3, field_zero, inf);

  fe_set(p3->x, x3);
  fe_set(p3->y, y3);

  p3->inf = inf;
}

static void
wge_sub(wge_t *p3, const wge_t *p1, const wge_t *p2) {
  wge_t p4;
  wge_neg(&p4, p2);
  wge_add(p3, p1, &p4);
}

static void
wge_set_jge(wge_t *r, const jge_t *p) {
  /* https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
   * 1I + 3M + 1S
   */
  fe_t a, aa;

  /* A = 1 / Z1 */
  fe_invert(a, p->z);

  /* AA = A^2 */
  fe_sqr(aa, a);

  /* X3 = X1 * AA */
  fe_mul(r->x, p->x, aa);

  /* Y3 = Y1 * AA * A */
  fe_mul(r->y, p->y, aa);
  fe_mul(r->y, r->y, a);

  r->inf = p->inf;
}

static void
wge_set_jge_var(wge_t *r, const jge_t *p) {
  /* https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
   * 1I + 3M + 1S
   */
  fe_t a, aa;

  /* P = O */
  if (p->inf) {
    wge_zero(r);
    return;
  }

  /* Z = 1 */
  if (p->aff) {
    fe_set(r->x, p->x);
    fe_set(r->y, p->y);
    r->inf = 0;
    return;
  }

  /* A = 1 / Z1 */
  ASSERT(fe_invert_var(a, p->z));

  /* AA = A^2 */
  fe_sqr(aa, a);

  /* X3 = X1 * AA */
  fe_mul(r->x, p->x, aa);

  /* Y3 = Y1 * AA * A */
  fe_mul(r->y, p->y, aa);
  fe_mul(r->y, r->y, a);

  r->inf = 0;
}

static void
wge_endo_beta(wge_t *r, const wge_t *p) {
  fe_mul(r->x, p->x, curve_beta);
  fe_set(r->y, p->y);

  r->inf = p->inf;
}

/*
 * Short Weierstrass Jacobian Point
 */

static void
jge_zero(jge_t *r) {
  fe_set(r->x, field_one);
  fe_set(r->y, field_one);
  fe_zero(r->z);

  r->inf = 1;
  r->aff = 0;
}

static void
jge_select(jge_t *p3,
           const jge_t *p1,
           const jge_t *p2,
           int flag) {
  int m = -int_barrier(flag != 0);

  fe_select(p3->x, p1->x, p2->x, flag);
  fe_select(p3->y, p1->y, p2->y, flag);
  fe_select(p3->z, p1->z, p2->z, flag);

  p3->inf = (p1->inf & ~m) | (p2->inf & m);
  p3->aff = (p1->aff & ~m) | (p2->aff & m);
}

static void
jge_set(jge_t *r, const jge_t *p) {
  fe_set(r->x, p->x);
  fe_set(r->y, p->y);
  fe_set(r->z, p->z);

  r->inf = p->inf;
  r->aff = p->aff;
}

static int
jge_is_zero(const jge_t *p) {
  return p->inf;
}

BTC_UNUSED static int
jge_equal(const jge_t *p1, const jge_t *p2) {
  fe_t z1, z2, e1, e2;
  int ret = 1;

  /* P != O, Q != O */
  ret &= (p1->inf | p2->inf) ^ 1;

  /* X1 * Z2^2 = X2 * Z1^2 */
  fe_sqr(z1, p1->z);
  fe_sqr(z2, p2->z);
  fe_mul(e1, p1->x, z2);
  fe_mul(e2, p2->x, z1);

  ret &= fe_equal(e1, e2);

  /* Y1 * Z2^3 = Y2 * Z1^3 */
  fe_mul(z1, z1, p1->z);
  fe_mul(z2, z2, p2->z);
  fe_mul(e1, p1->y, z2);
  fe_mul(e2, p2->y, z1);

  ret &= fe_equal(e1, e2);

  return ret | (p1->inf & p2->inf);
}

static int
jge_equal_r_var(const jge_t *p, const sc_t x) {
  /* Optimized function for checking `x(R) == r`
   * in the jacobian space (where `r` has been
   * previously reduced by `n`).
   *
   * There are two possibilities, assuming `p > n`
   * and `p < 2n`. The first is the obvious:
   *
   *   x(R) == r * z(R)^2 in F(p)
   *
   * Otherwise, if `r < p mod n`, the following
   * possibility also applies:
   *
   *   x(R) == (r + n) * z(R)^2 in F(p)
   *
   * If `p <= n`, only the first possibility
   * applies.
   *
   * If `p >= 2n`, there are more than two
   * possibilities and we skip this optimization.
   *
   * See: https://github.com/bitcoin-core/secp256k1/commit/ce7eb6f
   */
  fe_t rx, rn, zz;

  if (p->inf)
    return 0;

  if (!fe_set_sc(rx, x))
    return 0;

  fe_sqr(zz, p->z);
  fe_mul(rx, rx, zz);

  if (fe_equal(p->x, rx))
    return 1;

  if (sc_cmp_var(x, curve_sc_p) >= 0)
    return 0;

  fe_mul(rn, curve_fe_n, zz);
  fe_add(rx, rx, rn);

  return fe_equal(p->x, rx);
}

static void
jge_neg(jge_t *r, const jge_t *p) {
  fe_set(r->x, p->x);
  fe_neg(r->y, p->y);
  fe_set(r->z, p->z);

  /* Ensure (1, 1, 0) for infinity. */
  fe_select(r->y, r->y, field_one, p->inf);

  r->inf = p->inf;
  r->aff = p->aff;
}

static void
jge_neg_cond(jge_t *r, const jge_t *p, int flag) {
  fe_set(r->x, p->x);
  fe_neg_cond(r->y, p->y, flag);
  fe_set(r->z, p->z);

  /* Ensure (1, 1, 0) for infinity. */
  fe_select(r->y, r->y, field_one, p->inf);

  r->inf = p->inf;
  r->aff = p->aff;
}

static void
jge_dbl0(jge_t *p3, const jge_t *p1) {
  /* Assumes a = 0.
   * https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
   * 2M + 5S + 6A + 3*2 + 1*3 + 1*8
   */
  fe_t a, b, c, d, e, f;

  /* A = X1^2 */
  fe_sqr(a, p1->x);

  /* B = Y1^2 */
  fe_sqr(b, p1->y);

  /* C = B^2 */
  fe_sqr(c, b);

  /* D = 2 * ((X1 + B)^2 - A - C) */
  fe_add_nc(d, p1->x, b);
  fe_sqr(d, d);
  fe_sub(d, d, a);
  fe_sub(d, d, c);
  fe_add(d, d, d);

  /* E = 3 * A */
  fe_mul3(e, a);

  /* F = E^2 */
  fe_sqr(f, e);

  /* Z3 = 2 * Y1 * Z1 */
  fe_add_nc(a, p1->y, p1->y);
  fe_mul(p3->z, p1->z, a);

  /* X3 = F - 2 * D */
  fe_sub(p3->x, f, d);
  fe_sub(p3->x, p3->x, d);

  /* Y3 = E * (D - X3) - 8 * C */
  fe_sub_nc(d, d, p3->x);
  fe_mul8(c, c);
  fe_mul(p3->y, e, d);
  fe_sub(p3->y, p3->y, c);
}

static void
jge_dbl_var(jge_t *p3, const jge_t *p1) {
  /* P = O */
  if (p1->inf) {
    jge_zero(p3);
    return;
  }

  jge_dbl0(p3, p1);

  p3->inf = 0;
  p3->aff = 0;
}

static void
jge_addsub_var(jge_t *p3, const jge_t *p1, const jge_t *p2, int sign) {
  /* No assumptions.
   * https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
   * 12M + 4S + 6A + 1*2
   */
  fe_t t1, t2, t3, t4, t5, t6;

#define z1z1 t1
#define z2z2 t2
#define u1   t3
#define u2   t4
#define s1   t5
#define s2   t6
#define h    t1 /* <- z1z1 */
#define r    t2 /* <- z2z2 */
#define hh   t4 /* <- u2 */
#define hhh  t6 /* <- s2 */
#define v    t3 /* <- u1 */

  /* Z1Z1 = Z1^2 */
  fe_sqr(z1z1, p1->z);

  /* Z2Z2 = Z2^2 */
  fe_sqr(z2z2, p2->z);

  /* U1 = X1 * Z2Z2 */
  fe_mul(u1, p1->x, z2z2);

  /* U2 = X2 * Z1Z1 */
  fe_mul(u2, p2->x, z1z1);

  /* S1 = Y1 * Z2 * Z2Z2 */
  fe_mul(s1, p1->y, p2->z);
  fe_mul(s1, s1, z2z2);

  /* S2 = Y2 * Z1 * Z1Z1 */
  fe_mul(s2, p2->y, p1->z);
  fe_mul(s2, s2, z1z1);

  /* H = U2 - U1 */
  fe_sub(h, u2, u1);

  /* r = S2 - S1 */
  if (sign)
    fe_sub_nc(r, s2, s1);
  else
    fe_add_nc(r, s2, s1);

  /* H = 0 */
  if (fe_is_zero(h)) {
    fe_carry(r, r);

    if (fe_is_zero(r))
      jge_dbl_var(p3, p1);
    else
      jge_zero(p3);

    return;
  }

  /* HH = H^2 */
  fe_sqr(hh, h);

  /* HHH = H * HH */
  fe_mul(hhh, h, hh);

  /* V = U1 * HH */
  fe_mul(v, u1, hh);

  /* X3 = r^2 - HHH - 2 * V */
  fe_sqr(p3->x, r);
  fe_sub(p3->x, p3->x, hhh);
  fe_sub(p3->x, p3->x, v);
  fe_sub(p3->x, p3->x, v);

  /* Y3 = r * (V - X3) - S1 * HHH */
  if (sign)
    fe_sub_nc(v, v, p3->x);
  else
    fe_sub_nc(v, p3->x, v);

  fe_mul(s1, s1, hhh);
  fe_mul(p3->y, r, v);
  fe_sub(p3->y, p3->y, s1);

  /* Z3 = Z1 * Z2 * H */
  fe_mul(p3->z, p1->z, p2->z);
  fe_mul(p3->z, p3->z, h);

  p3->inf = 0;
  p3->aff = 0;

#undef z1z1
#undef z2z2
#undef u1
#undef u2
#undef s1
#undef s2
#undef h
#undef r
#undef hh
#undef hhh
#undef v
}

static void
jge_add_var(jge_t *p3, const jge_t *p1, const jge_t *p2) {
  /* O + P = P */
  if (p1->inf) {
    jge_set(p3, p2);
    return;
  }

  /* P + O = P */
  if (p2->inf) {
    jge_set(p3, p1);
    return;
  }

  /* Z2 = 1 */
  if (p2->aff) {
    jge_mixed_addsub_var(p3, p1, p2->x, p2->y, 1);
    return;
  }

  jge_addsub_var(p3, p1, p2, 1);
}

static void
jge_sub_var(jge_t *p3, const jge_t *p1, const jge_t *p2) {
  /* O - P = -P */
  if (p1->inf) {
    jge_neg(p3, p2);
    return;
  }

  /* P - O = P */
  if (p2->inf) {
    jge_set(p3, p1);
    return;
  }

  /* Z2 = 1 */
  if (p2->aff) {
    jge_mixed_addsub_var(p3, p1, p2->x, p2->y, 0);
    return;
  }

  jge_addsub_var(p3, p1, p2, 0);
}

static void
jge_mixed_addsub_var(jge_t *p3,
                     const jge_t *p1,
                     const fe_t x2,
                     const fe_t y2,
                     int sign) {
  /* Assumes Z2 = 1.
   * https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd
   * 8M + 3S + 6A + 5*2
   */
  fe_t t1, t2, t3, t4;

#define z1z1 t1
#define u2   t2
#define s2   t3
#define h    t4
#define r    t1 /* <- z1z1 */
#define i    t2 /* <- u2 */
#define j    t3 /* <- s2 */
#define v    t2 /* <- i */

  /* Z1Z1 = Z1^2 */
  fe_sqr(z1z1, p1->z);

  /* U2 = X2 * Z1Z1 */
  fe_mul(u2, x2, z1z1);

  /* S2 = Y2 * Z1 * Z1Z1 */
  fe_mul(s2, y2, p1->z);
  fe_mul(s2, s2, z1z1);

  /* H = U2 - X1 */
  fe_sub(h, u2, p1->x);

  /* r = 2 * (S2 - Y1) */
  if (sign)
    fe_sub(r, s2, p1->y);
  else
    fe_add(r, s2, p1->y);

  /* H = 0 */
  if (fe_is_zero(h)) {
    if (fe_is_zero(r))
      jge_dbl_var(p3, p1);
    else
      jge_zero(p3);

    return;
  }

  fe_add_nc(r, r, r);

  /* I = (2 * H)^2 */
  fe_add_nc(i, h, h);
  fe_mul(p3->z, p1->z, i);
  fe_sqr(i, i);

  /* J = H * I */
  fe_mul(j, h, i);

  /* V = X1 * I */
  fe_mul(v, i, p1->x);

  /* X3 = r^2 - J - 2 * V */
  fe_sqr(p3->x, r);
  fe_sub(p3->x, p3->x, j);
  fe_sub(p3->x, p3->x, v);
  fe_sub(p3->x, p3->x, v);

  /* Y3 = r * (V - X3) - 2 * Y1 * J */
  if (sign)
    fe_sub_nc(v, v, p3->x);
  else
    fe_sub_nc(v, p3->x, v);

  fe_mul(j, j, p1->y);
  fe_mul(p3->y, r, v);
  fe_sub(p3->y, p3->y, j);
  fe_sub(p3->y, p3->y, j);

  /* Z3 = 2 * Z1 * H */
  /* Computed above. */

  p3->inf = 0;
  p3->aff = 0;

#undef z1z1
#undef u2
#undef s2
#undef h
#undef r
#undef i
#undef j
#undef v
}

static void
jge_mixed_add_var(jge_t *p3, const jge_t *p1, const wge_t *p2) {
  /* O + P = P */
  if (p1->inf) {
    jge_set_wge(p3, p2);
    return;
  }

  /* P + O = P */
  if (p2->inf) {
    jge_set(p3, p1);
    return;
  }

  jge_mixed_addsub_var(p3, p1, p2->x, p2->y, 1);
}

static void
jge_mixed_sub_var(jge_t *p3, const jge_t *p1, const wge_t *p2) {
  /* O - P = -P */
  if (p1->inf) {
    jge_set_wge(p3, p2);
    jge_neg(p3, p3);
    return;
  }

  /* P - O = P */
  if (p2->inf) {
    jge_set(p3, p1);
    return;
  }

  jge_mixed_addsub_var(p3, p1, p2->x, p2->y, 0);
}

static void
jge_dbl(jge_t *p3, const jge_t *p1) {
  int inf = p1->inf;

  jge_dbl0(p3, p1);

  p3->inf = inf;
  p3->aff = 0;
}

static void
jge_add(jge_t *p3, const jge_t *p1, const jge_t *p2) {
  /* Strongly unified Jacobian addition (Brier and Joye).
   *
   * [SIDE1] Page 6, Corollary 2, Section 3.
   * [SIDE2] Page 4, Section 3.
   *
   * Brier and Joye give us a projective formula[1]:
   *
   *   U1 = X1 * Z2
   *   U2 = X2 * Z1
   *   S1 = Y1 * Z2
   *   S2 = Y2 * Z1
   *   Z = Z1 * Z2
   *   T = U1 + U2
   *   M = S1 + S2
   *   R = T^2 - U1 * U2 + a * Z^2
   *   F = Z * M
   *   L = M * F
   *   G = T * L
   *   W = R^2 - G
   *   X3 = 2 * F * W
   *   Y3 = R * (G - 2 * W) - L^2
   *   Z3 = 2 * F^3
   *
   * Modifying for jacobian coordinates, we get[2]:
   *
   *   Z1Z1 = Z1^2
   *   Z2Z2 = Z2^2
   *   U1 = X1 * Z2Z2
   *   U2 = X2 * Z1Z1
   *   S1 = Y1 * Z2Z2 * Z2
   *   S2 = Y2 * Z1Z1 * Z1
   *   Z = Z1 * Z2
   *   T = U1 + U2
   *   M = S1 + S2
   *   R = T^2 - U1 * U2 + a * Z^4
   *   F = Z * M
   *   L = M^2
   *   G = T * L
   *   W = R^2 - G
   *   LL = L^2
   *   X3 = 4 * W
   *   Y3 = 4 * (R * (G - 2 * W) - LL)
   *   Z3 = 2 * F
   *
   * If M = 0, R = 0 is detected, the following
   * substitutions must be performed[3][4]:
   *
   *   M = U1 - U2
   *   R = S1 - S2 (= 2 * S1)
   *   LL = 0
   *
   * This avoids the degenerate case of x1 != x2,
   * y1 = -y2, which can occur when:
   *
   *   x2 = (-x1 - sqrt(-3 * x1^2 - 4 * a)) / 2
   *   y2 = -y1
   *
   * This causes the lambda to evaluate to `0 / 0`.
   * On a GLV curve like secp256k1, this can imply
   * x2 = x1 * beta (i.e. P2 = -P1 * lambda).
   *
   * Note that infinity must be handled explicitly
   * with constant time selections.
   *
   * Cost: 11M + 8S + 7A + 1*a + 2*4 + 2*2 (a != 0)
   *       11M + 6S + 6A + 2*4 + 2*2 (a = 0)
   *
   * Possible to compute with 8 field registers.
   *
   * [1] https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-2002-bj
   * [2] https://github.com/bitcoin-core/secp256k1/blob/ee9e68c/src/group_impl.h#L525
   * [3] https://github.com/bitcoin-core/secp256k1/pull/261
   * [4] https://github.com/bitcoin-core/secp256k1/commit/5de4c5d
   */
  fe_t t1, t2, t3, t4, t5, t6, t7, t8;
  int degenerate, inf;

#define z1z1 t1
#define z2z2 t2
#define u1   t3
#define u2   t4
#define s1   t5
#define s2   t6
#define z0   t7
#define t    t8
#define m    t1 /* <- z1z1 */
#define r    t2 /* <- z2z2 */
#define f    t3 /* <- u1 */
#define l    t6 /* <- s2 */
#define g    t4 /* <- u2 */
#define w    t5 /* <- s1 */
#define ll   t6 /* <- l */
#define x3   t7 /* <- z0 */
#define y3   t8 /* <- t */
#define z3   t1 /* <- m */

  /* Z1Z1 = Z1^2 */
  fe_sqr(z1z1, p1->z);

  /* Z2Z2 = Z2^2 */
  fe_sqr(z2z2, p2->z);

  /* U1 = X1 * Z2Z2 */
  fe_mul(u1, p1->x, z2z2);

  /* U2 = X2 * Z1Z1 */
  fe_mul(u2, p2->x, z1z1);

  /* S1 = Y1 * Z2Z2 * Z2 */
  fe_mul(s1, p1->y, z2z2);
  fe_mul(s1, s1, p2->z);

  /* S2 = Y2 * Z1Z1 * Z1 */
  fe_mul(s2, p2->y, z1z1);
  fe_mul(s2, s2, p1->z);

  /* Z = Z1 * Z2 */
  fe_mul(z0, p1->z, p2->z);

  /* T = U1 + U2 */
  fe_add_nc(t, u1, u2);

  /* M = S1 + S2 */
  fe_add(m, s1, s2);

  /* R = T^2 - U1 * U2 + a * Z^4 */
  fe_sqr(r, t);
  fe_mul(l, u1, u2);
  fe_sub(r, r, l);

  /* Check for degenerate case (X1 != X2, Y1 = -Y2). */
  degenerate = fe_is_zero(m) & fe_is_zero(r);

  /* M = U1 - U2 (if degenerate) */
  fe_sub_nc(l, u1, u2);
  fe_select(m, m, l, degenerate);

  /* R = S1 - S2 = 2 * S1 (if degenerate) */
  fe_add_nc(l, s1, s1);
  fe_select(r, r, l, degenerate);

  /* F = Z * M */
  fe_mul(f, z0, m);

  /* L = M^2 */
  fe_sqr(l, m);

  /* G = T * L */
  fe_mul(g, t, l);

  /* W = R^2 - G */
  fe_sqr(w, r);
  fe_sub(w, w, g);

  /* LL = L^2 */
  fe_sqr(ll, l);

  /* LL = 0 (if degenerate) */
  fe_select(ll, ll, field_zero, degenerate);

  /* X3 = 4 * W */
  fe_mul4(x3, w);

  /* Y3 = 4 * (R * (G - 2 * W) - LL) */
  fe_sub(y3, g, w);
  fe_sub_nc(y3, y3, w);
  fe_mul(y3, y3, r);
  fe_sub_nc(y3, y3, ll);
  fe_mul4(y3, y3);

  /* Z3 = 2 * F */
  fe_add(z3, f, f);

  /* Check for infinity. */
  inf = fe_is_zero(z3) & ((p1->inf | p2->inf) ^ 1);

  /* Case 1: O + P = P */
  fe_select(x3, x3, p2->x, p1->inf);
  fe_select(y3, y3, p2->y, p1->inf);
  fe_select(z3, z3, p2->z, p1->inf);

  /* Case 2: P + O = P */
  fe_select(x3, x3, p1->x, p2->inf);
  fe_select(y3, y3, p1->y, p2->inf);
  fe_select(z3, z3, p1->z, p2->inf);

  /* Case 3: P + -P = O */
  fe_select(x3, x3, field_one, inf);
  fe_select(y3, y3, field_one, inf);
  fe_select(z3, z3, field_zero, inf);

  /* R = (X3, Y3, Z3) */
  fe_set(p3->x, x3);
  fe_set(p3->y, y3);
  fe_set(p3->z, z3);

  p3->inf = inf | (p1->inf & p2->inf);
  p3->aff = 0;

#undef z1z1
#undef z2z2
#undef u1
#undef u2
#undef s1
#undef s2
#undef z0
#undef t
#undef m
#undef r
#undef f
#undef l
#undef g
#undef w
#undef ll
#undef x3
#undef y3
#undef z3
}

BTC_UNUSED static void
jge_sub(jge_t *p3, const jge_t *p1, const jge_t *p2) {
  jge_t p4;
  jge_neg(&p4, p2);
  jge_add(p3, p1, &p4);
}

static void
jge_mixed_add(jge_t *p3, const jge_t *p1, const wge_t *p2) {
  /* Strongly unified mixed addition (Brier and Joye).
   *
   * [SIDE1] Page 6, Corollary 2, Section 3.
   * [SIDE2] Page 4, Section 3.
   *
   * Modifying the formula from `jge_add`, we get:
   *
   *   Z1Z1 = Z1^2
   *   U2 = X2 * Z1Z1
   *   S2 = Y2 * Z1Z1 * Z1
   *   T = X1 + U2
   *   M = Y1 + S2
   *   R = T^2 - X1 * U2 + a * Z1Z1^2
   *   F = Z1 * M
   *   L = M^2
   *   G = T * L
   *   W = R^2 - G
   *   LL = L^2
   *   X3 = 4 * W
   *   Y3 = 4 * (R * (G - 2 * W) - LL)
   *   Z3 = 2 * F
   *
   * If M = 0, R = 0 is detected, the following
   * substitutions must be performed:
   *
   *   M = X1 - U2
   *   R = Y1 - S2 (= 2 * Y1)
   *   LL = 0
   *
   * Note that infinity must be handled explicitly
   * with constant time selections.
   *
   * Cost: 7M + 6S + 7A + 1*a + 2*4 + 2*2 (a != 0)
   *       7M + 5S + 6A + 2*4 + 2*2 (a = 0)
   *
   * Possible to compute with 6 field registers.
   */
  fe_t t1, t2, t3, t4, t5, t6;
  int degenerate, inf;

#define z1z1 t1
#define u2   t2
#define s2   t3
#define t    t4
#define m    t5
#define r    t6
#define f    t1 /* <- z1z1 */
#define l    t3 /* <- s2 */
#define g    t2 /* <- u2 */
#define w    t4 /* <- t */
#define ll   t3 /* <- l */
#define x3   t5 /* <- m */
#define y3   t2 /* <- g */
#define z3   t1 /* <- f */

  /* Z1Z1 = Z1^2 */
  fe_sqr(z1z1, p1->z);

  /* U2 = X2 * Z1Z1 */
  fe_mul(u2, p2->x, z1z1);

  /* S2 = Y2 * Z1Z1 * Z1 */
  fe_mul(s2, p2->y, z1z1);
  fe_mul(s2, s2, p1->z);

  /* T = X1 + U2 */
  fe_add_nc(t, p1->x, u2);

  /* M = Y1 + S2 */
  fe_add(m, p1->y, s2);

  /* R = T^2 - X1 * U2 + a * Z1Z1^2 */
  fe_sqr(r, t);
  fe_mul(l, p1->x, u2);
  fe_sub(r, r, l);

  /* Check for degenerate case (X1 != X2, Y1 = -Y2). */
  degenerate = fe_is_zero(m) & fe_is_zero(r);

  /* M = X1 - U2 (if degenerate) */
  fe_sub_nc(l, p1->x, u2);
  fe_select(m, m, l, degenerate);

  /* R = Y1 - S2 = 2 * Y1 (if degenerate) */
  fe_add_nc(l, p1->y, p1->y);
  fe_select(r, r, l, degenerate);

  /* F = Z1 * M */
  fe_mul(f, p1->z, m);

  /* L = M^2 */
  fe_sqr(l, m);

  /* G = T * L */
  fe_mul(g, t, l);

  /* W = R^2 - G */
  fe_sqr(w, r);
  fe_sub(w, w, g);

  /* LL = L^2 */
  fe_sqr(ll, l);

  /* LL = 0 (if degenerate) */
  fe_select(ll, ll, field_zero, degenerate);

  /* X3 = 4 * W */
  fe_mul4(x3, w);

  /* Y3 = 4 * (R * (G - 2 * W) - LL) */
  fe_sub(y3, g, w);
  fe_sub_nc(y3, y3, w);
  fe_mul(y3, y3, r);
  fe_sub_nc(y3, y3, ll);
  fe_mul4(y3, y3);

  /* Z3 = 2 * F */
  fe_add(z3, f, f);

  /* Check for infinity. */
  inf = fe_is_zero(z3) & ((p1->inf | p2->inf) ^ 1);

  /* Case 1: O + P = P */
  fe_select(x3, x3, p2->x, p1->inf);
  fe_select(y3, y3, p2->y, p1->inf);
  fe_select(z3, z3, field_one, p1->inf);

  /* Case 2: P + O = P */
  fe_select(x3, x3, p1->x, p2->inf);
  fe_select(y3, y3, p1->y, p2->inf);
  fe_select(z3, z3, p1->z, p2->inf);

  /* Case 3: P + -P = O */
  fe_select(x3, x3, field_one, inf);
  fe_select(y3, y3, field_one, inf);
  fe_select(z3, z3, field_zero, inf);

  /* R = (X3, Y3, Z3) */
  fe_set(p3->x, x3);
  fe_set(p3->y, y3);
  fe_set(p3->z, z3);

  p3->inf = inf | (p1->inf & p2->inf);
  p3->aff = 0;

#undef z1z1
#undef u2
#undef s2
#undef t
#undef m
#undef r
#undef f
#undef l
#undef g
#undef w
#undef ll
#undef x3
#undef y3
#undef z3
}

BTC_UNUSED static void
jge_mixed_sub(jge_t *p3, const jge_t *p1, const wge_t *p2) {
  wge_t p4;
  wge_neg(&p4, p2);
  jge_mixed_add(p3, p1, &p4);
}

static void
jge_set_wge(jge_t *r, const wge_t *p) {
  fe_select(r->x, p->x, field_one, p->inf);
  fe_select(r->y, p->y, field_one, p->inf);
  fe_select(r->z, field_one, field_zero, p->inf);

  r->inf = p->inf;
  r->aff = p->inf ^ 1;
}

BTC_UNUSED static int
jge_validate(const jge_t *p) {
  /* [GECC] Example 3.20, Page 88, Section 3. */
  fe_t x3, z2, z4, z6, lhs, rhs;

  /* y^2 = x^3 + a * x * z^4 + b * z^6 */
  fe_sqr(x3, p->x);
  fe_mul(x3, x3, p->x);
  fe_sqr(z2, p->z);
  fe_sqr(z4, z2);
  fe_mul(z6, z4, z2);
  fe_mul(z6, z6, curve_b);

  fe_sqr(lhs, p->y);
  fe_add(rhs, x3, z6);

  return fe_equal(lhs, rhs);
}

static void
jge_jsf_points_var(jge_t *out, const wge_t *p1) {
  wge_t p2, p3;

  /* Split point. */
  wge_endo_beta(&p2, p1);

  /* No inversion (Y1 = Y2). */
  wge_add_var(&p3, p1, &p2);

  /* Create comb for JSF. */
  jge_set_wge(&out[0], p1); /* 1 */
  jge_set_wge(&out[1], &p3); /* 3 */
  jge_mixed_sub_var(&out[2], &out[0], &p2); /* 5 */
  jge_set_wge(&out[3], &p2); /* 7 */
}

static void
jge_endo_beta(jge_t *r, const jge_t *p) {
  fe_mul(r->x, p->x, curve_beta);
  fe_set(r->y, p->y);
  fe_set(r->z, p->z);

  /* Ensure (1, 1, 0) for infinity. */
  fe_select(r->x, r->x, field_one, p->inf);

  r->inf = p->inf;
  r->aff = p->aff;
}

/*
 * Short Weierstrass Curve
 */

static void
wei_solve_y2(fe_t y2, const fe_t x) {
  /* [GECC] Page 89, Section 3.2.2. */
  /* y^2 = x^3 + a * x + b */
  fe_t x3;

  fe_sqr(x3, x);
  fe_mul(x3, x3, x);
  fe_add(y2, x3, curve_b);
}

static int
wei_validate_xy(const fe_t x, const fe_t y) {
  fe_t lhs, rhs;

  fe_sqr(lhs, y);

  wei_solve_y2(rhs, x);

  return fe_equal(lhs, rhs);
}

static void
wei_endo_split(sc_t k1, sc_t k2, const sc_t k) {
  /* Balanced length-two representation of a multiplier.
   *
   * [GECC] Algorithm 3.74, Page 127, Section 3.5.
   *
   * Computation:
   *
   *   c1 = round(b2 * k / n)
   *   c2 = round(-b1 * k / n)
   *   k1 = k - c1 * a1 - c2 * a2
   *   k2 = -c1 * b1 - c2 * b2
   *
   * It is possible to precompute[1] values in order
   * to avoid the round division[2][3][4].
   *
   * This involves precomputing `g1` and `g2` as:
   *
   *   d = a1 * b2 - b1 * a2
   *   t = ceil(log2(d+1)) + p
   *   g1 = round((2^t * b2) / d)
   *   g2 = round((2^t * b1) / d)
   *
   * Where:
   *
   *   `p` is the number of precision bits.
   *   `d` is equal to `n` (the curve order).
   *
   * `c1` and `c2` can then be computed as follows:
   *
   *   t = ceil(log2(n+1)) + p
   *   c1 = (k * g1) >> t
   *   c2 = -((k * g2) >> t)
   *   k1 = k - c1 * a1 - c2 * a2
   *   k2 = -c1 * b1 - c2 * b2
   *
   * Where `>>` is an _unsigned_ right shift. Also
   * note that the last bit discarded in the shift
   * must be stored. If it is 1, then add 1 to the
   * integer (absolute addition).
   *
   * libsecp256k1 modifies the computation further:
   *
   *   t = ceil(log2(n+1)) + p
   *   c1 = ((k * g1) >> t) * -b1
   *   c2 = ((k * -g2) >> t) * -b2
   *   k2 = c1 + c2
   *   k1 = k2 * -lambda + k
   *
   * Once the multiply and shift are complete, we
   * can use modular arithmetic for the rest of
   * the calculations (the mul+shift is done in
   * the integers, not mod n). This is nice as it
   * allows us to re-use existing scalar functions,
   * and our decomposition becomes a constant-time
   * calculation.
   *
   * Since the above computation is done mod n,
   * the resulting scalars must be reduced. Sign
   * correction is necessary outside of this
   * function.
   *
   * [1] [JCEN12] Page 5, Section 4.3.
   * [2] https://github.com/bitcoin-core/secp256k1/blob/0b70241/src/scalar_impl.h#L259
   * [3] https://github.com/bitcoin-core/secp256k1/pull/21
   * [4] https://github.com/bitcoin-core/secp256k1/pull/127
   */
  sc_t c1, c2;

  sc_mulshift(c1, k, curve_g1, 384);
  sc_mulshift(c2, k, curve_g2, 384); /* -g2 */

  sc_mul(c1, c1, curve_b1); /* -b1 */
  sc_mul(c2, c2, curve_b2); /* -b2 */

  sc_add(k2, c1, c2);
  sc_mul(k1, k2, curve_lambda); /* -lambda */
  sc_add(k1, k1, k);
}

static void
wei_jmul_g(jge_t *r, const sc_t k) {
  /* Fixed-base method for point multiplication.
   *
   * [ECPM] "Windowed method".
   * [GECC] Page 95, Section 3.3.
   *
   * Windows are appropriately shifted to avoid any
   * doublings. This reduces a 256 bit multiplication
   * down to 64 additions with a window size of 4.
   */
  const wge_t *wnds = curve_wnd_fixed;
  mp_bits_t i, j, b;
  wge_t t;

  /* Multiply in constant time. */
  jge_zero(r);
  wge_zero(&t);

  for (i = 0; i < FIXED_STEPS; i++) {
    b = sc_get_bits(k, i * FIXED_WIDTH, FIXED_WIDTH);

    for (j = 0; j < FIXED_SIZE; j++)
      wge_select(&t, &t, &wnds[i * FIXED_SIZE + j], j == b);

    jge_mixed_add(r, r, &t);
  }

  cleanse(&b, sizeof(b));
}

static void
wei_mul_g(wge_t *r, const sc_t k) {
  jge_t j;

  wei_jmul_g(&j, k);

  wge_set_jge(r, &j);
}

static void
wei_jmul(jge_t *r, const wge_t *p, const sc_t k) {
  /* Windowed method for point multiplication
   * (with endomorphism).
   *
   * [ECPM] "Windowed method".
   * [GECC] Page 95, Section 3.3.
   */
  jge_t wnd1[WND_SIZE]; /* 3456 bytes */
  jge_t wnd2[WND_SIZE]; /* 3456 bytes */
  mp_bits_t i, j, b1, b2;
  jge_t t1, t2;
  sc_t k1, k2;
  int s1, s2;

  /* Split scalar. */
  wei_endo_split(k1, k2, k);

  /* Minimize scalars. */
  s1 = sc_minimize(k1, k1);
  s2 = sc_minimize(k2, k2);

  /* Create window. */
  jge_zero(&wnd1[0]);
  jge_set_wge(&wnd1[1], p);

  for (i = 2; i < WND_SIZE; i += 2) {
    jge_dbl(&wnd1[i], &wnd1[i / 2]);
    jge_mixed_add(&wnd1[i + 1], &wnd1[i], p);
  }

  /* Create beta window. */
  jge_zero(&wnd2[0]);

  for (i = 1; i < WND_SIZE; i++)
    jge_endo_beta(&wnd2[i], &wnd1[i]);

  /* Adjust signs. */
  for (i = 1; i < WND_SIZE; i++) {
    jge_neg_cond(&wnd1[i], &wnd1[i], s1);
    jge_neg_cond(&wnd2[i], &wnd2[i], s2);
  }

  /* Multiply and add in constant time. */
  jge_zero(r);
  jge_zero(&t1);
  jge_zero(&t2);

  for (i = WND_STEPS - 1; i >= 0; i--) {
    b1 = sc_get_bits(k1, i * WND_WIDTH, WND_WIDTH);
    b2 = sc_get_bits(k2, i * WND_WIDTH, WND_WIDTH);

    for (j = 0; j < WND_SIZE; j++) {
      jge_select(&t1, &t1, &wnd1[j], j == b1);
      jge_select(&t2, &t2, &wnd2[j], j == b2);
    }

    if (i == WND_STEPS - 1) {
      jge_add(r, &t1, &t2);
    } else {
      for (j = 0; j < WND_WIDTH; j++)
        jge_dbl(r, r);

      jge_add(r, r, &t1);
      jge_add(r, r, &t2);
    }
  }

  sc_cleanse(k1);
  sc_cleanse(k2);

  cleanse(&b1, sizeof(b1));
  cleanse(&b2, sizeof(b2));
  cleanse(&s1, sizeof(s1));
  cleanse(&s2, sizeof(s2));
}

static void
wei_mul(wge_t *r, const wge_t *p, const sc_t k) {
  jge_t j;

  wei_jmul(&j, p, k);

  wge_set_jge(r, &j);
}

static void
wei_jmul_double_var(jge_t *r,
                    const sc_t k1,
                    const wge_t *p2,
                    const sc_t k2) {
  /* Point multiplication with efficiently computable endomorphisms.
   *
   * [GECC] Algorithm 3.77, Page 129, Section 3.5.
   * [GLV] Page 193, Section 3 (Using Efficient Endomorphisms).
   */
  const wge_t *wnd1 = curve_wnd_naf;
  const wge_t *wnd2 = curve_wnd_endo;
  int naf1[ENDO_BITS + 1]; /* 1048 bytes */
  int naf2[ENDO_BITS + 1]; /* 1048 bytes */
  int naf3[ENDO_BITS + 1]; /* 1048 bytes */
  jge_t wnd3[JSF_SIZE]; /* 608 bytes */
  sc_t c1, c2, c3, c4; /* 288 bytes */
  mp_bits_t i, max, max1, max2;

  /* Split scalars. */
  wei_endo_split(c1, c2, k1);
  wei_endo_split(c3, c4, k2);

  /* Compute NAFs. */
  max1 = sc_naf_var(naf1, naf2, c1, c2, NAF_WIDTH_PRE);
  max2 = sc_jsf_var(naf3, c3, c4);
  max = ECC_MAX(max1, max2);

  /* Create comb for JSF. */
  jge_jsf_points_var(wnd3, p2);

  /* Multiply and add. */
  jge_zero(r);

  for (i = max - 1; i >= 0; i--) {
    int z1 = naf1[i];
    int z2 = naf2[i];
    int z3 = naf3[i];

    if (i != max - 1)
      jge_dbl_var(r, r);

    if (z1 > 0)
      jge_mixed_add_var(r, r, &wnd1[(z1 - 1) >> 1]);
    else if (z1 < 0)
      jge_mixed_sub_var(r, r, &wnd1[(-z1 - 1) >> 1]);

    if (z2 > 0)
      jge_mixed_add_var(r, r, &wnd2[(z2 - 1) >> 1]);
    else if (z2 < 0)
      jge_mixed_sub_var(r, r, &wnd2[(-z2 - 1) >> 1]);

    if (z3 > 0)
      jge_add_var(r, r, &wnd3[(z3 - 1) >> 1]);
    else if (z3 < 0)
      jge_sub_var(r, r, &wnd3[(-z3 - 1) >> 1]);
  }
}

static void
wei_mul_double_var(wge_t *r,
                   const sc_t k1,
                   const wge_t *p2,
                   const sc_t k2) {
  jge_t j;

  wei_jmul_double_var(&j, k1, p2, k2);

  wge_set_jge_var(r, &j);
}

static void
wei_jmul_multi_var(jge_t *r,
                   const sc_t k0,
                   const wge_t *points,
                   sc_t *coeffs,
                   size_t len,
                   wei_scratch_t *scratch) {
  /* Multiple point multiplication, also known
   * as "Shamir's trick" (with interleaved NAFs).
   *
   * [GECC] Algorithm 3.48, Page 109, Section 3.3.3.
   *        Algorithm 3.51, Page 112, Section 3.3.
   */
  const wge_t *wnd0 = curve_wnd_naf;
  const wge_t *wnd1 = curve_wnd_endo;
  int naf0[ENDO_BITS + 1]; /* 1048 bytes */
  int naf1[ENDO_BITS + 1]; /* 1048 bytes */
  jge_t **wnds = scratch->wnds;
  int **nafs = scratch->nafs;
  mp_bits_t i, max, size;
  sc_t k1, k2;
  size_t j;

  ASSERT(len <= scratch->size);

  /* Split scalar. */
  wei_endo_split(k1, k2, k0);

  /* Compute fixed NAFs. */
  max = sc_naf_var(naf0, naf1, k1, k2, NAF_WIDTH_PRE);

  for (j = 0; j < len; j++) {
    /* Split scalar. */
    wei_endo_split(k1, k2, coeffs[j]);

    /* Compute JSF.*/
    size = sc_jsf_var(nafs[j], k1, k2);

    /* Create comb for JSF. */
    jge_jsf_points_var(wnds[j], &points[j]);

    /* Calculate max. */
    max = ECC_MAX(max, size);
  }

  /* Multiply and add. */
  jge_zero(r);

  for (i = max - 1; i >= 0; i--) {
    int z0 = naf0[i];
    int z1 = naf1[i];

    if (i != max - 1)
      jge_dbl_var(r, r);

    if (z0 > 0)
      jge_mixed_add_var(r, r, &wnd0[(z0 - 1) >> 1]);
    else if (z0 < 0)
      jge_mixed_sub_var(r, r, &wnd0[(-z0 - 1) >> 1]);

    if (z1 > 0)
      jge_mixed_add_var(r, r, &wnd1[(z1 - 1) >> 1]);
    else if (z1 < 0)
      jge_mixed_sub_var(r, r, &wnd1[(-z1 - 1) >> 1]);

    for (j = 0; j < len; j++) {
      int z = nafs[j][i];

      if (z > 0)
        jge_add_var(r, r, &wnds[j][(z - 1) >> 1]);
      else if (z < 0)
        jge_sub_var(r, r, &wnds[j][(-z - 1) >> 1]);
    }
  }
}

BTC_UNUSED static void
wei_mul_multi_var(wge_t *r,
                  const sc_t k0,
                  const wge_t *points,
                  sc_t *coeffs,
                  size_t len,
                  wei_scratch_t *scratch) {
  jge_t j;

  wei_jmul_multi_var(&j, k0, points, coeffs, len, scratch);

  wge_set_jge_var(r, &j);
}

static void
wei_svdwf(fe_t x, fe_t y, const fe_t u) {
  /* Shallue-van de Woestijne Method.
   *
   * Distribution: 9/16.
   *
   * [SVDW1] Section 5.
   * [SVDW2] Page 8, Section 3.
   *         Page 15, Section 6, Algorithm 1.
   * [H2EC] "Shallue-van de Woestijne Method".
   *
   * Assumptions:
   *
   *   - p = 1 (mod 3).
   *   - a = 0, b != 0.
   *   - Let z be a unique element in F(p).
   *   - g((sqrt(-3 * z^2) - z) / 2) is square in F(p).
   *   - u != 0, u != +-sqrt(-g(z)).
   *
   * Map:
   *
   *   g(x) = x^3 + b
   *   c = sqrt(-3 * z^2)
   *   t1 = u^2 + g(z)
   *   t2 = 1 / (u^2 * t1)
   *   t3 = u^4 * t2 * c
   *   x1 = (c - z) / 2 - t3
   *   x2 = t3 - (c + z) / 2
   *   x3 = z - t1^3 * t2 / (3 * z^2)
   *   x = x1, if g(x1) is square
   *     = x2, if g(x2) is square
   *     = x3, otherwise
   *   y = sign(u) * abs(sqrt(g(x)))
   */
  fe_t gz, z3, u2, u4, t1, t2, t3, t4;
  fe_t x1, x2, x3, y1, y2, y3;
  int alpha, beta;

  wei_solve_y2(gz, curve_z);

  fe_sqr(z3, curve_zi);
  fe_mul(z3, z3, curve_i3);

  fe_sqr(u2, u);
  fe_sqr(u4, u2);

  fe_add_nc(t1, u2, gz);

  fe_mul(t2, u2, t1);
  fe_invert(t2, t2);

  fe_mul(t3, u4, t2);
  fe_mul(t3, t3, curve_c);

  fe_sqr(t4, t1);
  fe_mul(t4, t4, t1);

  fe_sub_nc(x1, curve_c, curve_z);
  fe_mul(x1, x1, curve_i2);
  fe_sub(x1, x1, t3);

  fe_add_nc(y1, curve_c, curve_z);
  fe_mul(y1, y1, curve_i2);
  fe_sub(x2, t3, y1);

  fe_mul(y1, t4, t2);
  fe_mul(y1, y1, z3);
  fe_sub(x3, curve_z, y1);

  wei_solve_y2(y1, x1);
  wei_solve_y2(y2, x2);
  wei_solve_y2(y3, x3);

  alpha = fe_is_square(y1);
  beta = fe_is_square(y2);

  fe_select(x1, x1, x2, (alpha ^ 1) & beta);
  fe_select(y1, y1, y2, (alpha ^ 1) & beta);
  fe_select(x1, x1, x3, (alpha ^ 1) & (beta ^ 1));
  fe_select(y1, y1, y3, (alpha ^ 1) & (beta ^ 1));

  fe_set(x, x1);
  fe_set(y, y1);
}

static void
wei_svdw(wge_t *r, const fe_t u) {
  fe_t x, y;

  wei_svdwf(x, y, u);

  ASSERT(fe_sqrt(y, y));

  fe_set_odd(y, y, fe_is_odd(u));

  fe_set(r->x, x);
  fe_set(r->y, y);

  r->inf = 0;
}

static int
wei_svdwi(fe_t u, const wge_t *p, unsigned int hint) {
  /* Inverting the Map (Shallue-van de Woestijne).
   *
   * [SQUARED] Algorithm 1, Page 8, Section 3.3.
   * [SVDW2] Page 12, Section 5.
   * [SVDW3] "Inverting the map".
   *
   * Assumptions:
   *
   *   - If r = 1 then x != -(c + z) / 2.
   *   - If r = 2 then x != (c - z) / 2.
   *   - If r > 2 then (t0 - t1 + t2) is square in F(p).
   *   - f(f^-1(x)) = x where f is the map function.
   *
   * We use the sampling method from [SVDW2],
   * _not_ [SQUARED]. This seems to have a
   * better distribution in practice.
   *
   * Note that [SVDW3] also appears to be
   * incorrect in terms of distribution.
   *
   * The distribution of f(u), assuming u is
   * random, is (1/2, 1/4, 1/4).
   *
   * To mirror this, f^-1(x) should simply
   * pick (1/2, 1/4, 1/8, 1/8).
   *
   * To anyone running the forward map, our
   * strings will appear to be random.
   *
   * Map:
   *
   *   g(x) = x^3 + b
   *   c = sqrt(-3 * z^2)
   *   t0 = 9 * (x^2 * z^2 + z^4)
   *   t1 = 18 * x * z^3
   *   t2 = 12 * g(z) * (x - z)
   *   t3 = sqrt(t0 - t1 + t2)
   *   t4 = t3 * z
   *   u1 = g(z) * (c - 2 * x - z) / (c + 2 * x + z)
   *   u2 = g(z) * (c + 2 * x + z) / (c - 2 * x - z)
   *   u3 = (3 * (z^3 - x * z^2) - 2 * g(z) + t4) / 2
   *   u4 = (3 * (z^3 - x * z^2) - 2 * g(z) - t4) / 2
   *   r = random integer in [1,4]
   *   u = sign(y) * abs(sqrt(ur))
   */
  fe_t z2, z3, z4, gz, c0, c1, t4, t5;
  fe_t n0, n1, n2, n3, d0;
  uint32_t r = hint & 3;
  uint32_t ret = 1;
  uint32_t sqr;

  fe_sqr(z2, curve_z);
  fe_mul(z3, z2, curve_z);
  fe_sqr(z4, z2);
  fe_add(gz, z3, curve_b);

  fe_sqr(n0, p->x);
  fe_mul(n0, n0, z2);
  fe_add_nc(n0, n0, z4);
  fe_mul3(n0, n0); /* x3 */
  fe_mul3(n0, n0); /* x9 */

  fe_mul(n1, p->x, z3);
  fe_add_nc(n1, n1, n1); /* x2 */
  fe_mul3(n1, n1); /* x6 */
  fe_mul3(n1, n1); /* x18 */

  fe_sub_nc(n2, p->x, curve_z);
  fe_mul(n2, n2, gz);
  fe_mul3(n2, n2); /* x3 */
  fe_mul4(n2, n2); /* x12 */

  fe_sub(t4, n0, n1);
  fe_add(t4, t4, n2);
  sqr = fe_sqrt(t4, t4);
  fe_mul(t4, t4, curve_z);

  ret &= ((r - 2) >> 31) | sqr;

  fe_mul(n0, p->x, z2);
  fe_add(n1, gz, gz);
  fe_sub_nc(t5, z3, n0);
  fe_mul3(t5, t5);
  fe_sub(t5, t5, n1);

  fe_add(n0, p->x, p->x);
  fe_add(n0, n0, curve_z);

  fe_sub(c0, curve_c, n0);
  fe_add(c1, curve_c, n0);

  fe_mul(n0, gz, c0);
  fe_mul(n1, gz, c1);
  fe_add(n2, t5, t4);
  fe_sub(n3, t5, t4);
  fe_set(d0, field_two);

  fe_select(n0, n0, n1, ((r ^ 1) - 1) >> 31); /* r = 1 */
  fe_select(n0, n0, n2, ((r ^ 2) - 1) >> 31); /* r = 2 */
  fe_select(n0, n0, n3, ((r ^ 3) - 1) >> 31); /* r = 3 */
  fe_select(d0, d0, c1, ((r ^ 0) - 1) >> 31); /* r = 0 */
  fe_select(d0, d0, c0, ((r ^ 1) - 1) >> 31); /* r = 1 */

  ret &= fe_isqrt(u, n0, d0);

  wei_svdwf(n0, n1, u);

  ret &= fe_equal(n0, p->x);

  fe_set_odd(u, u, fe_is_odd(p->y));

  ret &= p->inf ^ 1;

  return ret;
}

static void
wei_point_from_uniform(wge_t *r, const unsigned char *bytes) {
  fe_t u;

  fe_import(u, bytes);

  wei_svdw(r, u);

  fe_cleanse(u);
}

static int
wei_point_to_uniform(unsigned char *bytes, const wge_t *p, unsigned int hint) {
  /* Convert a short weierstrass point to a field
   * element by inverting either the SSWU or SVDW
   * map.
   *
   * Hint Layout:
   *
   *   [00000000] [0000] [0000]
   *        |        |      |
   *        |        |      +-- preimage index
   *        |        +--- subgroup
   *        +-- bits to OR with uniform bytes
   */
  int ret = 1;
  fe_t u;

  ret &= wei_svdwi(u, p, hint);

  fe_export(bytes, u);

  bytes[0] |= (hint >> 8) & 0xff;

  fe_cleanse(u);

  return ret;
}

static void
wei_point_from_hash(wge_t *r, const unsigned char *bytes) {
  /* [H2EC] "Roadmap". */
  const unsigned char *u1 = bytes;
  const unsigned char *u2 = bytes + 32;
  wge_t p1, p2;

  wei_point_from_uniform(&p1, u1);
  wei_point_from_uniform(&p2, u2);

  wge_add(r, &p1, &p2);

  wge_cleanse(&p1);
  wge_cleanse(&p2);
}

static void
wei_point_to_hash(unsigned char *bytes,
                  const wge_t *p,
                  const unsigned char *entropy) {
  /* [SQUARED] Algorithm 1, Page 8, Section 3.3. */
  unsigned char *u1 = bytes;
  unsigned char *u2 = bytes + 32;
  unsigned int hint = 0;
  btc_drbg_t rng;
  wge_t p1, p2;

  btc_drbg_init(&rng, entropy, 32);

  do {
    btc_drbg_generate(&rng, u1, 32);

    wei_point_from_uniform(&p1, u1);

    wge_sub(&p2, p, &p1);

    btc_drbg_generate(&rng, &hint, sizeof(hint));
  } while (!wei_point_to_uniform(u2, &p2, hint));

  cleanse(&rng, sizeof(rng));
  cleanse(&hint, sizeof(hint));

  wge_cleanse(&p1);
  wge_cleanse(&p2);
}

/*
 * Scratch API
 */

wei_scratch_t *
btc_scratch_create(size_t size) {
  wei_scratch_t *scratch =
    (wei_scratch_t *)checked_malloc(sizeof(wei_scratch_t));
  size_t i;

  scratch->size = size;
  scratch->wnd = (jge_t *)checked_malloc(size * JSF_SIZE * sizeof(jge_t));
  scratch->wnds = (jge_t **)checked_malloc(size * sizeof(jge_t *));
  scratch->naf = (int *)checked_malloc(size * (ENDO_BITS + 1) * sizeof(int));
  scratch->nafs = (int **)checked_malloc(size * sizeof(int *));

  for (i = 0; i < size; i++) {
    scratch->wnds[i] = &scratch->wnd[i * JSF_SIZE];
    scratch->nafs[i] = &scratch->naf[i * (ENDO_BITS + 1)];
  }

  scratch->points = (wge_t *)checked_malloc(size * sizeof(wge_t));
  scratch->coeffs = (sc_t *)checked_malloc(size * sizeof(sc_t));

  return scratch;
}

void
btc_scratch_destroy(wei_scratch_t *scratch) {
  free(scratch->wnd);
  free(scratch->wnds);
  free(scratch->naf);
  free(scratch->nafs);
  free(scratch->points);
  free(scratch->coeffs);
  free(scratch);
}

/*
 * ECDSA
 */

void
btc_ecdsa_privkey_generate(unsigned char *out, const unsigned char *entropy) {
  btc_drbg_t rng;
  sc_t a;

  btc_drbg_init(&rng, entropy, 32);

  sc_random(a, &rng);
  sc_export(out, a);
  sc_cleanse(a);

  cleanse(&rng, sizeof(rng));
}

int
btc_ecdsa_privkey_verify(const unsigned char *priv) {
  int ret = 1;
  sc_t a;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;

  sc_cleanse(a);

  return ret;
}

int
btc_ecdsa_privkey_tweak_add(unsigned char *out,
                            const unsigned char *priv,
                            const unsigned char *tweak) {
  int ret = 1;
  sc_t a, t;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;
  ret &= sc_import(t, tweak);

  sc_add(a, a, t);

  ret &= sc_is_zero(a) ^ 1;

  sc_export(out, a);
  sc_cleanse(a);
  sc_cleanse(t);

  return ret;
}

int
btc_ecdsa_privkey_tweak_mul(unsigned char *out,
                            const unsigned char *priv,
                            const unsigned char *tweak) {
  int ret = 1;
  sc_t a, t;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;
  ret &= sc_import(t, tweak);

  sc_mul(a, a, t);

  ret &= sc_is_zero(a) ^ 1;

  sc_export(out, a);
  sc_cleanse(a);
  sc_cleanse(t);

  return ret;
}

int
btc_ecdsa_privkey_negate(unsigned char *out, const unsigned char *priv) {
  int ret = 1;
  sc_t a;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;

  sc_neg(a, a);
  sc_export(out, a);
  sc_cleanse(a);

  return ret;
}

int
btc_ecdsa_privkey_invert(unsigned char *out, const unsigned char *priv) {
  int ret = 1;
  sc_t a;

  ret &= sc_import(a, priv);
  ret &= sc_invert(a, a);

  sc_export(out, a);
  sc_cleanse(a);

  return ret;
}

int
btc_ecdsa_pubkey_create(unsigned char *pub,
                        const unsigned char *priv,
                        int compact) {
  int ret = 1;
  wge_t A;
  sc_t a;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;

  wei_mul_g(&A, a);

  ret &= wge_export(pub, &A, compact);

  sc_cleanse(a);
  wge_cleanse(&A);

  return ret;
}

int
btc_ecdsa_pubkey_convert(unsigned char *out,
                         const unsigned char *pub,
                         size_t pub_len,
                         int compact) {
  int ret = 1;
  wge_t A;

  ret &= wge_import(&A, pub, pub_len);
  ret &= wge_export(out, &A, compact);

  return ret;
}

void
btc_ecdsa_pubkey_from_uniform(unsigned char *out,
                              const unsigned char *bytes,
                              int compact) {
  wge_t A;

  wei_point_from_uniform(&A, bytes);

  ASSERT(wge_export(out, &A, compact));
}

int
btc_ecdsa_pubkey_to_uniform(unsigned char *out,
                            const unsigned char *pub,
                            size_t pub_len,
                            unsigned int hint) {
  int ret = 1;
  wge_t A;

  ret &= wge_import(&A, pub, pub_len);
  ret &= wei_point_to_uniform(out, &A, hint);

  return ret;
}

int
btc_ecdsa_pubkey_from_hash(unsigned char *out,
                           const unsigned char *bytes,
                           int compact) {
  wge_t A;

  wei_point_from_hash(&A, bytes);

  return wge_export(out, &A, compact);
}

int
btc_ecdsa_pubkey_to_hash(unsigned char *out,
                         const unsigned char *pub,
                         size_t pub_len,
                         const unsigned char *entropy) {
  int ret = 1;
  wge_t A;

  ret &= wge_import(&A, pub, pub_len);

  wei_point_to_hash(out, &A, entropy);

  return ret;
}

int
btc_ecdsa_pubkey_verify(const unsigned char *pub, size_t pub_len) {
  wge_t A;

  return wge_import(&A, pub, pub_len);
}

int
btc_ecdsa_pubkey_tweak_add(unsigned char *out,
                           const unsigned char *pub,
                           size_t pub_len,
                           const unsigned char *tweak,
                           int compact) {
  int ret = 1;
  wge_t A;
  jge_t T;
  sc_t t;

  ret &= wge_import(&A, pub, pub_len);
  ret &= sc_import(t, tweak);

  wei_jmul_g(&T, t);

  jge_mixed_add(&T, &T, &A);

  wge_set_jge(&A, &T);

  ret &= wge_export(out, &A, compact);

  sc_cleanse(t);

  return ret;
}

int
btc_ecdsa_pubkey_tweak_mul(unsigned char *out,
                           const unsigned char *pub,
                           size_t pub_len,
                           const unsigned char *tweak,
                           int compact) {
  int ret = 1;
  wge_t A;
  sc_t t;

  ret &= wge_import(&A, pub, pub_len);
  ret &= sc_import(t, tweak);

  wei_mul(&A, &A, t);

  ret &= wge_export(out, &A, compact);

  sc_cleanse(t);

  return ret;
}

int
btc_ecdsa_pubkey_add(unsigned char *out,
                     const unsigned char *pub1,
                     size_t pub_len1,
                     const unsigned char *pub2,
                     size_t pub_len2,
                     int compact) {
  int ret = 1;
  wge_t P, Q;

  ret &= wge_import(&P, pub1, pub_len1);
  ret &= wge_import(&Q, pub2, pub_len2);

  wge_add(&P, &P, &Q);

  ret &= wge_export(out, &P, compact);

  return ret;
}

int
btc_ecdsa_pubkey_combine(unsigned char *out,
                         const unsigned char *const *pubs,
                         const size_t *pub_lens,
                         size_t len,
                         int compact) {
  int ret = 1;
  size_t i;
  wge_t A;
  jge_t P;

  if (len > 0) {
    ret &= wge_import(&A, pubs[0], pub_lens[0]);

    jge_set_wge(&P, &A);
  } else {
    jge_zero(&P);
  }

  for (i = 1; i < len; i++) {
    ret &= wge_import(&A, pubs[i], pub_lens[i]);

    jge_mixed_add(&P, &P, &A);
  }

  wge_set_jge(&A, &P);

  ret &= wge_export(out, &A, compact);

  return ret;
}

int
btc_ecdsa_pubkey_negate(unsigned char *out,
                        const unsigned char *pub,
                        size_t pub_len,
                        int compact) {
  int ret = 1;
  wge_t A;

  ret &= wge_import(&A, pub, pub_len);

  wge_neg(&A, &A);

  ret &= wge_export(out, &A, compact);

  return ret;
}

static void
ecdsa_encode_der(unsigned char *out,
                 size_t *out_len,
                 const sc_t r,
                 const sc_t s) {
  unsigned char rp[32];
  unsigned char sp[32];
  size_t size = 0;
  size_t pos = 0;

  sc_export(rp, r);
  sc_export(sp, s);

  size += asn1_size_int(rp, 32);
  size += asn1_size_int(sp, 32);

  pos = asn1_write_seq(out, pos, size);
  pos = asn1_write_int(out, pos, rp, 32);
  pos = asn1_write_int(out, pos, sp, 32);

  *out_len = pos;
}

static int
ecdsa_decode_der(sc_t r,
                 sc_t s,
                 const unsigned char *der,
                 size_t der_len,
                 int strict) {
  unsigned char rp[32];
  unsigned char sp[32];

  if (!asn1_read_seq(&der, &der_len, strict))
    goto fail;

  if (!asn1_read_int(rp, 32, &der, &der_len, strict))
    goto fail;

  if (!asn1_read_int(sp, 32, &der, &der_len, strict))
    goto fail;

  if (strict && der_len != 0)
    goto fail;

  if (!sc_import(r, rp))
    goto fail;

  if (!sc_import(s, sp))
    goto fail;

  return 1;
fail:
  sc_zero(r);
  sc_zero(s);
  return 0;
}

static int
ecdsa_reduce(sc_t r, const unsigned char *msg, size_t msg_len) {
  /* Byte array to integer conversion.
   *
   * [SEC1] Step 5, Page 45, Section 4.1.3.
   * [FIPS186] Page 25, Section B.2.
   *
   * The two sources above disagree on this.
   *
   * FIPS186 simply modulos the entire byte
   * array by the order, whereas SEC1 takes
   * the left-most ceil(log2(n+1)) bits modulo
   * the order (and maybe does other stuff).
   *
   * Instead of trying to decipher all of
   * this nonsense, we simply replicate the
   * OpenSSL behavior (which, in actuality,
   * is more similar to the SEC1 behavior).
   */

  /* Truncate. */
  if (msg_len > 32)
    msg_len = 32;

  /* Import and pad. */
  mpn_import(r, SCALAR_LIMBS, msg, msg_len, 1);

  /* Reduce (r < 2^ceil(log2(n+1))). */
  return sc_reduce_weak(r, r, 0) ^ 1;
}

int
btc_ecdsa_sig_export(unsigned char *out,
                     size_t *out_len,
                     const unsigned char *sig) {
  int ret = 1;
  sc_t r, s;

  ret &= sc_import(r, sig);
  ret &= sc_import(s, sig + 32);

  if (!ret) {
    sc_zero(r);
    sc_zero(s);
  }

  ecdsa_encode_der(out, out_len, r, s);

  return ret;
}

int
btc_ecdsa_sig_import(unsigned char *out,
                     const unsigned char *der,
                     size_t der_len) {
  int ret = 1;
  sc_t r, s;

  ret &= ecdsa_decode_der(r, s, der, der_len, 1);

  sc_export(out, r);
  sc_export(out + 32, s);

  return ret;
}

int
btc_ecdsa_sig_import_lax(unsigned char *out,
                         const unsigned char *der,
                         size_t der_len) {
  int ret = 1;
  sc_t r, s;

  ret &= ecdsa_decode_der(r, s, der, der_len, 0);

  sc_export(out, r);
  sc_export(out + 32, s);

  return ret;
}

int
btc_ecdsa_sig_normalize(unsigned char *out, const unsigned char *sig) {
  int ret = 1;
  sc_t r, s;

  ret &= sc_import(r, sig);
  ret &= sc_import(s, sig + 32);

  sc_minimize(s, s);

  sc_export(out, r);
  sc_export(out + 32, s);

  return ret;
}

int
btc_ecdsa_is_low_s(const unsigned char *sig) {
  int ret = 1;
  sc_t r, s;

  ret &= sc_import(r, sig);
  ret &= sc_import(s, sig + 32);
  ret &= sc_is_high(s) ^ 1;

  return ret;
}

int
btc_ecdsa_sign(unsigned char *sig,
               unsigned int *param,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *priv) {
  return btc_ecdsa_sign_internal(sig, param, msg, msg_len, priv, NULL);
}

int
btc_ecdsa_sign_internal(unsigned char *sig,
                        unsigned int *param,
                        const unsigned char *msg,
                        size_t msg_len,
                        const unsigned char *priv,
                        btc_redefine_f *redefine) {
  /* ECDSA Signing.
   *
   * [SEC1] Page 44, Section 4.1.3.
   * [GECC] Algorithm 4.29, Page 184, Section 4.4.1.
   * [RFC6979] Page 9, Section 2.4.
   * [RFC6979] Page 10, Section 3.2.
   *
   * Assumptions:
   *
   *   - Let `m` be an integer reduced from bytes.
   *   - Let `a` be a secret non-zero scalar.
   *   - Let `k` be a random non-zero scalar.
   *   - R != O, r != 0, s != 0.
   *
   * Computation:
   *
   *   k = random integer in [1,n-1]
   *   R = G * k
   *   r = x(R) mod n
   *   s = (r * a + m) / k mod n
   *   s = -s mod n, if s > n / 2
   *   S = (r, s)
   *
   * Note that `k` must remain secret,
   * otherwise an attacker can compute:
   *
   *   a = (s * k - m) / r mod n
   *
   * This means that if two signatures
   * share the same `r` value, an attacker
   * can compute:
   *
   *   k = (m1 - m2) / (+-s1 - +-s2) mod n
   *   a = (s1 * k - m1) / r mod n
   *
   * Assuming:
   *
   *   s1 = (r * a + m1) / k mod n
   *   s2 = (r * a + m2) / k mod n
   *
   * To mitigate this, `k` can be generated
   * deterministically using the HMAC-DRBG
   * construction described in [RFC6979].
   */
  unsigned char bytes[32 * 2];
  unsigned int sign, high;
  sc_t a, m, k, r, s;
  btc_drbg_t rng;
  wge_t R;
  int ret = 1;
  int ok;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;

  ecdsa_reduce(m, msg, msg_len);

  sc_export(bytes, a);
  sc_export(bytes + 32, m);

  btc_drbg_init(&rng, bytes, 32 * 2);

  do {
    btc_drbg_generate(&rng, bytes, 32);

    ok = ecdsa_reduce(k, bytes, 32);

    wei_mul_g(&R, k);

    sign = fe_is_odd(R.y);
    high = sc_set_fe(r, R.x) ^ 1;

    ok &= sc_is_zero(k) ^ 1;
    ok &= wge_is_zero(&R) ^ 1;
    ok &= sc_is_zero(r) ^ 1;

    if (redefine != NULL)
      redefine(&ok, sizeof(ok));
  } while (UNLIKELY(!ok));

  ASSERT(sc_invert(k, k));

  sc_mul(s, r, a);
  sc_add(s, s, m);
  sc_mul(s, s, k);

  sign ^= sc_minimize(s, s);

  sc_export(sig, r);
  sc_export(sig + 32, s);

  if (param != NULL)
    *param = (high << 1) | sign;

  sc_cleanse(a);
  sc_cleanse(m);
  sc_cleanse(k);
  sc_cleanse(r);
  sc_cleanse(s);

  wge_cleanse(&R);

  cleanse(&rng, sizeof(rng));
  cleanse(bytes, 32 * 2);

  return ret;
}

int
btc_ecdsa_verify(const unsigned char *msg,
                 size_t msg_len,
                 const unsigned char *sig,
                 const unsigned char *pub,
                 size_t pub_len) {
  /* ECDSA Verification.
   *
   * [SEC1] Page 46, Section 4.1.4.
   * [GECC] Algorithm 4.30, Page 184, Section 4.4.1.
   *
   * Assumptions:
   *
   *   - Let `m` be an integer reduced from bytes.
   *   - Let `r` and `s` be signature elements.
   *   - Let `A` be a valid group element.
   *   - r != 0, r < n.
   *   - s != 0, s < n.
   *   - R != O.
   *
   * Computation:
   *
   *   u1 = m / s mod n
   *   u2 = r / s mod n
   *   R = G * u1 + A * u2
   *   r == x(R) mod n
   *
   * Note that the signer can verify their
   * own signatures more efficiently with:
   *
   *   R = G * ((u1 + u2 * a) mod n)
   *
   * Furthermore, we can avoid affinization
   * of `R` by scaling `r` by `z^2` and
   * adding `n * z^2` to it when possible.
   */
  sc_t m, r, s, u1, u2;
  wge_t A;
  jge_t R;

  if (!sc_import(r, sig))
    return 0;

  if (!sc_import(s, sig + 32))
    return 0;

  if (sc_is_zero(r) || sc_is_zero(s))
    return 0;

  if (sc_is_high_var(s))
    return 0;

  if (!wge_import(&A, pub, pub_len))
    return 0;

  ecdsa_reduce(m, msg, msg_len);

  ASSERT(sc_invert_var(s, s));

  sc_mul(u1, m, s);
  sc_mul(u2, r, s);

  wei_jmul_double_var(&R, u1, &A, u2);

  return jge_equal_r_var(&R, r);
}

int
btc_ecdsa_recover(unsigned char *pub,
                  const unsigned char *msg,
                  size_t msg_len,
                  const unsigned char *sig,
                  unsigned int param,
                  int compact) {
  /* ECDSA Public Key Recovery.
   *
   * [SEC1] Page 47, Section 4.1.6.
   *
   * Assumptions:
   *
   *   - Let `m` be an integer reduced from bytes.
   *   - Let `r` and `s` be signature elements.
   *   - Let `i` be an integer in [0,3].
   *   - x^3 + a * x + b is square in F(p).
   *   - If i > 1 then r < (p mod n).
   *   - r != 0, r < n.
   *   - s != 0, s < n.
   *   - A != O.
   *
   * Computation:
   *
   *   x = r + n, if i > 1
   *     = r, otherwise
   *   R' = (x, sqrt(x^3 + a * x + b))
   *   R = -R', if i mod 2 == 1
   *     = +R', otherwise
   *   s1 = m / r mod n
   *   s2 = s / r mod n
   *   A = R * s2 - G * s1
   *
   * Note that this implementation will have
   * trouble on curves where `p / n > 1`.
   */
  unsigned int sign = param & 1;
  unsigned int high = param >> 1;
  sc_t m, r, s, s1, s2;
  wge_t R, A;
  fe_t x;

  wge_zero(&A);

  if (!sc_import(r, sig))
    goto fail;

  if (!sc_import(s, sig + 32))
    goto fail;

  if (sc_is_zero(r) || sc_is_zero(s))
    goto fail;

  if (sc_is_high_var(s))
    goto fail;

  if (!fe_set_sc(x, r))
    goto fail;

  if (high) {
    if (sc_cmp_var(r, curve_sc_p) >= 0)
      goto fail;

    fe_add(x, x, curve_fe_n);
  }

  if (!wge_set_x(&R, x, sign))
    goto fail;

  ecdsa_reduce(m, msg, msg_len);

  ASSERT(sc_invert_var(r, r));

  sc_mul(s1, m, r);
  sc_mul(s2, s, r);
  sc_neg(s1, s1);

  wei_mul_double_var(&A, s1, &R, s2);

fail:
  return wge_export(pub, &A, compact);
}

int
btc_ecdsa_derive(unsigned char *secret,
                 const unsigned char *pub,
                 size_t pub_len,
                 const unsigned char *priv,
                 int compact) {
  int ret = 1;
  wge_t A, P;
  sc_t a;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;
  ret &= wge_import(&A, pub, pub_len);

  wei_mul(&P, &A, a);

  ret &= wge_export(secret, &P, compact);

  sc_cleanse(a);

  wge_cleanse(&A);
  wge_cleanse(&P);

  return ret;
}

/*
 * BIP340
 */

void
btc_bip340_privkey_generate(unsigned char *out, const unsigned char *entropy) {
  btc_ecdsa_privkey_generate(out, entropy);
}

int
btc_bip340_privkey_verify(const unsigned char *priv) {
  return btc_ecdsa_privkey_verify(priv);
}

int
btc_bip340_privkey_tweak_add(unsigned char *out,
                             const unsigned char *priv,
                             const unsigned char *tweak) {
  int ret = 1;
  sc_t a, t;
  wge_t A;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;
  ret &= sc_import(t, tweak);

  wei_mul_g(&A, a);

  sc_neg_cond(a, a, wge_is_even(&A) ^ 1);
  sc_add(a, a, t);

  ret &= sc_is_zero(a) ^ 1;

  sc_export(out, a);

  sc_cleanse(a);
  sc_cleanse(t);

  wge_cleanse(&A);

  return ret;
}

int
btc_bip340_privkey_tweak_mul(unsigned char *out,
                             const unsigned char *priv,
                             const unsigned char *tweak) {
  return btc_ecdsa_privkey_tweak_mul(out, priv, tweak);
}

int
btc_bip340_privkey_invert(unsigned char *out, const unsigned char *priv) {
  return btc_ecdsa_privkey_invert(out, priv);
}

int
btc_bip340_pubkey_create(unsigned char *pub, const unsigned char *priv) {
  int ret = 1;
  wge_t A;
  sc_t a;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;

  wei_mul_g(&A, a);

  ret &= wge_export_x(pub, &A);

  sc_cleanse(a);

  wge_cleanse(&A);

  return ret;
}

void
btc_bip340_pubkey_from_uniform(unsigned char *out, const unsigned char *bytes) {
  wge_t A;

  wei_point_from_uniform(&A, bytes);

  ASSERT(wge_export_x(out, &A));
}

int
btc_bip340_pubkey_to_uniform(unsigned char *out,
                             const unsigned char *pub,
                             unsigned int hint) {
  int ret = 1;
  wge_t A;

  ret &= wge_import_even(&A, pub);
  ret &= wei_point_to_uniform(out, &A, hint);

  return ret;
}

int
btc_bip340_pubkey_from_hash(unsigned char *out, const unsigned char *bytes) {
  wge_t A;

  wei_point_from_hash(&A, bytes);

  return wge_export_x(out, &A);
}

int
btc_bip340_pubkey_to_hash(unsigned char *out,
                          const unsigned char *pub,
                          const unsigned char *entropy) {
  int ret = 1;
  wge_t A;

  ret &= wge_import_even(&A, pub);

  wei_point_to_hash(out, &A, entropy);

  return ret;
}

int
btc_bip340_pubkey_verify(const unsigned char *pub) {
  wge_t A;

  return wge_import_even(&A, pub);
}

int
btc_bip340_pubkey_tweak_add(unsigned char *out,
                            int *negated,
                            const unsigned char *pub,
                            const unsigned char *tweak) {
  int ret = 1;
  wge_t A;
  jge_t T;
  sc_t t;

  ret &= wge_import_even(&A, pub);
  ret &= sc_import(t, tweak);

  wei_jmul_g(&T, t);

  jge_mixed_add(&T, &T, &A);

  wge_set_jge(&A, &T);

  ret &= wge_export_x(out, &A);

  if (negated != NULL)
    *negated = wge_is_even(&A) ^ 1;

  sc_cleanse(t);

  return ret;
}

int
btc_bip340_pubkey_tweak_add_check(const unsigned char *pub,
                                  const unsigned char *tweak,
                                  const unsigned char *expect,
                                  int negated) {
  unsigned char raw[32];
  int ret = 1;
  int sign;

  ret &= btc_bip340_pubkey_tweak_add(raw, &sign, pub, tweak);
  ret &= btc_memequal(raw, expect, 32);
  ret &= (sign == (negated != 0));

  return ret;
}

int
btc_bip340_pubkey_tweak_mul(unsigned char *out,
                            int *negated,
                            const unsigned char *pub,
                            const unsigned char *tweak) {
  int ret = 1;
  wge_t A;
  sc_t t;

  ret &= wge_import_even(&A, pub);
  ret &= sc_import(t, tweak);

  wei_mul(&A, &A, t);

  ret &= wge_export_x(out, &A);

  if (negated != NULL)
    *negated = wge_is_even(&A) ^ 1;

  sc_cleanse(t);

  return ret;
}

int
btc_bip340_pubkey_tweak_mul_check(const unsigned char *pub,
                                  const unsigned char *tweak,
                                  const unsigned char *expect,
                                  int negated) {
  unsigned char raw[32];
  int ret = 1;
  int sign;

  ret &= btc_bip340_pubkey_tweak_mul(raw, &sign, pub, tweak);
  ret &= btc_memequal(raw, expect, 32);
  ret &= (sign == (negated != 0));

  return ret;
}

int
btc_bip340_pubkey_add(unsigned char *out,
                      const unsigned char *pub1,
                      const unsigned char *pub2) {
  int ret = 1;
  wge_t P, Q;

  ret &= wge_import_even(&P, pub1);
  ret &= wge_import_even(&Q, pub2);

  wge_add(&P, &P, &Q);

  ret &= wge_export_x(out, &P);

  return ret;
}

int
btc_bip340_pubkey_combine(unsigned char *out,
                          const unsigned char *const *pubs,
                          size_t len) {
  int ret = 1;
  size_t i;
  wge_t A;
  jge_t P;

  if (len > 0) {
    ret &= wge_import_even(&A, pubs[0]);

    jge_set_wge(&P, &A);
  } else {
    jge_zero(&P);
  }

  for (i = 1; i < len; i++) {
    ret &= wge_import_even(&A, pubs[i]);

    jge_mixed_add(&P, &P, &A);
  }

  wge_set_jge(&A, &P);

  ret &= wge_export_x(out, &A);

  return ret;
}

static void
bip340_hash_aux(unsigned char *out, const unsigned char *scalar,
                                    const unsigned char *aux) {
  unsigned char bytes[32];
  btc_sha256_t hash;
  size_t i;

  /* "BIP0340/aux" */
  hash.state[0] = 0x24dd3219;
  hash.state[1] = 0x4eba7e70;
  hash.state[2] = 0xca0fabb9;
  hash.state[3] = 0x0fa3166d;
  hash.state[4] = 0x3afbe4b1;
  hash.state[5] = 0x4c44df97;
  hash.state[6] = 0x4aac2739;
  hash.state[7] = 0x249e850a;
  hash.size = 64;

  btc_sha256_update(&hash, aux, 32);
  btc_sha256_final(&hash, bytes);

  for (i = 0; i < 32; i++)
    out[i] = scalar[i] ^ bytes[i];

  cleanse(bytes, 32);
  cleanse(&hash, sizeof(hash));
}

static void
bip340_hash_nonce(sc_t k, const unsigned char *scalar,
                          const unsigned char *point,
                          const unsigned char *msg,
                          size_t msg_len,
                          const unsigned char *aux) {
  unsigned char secret[32];
  unsigned char bytes[32];
  btc_sha256_t hash;

  if (aux != NULL)
    bip340_hash_aux(secret, scalar, aux);
  else
    memcpy(secret, scalar, 32);

  /* "BIP0340/nonce" */
  hash.state[0] = 0x46615b35;
  hash.state[1] = 0xf4bfbff7;
  hash.state[2] = 0x9f8dc671;
  hash.state[3] = 0x83627ab3;
  hash.state[4] = 0x60217180;
  hash.state[5] = 0x57358661;
  hash.state[6] = 0x21a29e54;
  hash.state[7] = 0x68b07b4c;
  hash.size = 64;

  btc_sha256_update(&hash, secret, 32);
  btc_sha256_update(&hash, point, 32);
  btc_sha256_update(&hash, msg, msg_len);
  btc_sha256_final(&hash, bytes);

  sc_import_weak(k, bytes);

  cleanse(secret, 32);
  cleanse(bytes, 32);
  cleanse(&hash, sizeof(hash));
}

static void
bip340_hash_challenge(sc_t e, const unsigned char *R,
                              const unsigned char *A,
                              const unsigned char *msg,
                              size_t msg_len) {
  unsigned char bytes[32];
  btc_sha256_t hash;

  /* "BIP0340/challenge" */
  hash.state[0] = 0x9cecba11;
  hash.state[1] = 0x23925381;
  hash.state[2] = 0x11679112;
  hash.state[3] = 0xd1627e0f;
  hash.state[4] = 0x97c87550;
  hash.state[5] = 0x003cc765;
  hash.state[6] = 0x90f61164;
  hash.state[7] = 0x33e9b66a;
  hash.size = 64;

  btc_sha256_update(&hash, R, 32);
  btc_sha256_update(&hash, A, 32);
  btc_sha256_update(&hash, msg, msg_len);
  btc_sha256_final(&hash, bytes);

  sc_import_weak(e, bytes);

  cleanse(bytes, 32);
  cleanse(&hash, sizeof(hash));
}

int
btc_bip340_sign(unsigned char *sig,
                const unsigned char *msg,
                size_t msg_len,
                const unsigned char *priv,
                const unsigned char *aux) {
  /* BIP340 Signing.
   *
   * [BIP340] "Default Signing".
   *
   * Assumptions:
   *
   *   - Let `H` be a cryptographic hash function.
   *   - Let `m` be a 32-byte array.
   *   - Let `a` be a secret non-zero scalar.
   *   - Let `d` be a 32-byte array.
   *   - k != 0.
   *
   * Computation:
   *
   *   A = G * a
   *   a = -a mod n, if y(A) is not even
   *   x = x(A)
   *   t = a xor H("BIP0340/aux", d)
   *   k = H("BIP0340/nonce", t, x, m) mod n
   *   R = G * k
   *   k = -k mod n, if y(R) is not even
   *   r = x(R)
   *   e = H("BIP0340/challenge", r, x, m) mod n
   *   s = (k + e * a) mod n
   *   S = (r, s)
   *
   * Note that `k` must remain secret,
   * otherwise an attacker can compute:
   *
   *   a = (s - k) / e mod n
   */
  unsigned char *Rraw = sig;
  unsigned char *sraw = sig + 32;
  unsigned char araw[32];
  unsigned char Araw[32];
  sc_t a, k, e, s;
  wge_t A, R;
  int ret = 1;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;

  wei_mul_g(&A, a);

  sc_neg_cond(a, a, wge_is_even(&A) ^ 1);
  sc_export(araw, a);

  ret &= wge_export_x(Araw, &A);

  bip340_hash_nonce(k, araw, Araw, msg, msg_len, aux);

  ret &= sc_is_zero(k) ^ 1;

  wei_mul_g(&R, k);

  sc_neg_cond(k, k, wge_is_even(&R) ^ 1);

  ret &= wge_export_x(Rraw, &R);

  bip340_hash_challenge(e, Rraw, Araw, msg, msg_len);

  sc_mul(s, e, a);
  sc_add(s, s, k);

  sc_export(sraw, s);

  sc_cleanse(a);
  sc_cleanse(k);
  sc_cleanse(e);
  sc_cleanse(s);

  wge_cleanse(&A);
  wge_cleanse(&R);

  cleanse(araw, 32);
  cleanse(Araw, 32);

  return ret;
}

int
btc_bip340_verify(const unsigned char *msg,
                  size_t msg_len,
                  const unsigned char *sig,
                  const unsigned char *pub) {
  /* BIP340 Verification.
   *
   * [BIP340] "Verification".
   *
   * Assumptions:
   *
   *   - Let `H` be a cryptographic hash function.
   *   - Let `m` be a 32-byte array.
   *   - Let `r` and `s` be signature elements.
   *   - Let `x` be a field element.
   *   - r^3 + a * r + b is square in F(p).
   *   - x^3 + a * x + b is square in F(p).
   *   - sqrt(r^3 + a * r + b) is even in F(p).
   *   - sqrt(x^3 + a * x + b) is even in F(p).
   *   - r < p, s < n, x < p.
   *   - R != O.
   *
   * Computation:
   *
   *   R = (r, sqrt(r^3 + a * r + b))
   *   A = (x, sqrt(x^3 + a * x + b))
   *   e = H("BIP0340/challenge", r, x, m) mod n
   *   R == G * s - A * e
   *
   * We can skip a square root with:
   *
   *   A = (x, sqrt(x^3 + a * x + b))
   *   e = H("BIP0340/challenge", r, x, m) mod n
   *   R = G * s - A * e
   *   y(R) is even
   *   x(R) == r
   */
  const unsigned char *Rraw = sig;
  const unsigned char *sraw = sig + 32;
  wge_t A, R;
  sc_t s, e;
  fe_t r;

  if (!fe_import(r, Rraw))
    return 0;

  if (!sc_import(s, sraw))
    return 0;

  if (!wge_import_even(&A, pub))
    return 0;

  bip340_hash_challenge(e, Rraw, pub, msg, msg_len);

  sc_neg(e, e);

  wei_mul_double_var(&R, s, &A, e);

  if (!wge_is_even(&R))
    return 0;

  if (!wge_equal_x(&R, r))
    return 0;

  return 1;
}

int
btc_bip340_verify_batch(const unsigned char *const *msgs,
                        const size_t *msg_lens,
                        const unsigned char *const *sigs,
                        const unsigned char *const *pubs,
                        size_t len,
                        wei_scratch_t *scratch) {
  /* BIP340 Batch Verification.
   *
   * [BIP340] "Batch Verification".
   *
   * Assumptions:
   *
   *   - Let `H` be a cryptographic hash function.
   *   - Let `m` be a 32-byte array.
   *   - Let `r` and `s` be signature elements.
   *   - Let `x` be a field element.
   *   - Let `i` be the batch item index.
   *   - r^3 + a * r + b is square in F(p).
   *   - x^3 + a * x + b is square in F(p).
   *   - sqrt(r^3 + a * r + b) is even in F(p).
   *   - sqrt(x^3 + a * x + b) is even in F(p).
   *   - r < p, s < n, x < p.
   *   - a1 = 1 mod n.
   *
   * Computation:
   *
   *   Ri = (ri, sqrt(ri^3 + a * ri + b))
   *   Ai = (xi, sqrt(xi^3 + a * xi + b))
   *   ei = H("BIP0340/challenge", ri, xi, mi) mod n
   *   ai = random integer in [1,n-1]
   *   lhs = si * ai + ... mod n
   *   rhs = Ri * ai + Ai * (ei * ai mod n) + ...
   *   G * -lhs + rhs == O
   */
  wge_t *points = scratch->points;
  sc_t *coeffs = scratch->coeffs;
  sc_t sum, s, e, a;
  btc_drbg_t rng;
  wge_t R, A;
  jge_t r;
  size_t j = 0;
  size_t i;

  CHECK(scratch->size >= 2);

  /* Seed RNG. */
  {
    unsigned char bytes[32];
    btc_sha256_t outer, inner;

    btc_sha256_init(&outer);

    for (i = 0; i < len; i++) {
      const unsigned char *msg = msgs[i];
      size_t msg_len = msg_lens[i];
      const unsigned char *sig = sigs[i];
      const unsigned char *pub = pubs[i];

      btc_sha256_init(&inner);
      btc_sha256_update(&inner, msg, msg_len);
      btc_sha256_final(&inner, bytes);

      btc_sha256_update(&outer, bytes, 32);
      btc_sha256_update(&outer, sig, 32 + 32);
      btc_sha256_update(&outer, pub, 32);
    }

    btc_sha256_final(&outer, bytes);

    btc_drbg_init(&rng, bytes, 32);
  }

  /* Intialize sum. */
  sc_zero(sum);

  /* Verify signatures. */
  for (i = 0; i < len; i++) {
    const unsigned char *msg = msgs[i];
    size_t msg_len = msg_lens[i];
    const unsigned char *sig = sigs[i];
    const unsigned char *pub = pubs[i];
    const unsigned char *Rraw = sig;
    const unsigned char *sraw = sig + 32;

    if (!sc_import(s, sraw))
      return 0;

    if (!wge_import_even(&R, Rraw))
      return 0;

    if (!wge_import_even(&A, pub))
      return 0;

    bip340_hash_challenge(e, Rraw, pub, msg, msg_len);

    if (j == 0)
      sc_set_word(a, 1);
    else
      sc_random(a, &rng);

    sc_mul(e, e, a);
    sc_mul(s, s, a);
    sc_add(sum, sum, s);

    wge_set(&points[j + 0], &R);
    wge_set(&points[j + 1], &A);

    sc_set(coeffs[j + 0], a);
    sc_set(coeffs[j + 1], e);

    j += 2;

    if (j == scratch->size - (scratch->size & 1)) {
      sc_neg(sum, sum);

      wei_jmul_multi_var(&r, sum, points, coeffs, j, scratch);

      if (!jge_is_zero(&r))
        return 0;

      sc_zero(sum);

      j = 0;
    }
  }

  if (j > 0) {
    sc_neg(sum, sum);

    wei_jmul_multi_var(&r, sum, points, coeffs, j, scratch);

    if (!jge_is_zero(&r))
      return 0;
  }

  return 1;
}

int
btc_bip340_derive(unsigned char *secret,
                  const unsigned char *pub,
                  const unsigned char *priv) {
  int ret = 1;
  wge_t A, P;
  sc_t a;

  ret &= sc_import(a, priv);
  ret &= sc_is_zero(a) ^ 1;
  ret &= wge_import_even(&A, pub);

  wei_mul(&P, &A, a);

  ret &= wge_export_x(secret, &P);

  sc_cleanse(a);

  wge_cleanse(&A);
  wge_cleanse(&P);

  return ret;
}
