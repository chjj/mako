/*!
 * scalar.h - scalar inversion chains for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

static void
secq256k1_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_scalar_inversion */
  /* https://github.com/bitcoin-core/secp256k1/blob/master/src/scalar_impl.h */
  sc_t x2, x3, x6, x8, x14, x28, x56, x112, x126;
  sc_t u1, u2, u5, u9, u11, u13;

  sc_mont(sc, u1, x);

  sc_montsqr(sc, u2, u1);
  sc_montmul(sc, x2, u2, u1);
  sc_montmul(sc, u5, u2, x2);
  sc_montmul(sc, x3, u5, u2);
  sc_montmul(sc, u9, x3, u2);
  sc_montmul(sc, u11, u9, u2);
  sc_montmul(sc, u13, u11, u2);

  sc_montsqr(sc, x6, u13);
  sc_montsqr(sc, x6, x6);
  sc_montmul(sc, x6, x6, u11);

  sc_montsqr(sc, x8, x6);
  sc_montsqr(sc, x8, x8);
  sc_montmul(sc, x8, x8,  x2);

  sc_montsqr(sc, x14, x8);
  sc_montsqrn(sc, x14, x14, 5);
  sc_montmul(sc, x14, x14, x6);

  sc_montsqr(sc, x28, x14);
  sc_montsqrn(sc, x28, x28, 13);
  sc_montmul(sc, x28, x28, x14);

  sc_montsqr(sc, x56, x28);
  sc_montsqrn(sc, x56, x56, 27);
  sc_montmul(sc, x56, x56, x28);

  sc_montsqr(sc, x112, x56);
  sc_montsqrn(sc, x112, x112, 55);
  sc_montmul(sc, x112, x112, x56);

  sc_montsqr(sc, x126, x112);
  sc_montsqrn(sc, x126, x126, 13);
  sc_montmul(sc, z, x126, x14);

  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01011 */
  sc_montmul(sc, z, z, u11);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, u11);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, u9);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 7 + 3); /* 0000000111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 8); /* 011111111 */
  sc_montmul(sc, z, z, x8);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, u9);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001011 */
  sc_montmul(sc, z, z, u11);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 0 + 5); /* 11 */
  sc_montmul(sc, z, z, x2);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 6 + 4); /* 0000001101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, u9);
  sc_montsqrn(sc, z, z, 5 + 1); /* 000001 */
  sc_montmul(sc, z, z, u1);
  sc_montsqrn(sc, z, z, 2 + 6); /* 00111111 */
  sc_montmul(sc, z, z, x6);

  sc_normal(sc, z, z);

  sc_cleanse(sc, u1);
}
