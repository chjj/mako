/*!
 * asn1.h - asn1 for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_ASN1_H
#define BTC_ASN1_H

#include <stddef.h>

/*
 * Alias
 */

#define asn1_read_size btc__asn1_read_size
#define asn1_read_seq btc__asn1_read_seq
#define asn1_read_int btc__asn1_read_int
#define asn1_size_size btc__asn1_size_size
#define asn1_size_int btc__asn1_size_int
#define asn1_write_size btc__asn1_write_size
#define asn1_write_seq btc__asn1_write_seq
#define asn1_write_int btc__asn1_write_int

/*
 * ASN1
 */

int
asn1_read_size(size_t *size,
               const unsigned char **data,
               size_t *len, int strict);

int
asn1_read_seq(const unsigned char **data, size_t *len, int strict);

int
asn1_read_int(unsigned char *out, size_t out_len,
              const unsigned char **data, size_t *len, int strict);

size_t
asn1_size_size(size_t size);

size_t
asn1_size_int(const unsigned char *num, size_t len);

size_t
asn1_write_size(unsigned char *data, size_t pos, size_t size);

size_t
asn1_write_seq(unsigned char *data, size_t pos, size_t size);

size_t
asn1_write_int(unsigned char *data, size_t pos,
               const unsigned char *num, size_t len);

#endif /* BTC_ASN1_H */
