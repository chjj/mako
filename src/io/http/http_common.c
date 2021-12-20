/*!
 * http_common.c - http utils for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <io/http.h>
#include "http_common.h"

/*
 * Helpers
 */

void *
http_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

void *
http_realloc(void *ptr, size_t size) {
  ptr = realloc(ptr, size);

  if (ptr == NULL) {
    abort(); /* LCOV_EXCL_LINE */
    return NULL;
  }

  return ptr;
}

/*
 * String
 */

void
http_string_init(http_string_t *str) {
  str->data = http_malloc(1);
  str->data[0] = '\0';
  str->alloc = 0;
  str->length = 0;
}

void
http_string_clear(http_string_t *str) {
  free(str->data);
}

void
http_string_reset(http_string_t *str) {
  str->data[0] = '\0';
  str->length = 0;
}

void
http_string_grow(http_string_t *str, size_t len) {
  if (len > str->alloc) {
    str->data = http_realloc(str->data, len + 1);
    str->alloc = len;
  }
}

void
http_string_copy(http_string_t *z, const http_string_t *x) {
  http_string_grow(z, x->length);

  memcpy(z->data, x->data, x->length + 1);

  z->length = x->length;
}

void
http_string_assign(http_string_t *z, const char *xp, size_t xn) {
  http_string_grow(z, xn);

  if (xn > 0)
    memcpy(z->data, xp, xn);

  z->length = xn;
  z->data[z->length] = '\0';
}

void
http_string_set(http_string_t *z, const char *xp) {
  http_string_assign(z, xp, strlen(xp));
}

void
http_string_append(http_string_t *z, const char *xp, size_t xn) {
  http_string_grow(z, z->length + xn);

  if (xn > 0)
    memcpy(z->data + z->length, xp, xn);

  z->length += xn;
  z->data[z->length] = '\0';
}

void
http_string_lower(http_string_t *z) {
  size_t i;

  for (i = 0; i < z->length; i++)
    z->data[i] |= 0x20;
}

int
http_string_equal(const http_string_t *x, const char *yp, size_t yn) {
  size_t i;

  if (x->length != yn)
    return 0;

  for (i = 0; i < x->length; i++) {
    int a = x->data[i] | 0x20;
    int b = yp[i] | 0x20;

    if (a != b)
      return 0;
  }

  return 1;
}

/*
 * Header
 */

void
http_header_init(http_header_t *hdr) {
  http_string_init(&hdr->field);
  http_string_init(&hdr->value);
}

void
http_header_clear(http_header_t *hdr) {
  http_string_clear(&hdr->field);
  http_string_clear(&hdr->value);
}

void
http_header_reset(http_header_t *hdr) {
  http_string_reset(&hdr->field);
  http_string_reset(&hdr->value);
}

http_header_t *
http_header_create(void) {
  http_header_t *hdr = http_malloc(sizeof(http_header_t));
  http_header_init(hdr);
  return hdr;
}

void
http_header_destroy(http_header_t *hdr) {
  http_header_clear(hdr);
  free(hdr);
}

/*
 * Head
 */

void
http_head_init(http_head_t *z) {
  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
http_head_clear(http_head_t *z) {
  size_t i;

  for (i = 0; i < z->length; i++)
    http_header_destroy(z->items[i]);

  if (z->alloc > 0)
    free(z->items);

  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
http_head_grow(http_head_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->items = http_realloc(z->items, zn * sizeof(http_header_t *));
    z->alloc = zn;
  }
}

void
http_head_push(http_head_t *z, http_header_t *x) {
  if (z->length == z->alloc)
    http_head_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->items[z->length++] = x;
}

void
http_head_push_item(http_head_t *z, const char *field, const char *value) {
  http_header_t *hdr = http_header_create();

  http_string_set(&hdr->field, field);
  http_string_set(&hdr->value, value);

  http_head_push(z, hdr);
}

/*
 * Base64
 */

static const char *base64_charset =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const signed char base64_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59,
  60, 61, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32,
  33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static int
base64_check_padding(const char *str, size_t len, size_t size) {
  switch (size % 3) {
    case 0: {
      if (len == 0)
        return 1;

      if (len == 1)
        return str[0] != '=';

      return str[len - 2] != '='
          && str[len - 1] != '=';
    }

    case 1: {
      return len >= 4
          && str[len - 2] == '='
          && str[len - 1] == '=';
    }

    case 2: {
      return len >= 4
          && str[len - 2] != '='
          && str[len - 1] == '=';
    }

    default: {
      return 0; /* Unreachable. */
    }
  }
}

size_t
base64_encode_size(size_t len) {
  size_t size = (len / 3) * 4;

  switch (len % 3) {
    case 1:
      size += 2;
      size += 2;
      break;
    case 2:
      size += 3;
      size += 1;
      break;
  }

  return size;
}

void
base64_encode(char *dst,
              size_t *dstlen,
              const unsigned char *src,
              size_t srclen) {
  size_t left = srclen;
  size_t i = 0;
  size_t j = 0;

  while (left >= 3) {
    int c1 = src[i++];
    int c2 = src[i++];
    int c3 = src[i++];

    dst[j++] = base64_charset[c1 >> 2];
    dst[j++] = base64_charset[((c1 & 3) << 4) | (c2 >> 4)];
    dst[j++] = base64_charset[((c2 & 15) << 2) | (c3 >> 6)];
    dst[j++] = base64_charset[c3 & 63];

    left -= 3;
  }

  switch (left) {
    case 1: {
      int c1 = src[i++];

      dst[j++] = base64_charset[c1 >> 2];
      dst[j++] = base64_charset[(c1 & 3) << 4];
      dst[j++] = '=';
      dst[j++] = '=';

      break;
    }

    case 2: {
      int c1 = src[i++];
      int c2 = src[i++];

      dst[j++] = base64_charset[c1 >> 2];
      dst[j++] = base64_charset[((c1 & 3) << 4) | (c2 >> 4)];
      dst[j++] = base64_charset[(c2 & 15) << 2];
      dst[j++] = '=';

      break;
    }
  }

  dst[j] = '\0';

  if (dstlen != NULL)
    *dstlen = j;
}

size_t
base64_decode_size(const char *str, size_t len) {
  size_t size, rem;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  size = (len / 4) * 3;
  rem = len & 3;

  if (rem)
    size += rem - 1;

  return size;
}

int
base64_decode(unsigned char *dst,
              size_t *dstlen,
              const char *src,
              size_t srclen) {
  size_t size = base64_decode_size(src, srclen);
  size_t left = srclen;
  size_t i = 0;
  size_t j = 0;

  if (!base64_check_padding(src, srclen, size))
    return 0;

  if (left > 0 && src[left - 1] == '=')
    left -= 1;

  if (left > 0 && src[left - 1] == '=')
    left -= 1;

  if ((left & 3) == 1) /* Fail early. */
    return 0;

  while (left >= 4) {
    int t1 = base64_table[src[i++] & 0xff];
    int t2 = base64_table[src[i++] & 0xff];
    int t3 = base64_table[src[i++] & 0xff];
    int t4 = base64_table[src[i++] & 0xff];

    if ((t1 | t2 | t3 | t4) < 0)
      return 0;

    dst[j++] = (t1 << 2) | (t2 >> 4);
    dst[j++] = (t2 << 4) | (t3 >> 2);
    dst[j++] = (t3 << 6) | (t4 >> 0);

    left -= 4;
  }

  switch (left) {
    case 1: {
      return 0;
    }

    case 2: {
      int t1 = base64_table[src[i++] & 0xff];
      int t2 = base64_table[src[i++] & 0xff];

      if ((t1 | t2) < 0)
        return 0;

      dst[j++] = (t1 << 2) | (t2 >> 4);

      if (t2 & 15)
        return 0;

      break;
    }

    case 3: {
      int t1 = base64_table[src[i++] & 0xff];
      int t2 = base64_table[src[i++] & 0xff];
      int t3 = base64_table[src[i++] & 0xff];

      if ((t1 | t2 | t3) < 0)
        return 0;

      dst[j++] = (t1 << 2) | (t2 >> 4);
      dst[j++] = (t2 << 4) | (t3 >> 2);

      if (t3 & 3)
        return 0;

      break;
    }
  }

  if (dstlen != NULL)
    *dstlen = j;

  return 1;
}

int
base64_test(const char *str, size_t len) {
  size_t size = base64_decode_size(str, len);
  size_t i;

  if (!base64_check_padding(str, len, size))
    return 0;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  if (len > 0 && str[len - 1] == '=')
    len -= 1;

  if ((len & 3) == 1) /* Fail early. */
    return 0;

  for (i = 0; i < len; i++) {
    if (base64_table[str[i] & 0xff] == -1)
      return 0;
  }

  switch (len & 3) {
    case 1:
      return 0;
    case 2:
      return (base64_table[str[len - 1] & 0xff] & 15) == 0;
    case 3:
      return (base64_table[str[len - 1] & 0xff] & 3) == 0;
  }

  return 1;
}
