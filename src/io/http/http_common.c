/*!
 * http_common.c - http utils for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
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
