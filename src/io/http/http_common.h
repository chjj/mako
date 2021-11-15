/*!
 * http_common.h - http utils for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <io/http.h>

/*
 * Constants
 */

#define HTTP_MAX_BUFFER (20 << 20)
#define HTTP_MAX_FIELD_SIZE (1 << 10)
#define HTTP_MAX_HEADERS 100
#define HTTP_BACKLOG 100

/*
 * Helpers
 */

void *
http_malloc(size_t size);

void *
http_realloc(void *ptr, size_t size);

/*
 * String
 */

void
http_string_init(http_string_t *str);

void
http_string_clear(http_string_t *str);

void
http_string_reset(http_string_t *str);

void
http_string_grow(http_string_t *str, size_t len);

void
http_string_copy(http_string_t *z, const http_string_t *x);

void
http_string_assign(http_string_t *z, const char *xp, size_t xn);

void
http_string_set(http_string_t *z, const char *xp);

void
http_string_append(http_string_t *z, const char *xp, size_t xn);

void
http_string_lower(http_string_t *z);

int
http_string_equal(const http_string_t *x, const char *yp, size_t yn);

/*
 * Header
 */

void
http_header_init(http_header_t *hdr);

void
http_header_clear(http_header_t *hdr);

void
http_header_reset(http_header_t *hdr);

http_header_t *
http_header_create(void);

void
http_header_destroy(http_header_t *hdr);

/*
 * Head
 */

void
http_head_init(http_head_t *z);

void
http_head_clear(http_head_t *z);

void
http_head_grow(http_head_t *z, size_t zn);

void
http_head_push(http_head_t *z, http_header_t *x);

void
http_head_push_item(http_head_t *z, const char *field, const char *value);

#endif /* HTTP_COMMON_H */
