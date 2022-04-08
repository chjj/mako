/*!
 * iterator.h - iterator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_ITERATOR_H
#define LDB_ITERATOR_H

#include <stddef.h>

#include "../util/extern.h"
#include "../util/types.h"

/*
 * Types
 */

/* Clients are allowed to register function/arg1/arg2 triples that
 * will be invoked when this iterator is destroyed.
 *
 * Note that unlike all of the preceding methods, this method is
 * not abstract and therefore clients should not override it.
 */
typedef void (*ldb_cleanup_f)(void *arg1, void *arg2);

/* Cleanup functions are stored in a single-linked list.
   The list's head node is inlined in the iterator. */
typedef struct ldb_cleanup_s {
  /* The head node is used if the function pointer is not null. */
  ldb_cleanup_f func;
  void *arg1;
  void *arg2;
  struct ldb_cleanup_s *next;
} ldb_cleanup_t;

typedef struct ldb_itertbl_s ldb_itertbl_t;

typedef struct ldb_iter_s {
  /* The underlying iterator. */
  void *ptr;

  /* Cleanup functions are stored in a single-linked list.
     The list's head node is inlined in the iterator. */
  ldb_cleanup_t cleanup_head;

  /* Iterator function table. */
  const ldb_itertbl_t *table;
} ldb_iter_t;

/*
 * Function Table
 */

struct ldb_itertbl_s {
  /* Clear iterator. */
  void (*clear)(void *iter);

  /* An iterator is either positioned at a key/value pair, or
     not valid. This method returns true iff the iterator is valid. */
  int (*valid)(const void *iter);

  /* Position at the first key in the source. The iterator is valid()
     after this call iff the source is not empty. */
  void (*first)(void *iter);

  /* Position at the last key in the source. The iterator is
     valid() after this call iff the source is not empty. */
  void (*last)(void *iter);

  /* Position at the first key in the source that is at or past target.
     The iterator is valid() after this call iff the source contains
     an entry that comes at or past target. */
  void (*seek)(void *iter, const ldb_slice_t *target);

  /* Moves to the next entry in the source. After this call, valid() is
     true iff the iterator was not positioned at the last entry in the source.
     REQUIRES: valid() */
  void (*next)(void *iter);

  /* Moves to the previous entry in the source. After this call, valid() is
     true iff the iterator was not positioned at the first entry in source.
     REQUIRES: valid() */
  void (*prev)(void *iter);

  /* Return the key for the current entry. The underlying storage for
     the returned slice is valid only until the next modification of
     the iterator.
     REQUIRES: valid() */
  ldb_slice_t (*key)(const void *iter);

  /* Return the value for the current entry. The underlying storage for
     the returned slice is valid only until the next modification of
     the iterator.
     REQUIRES: valid() */
  ldb_slice_t (*value)(const void *iter);

  /* If an error has occurred, return it. Else return an ok status. */
  int (*status)(const void *iter);
};

#define LDB_ITERATOR_FUNCTIONS(name)                                  \
                                                                      \
static const ldb_itertbl_t name ## _table = {                         \
  /* .clear = */ (void (*)(void *))name ## _clear,                    \
  /* .valid = */ (int (*)(const void *))name ## _valid,               \
  /* .first = */ (void (*)(void *))name ## _first,                    \
  /* .last = */ (void (*)(void *))name ## _last,                      \
  /* .seek = */ (void (*)(void *, const ldb_slice_t *))name ## _seek, \
  /* .next = */ (void (*)(void *))name ## _next,                      \
  /* .prev = */ (void (*)(void *))name ## _prev,                      \
  /* .key = */ (ldb_slice_t (*)(const void *))name ## _key,           \
  /* .value = */ (ldb_slice_t (*)(const void *))name ## _value,       \
  /* .status = */ (int (*)(const void *))name ## _status              \
}

/* Casting function pointers is technically UB[1] but will
 * work on a vast majority of platforms. Notable exceptions
 * include a lot of old 16 bit platforms as well as wasm and
 * emscripten[2].
 *
 * [1] https://stackoverflow.com/questions/559581
 * [2] https://emscripten.org/docs/porting/guidelines/function_pointer_issues.html
 */
#if defined(__wasm__) || defined(__EMSCRIPTEN__)

#undef LDB_ITERATOR_FUNCTIONS

#define LDB_ITERATOR_FUNCTIONS(name)                           \
                                                               \
static void                                                    \
name ## _clear_wrapped(void *iter) {                           \
  name ## _clear((name ## _t *)iter);                          \
}                                                              \
                                                               \
static int                                                     \
name ## _valid_wrapped(const void *iter) {                     \
  return name ## _valid((const name ## _t *)iter);             \
}                                                              \
                                                               \
static void                                                    \
name ## _seek_wrapped(void *iter, const ldb_slice_t *target) { \
  name ## _seek((name ## _t *)iter, target);                   \
}                                                              \
                                                               \
static void                                                    \
name ## _first_wrapped(void *iter) {                           \
  name ## _first((name ## _t *)iter);                          \
}                                                              \
                                                               \
static void                                                    \
name ## _last_wrapped(void *iter) {                            \
  name ## _last((name ## _t *)iter);                           \
}                                                              \
                                                               \
static void                                                    \
name ## _next_wrapped(void *iter) {                            \
  name ## _next((name ## _t *)iter);                           \
}                                                              \
                                                               \
static void                                                    \
name ## _prev_wrapped(void *iter) {                            \
  name ## _prev((name ## _t *)iter);                           \
}                                                              \
                                                               \
static ldb_slice_t                                             \
name ## _key_wrapped(const void *iter) {                       \
  return name ## _key((const name ## _t *)iter);               \
}                                                              \
                                                               \
static ldb_slice_t                                             \
name ## _value_wrapped(const void *iter) {                     \
  return name ## _value((const name ## _t *)iter);             \
}                                                              \
                                                               \
static int                                                     \
name ## _status_wrapped(const void *iter) {                    \
  return name ## _status((const name ## _t *)iter);            \
}                                                              \
                                                               \
static const ldb_itertbl_t name ## _table = {                  \
  /* .clear = */ name ## _clear_wrapped,                       \
  /* .valid = */ name ## _valid_wrapped,                       \
  /* .first = */ name ## _first_wrapped,                       \
  /* .last = */ name ## _last_wrapped,                         \
  /* .seek = */ name ## _seek_wrapped,                         \
  /* .next = */ name ## _next_wrapped,                         \
  /* .prev = */ name ## _prev_wrapped,                         \
  /* .key = */ name ## _key_wrapped,                           \
  /* .value = */ name ## _value_wrapped,                       \
  /* .status = */ name ## _status_wrapped                      \
}

#endif /* __wasm__ || __EMSCRIPTEN__ */

/*
 * Cleanup
 */

/* True if the node is not used. Only head nodes might be unused. */
#define ldb_cleanup_empty(x) ((x)->func == NULL)
/* Invokes the cleanup function. */
#define ldb_cleanup_run(x) (x)->func((x)->arg1, (x)->arg2)

/*
 * Iterator
 */

ldb_iter_t *
ldb_iter_create(void *ptr, const ldb_itertbl_t *table);

LDB_EXTERN void
ldb_iter_destroy(ldb_iter_t *iter);

void
ldb_iter_register_cleanup(ldb_iter_t *iter,
                          ldb_cleanup_f func,
                          void *arg1,
                          void *arg2);

#ifdef LDB_ITERATOR_C

LDB_EXTERN int
ldb_iter_valid(const ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_first(ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_last(ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_seek(ldb_iter_t *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_next(ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_prev(ldb_iter_t *iter);

LDB_EXTERN ldb_slice_t
ldb_iter_key(const ldb_iter_t *iter);

LDB_EXTERN ldb_slice_t
ldb_iter_value(const ldb_iter_t *iter);

LDB_EXTERN int
ldb_iter_status(const ldb_iter_t *iter);

#else /* !LDB_ITERATOR_C */

#define ldb_iter_valid(x) (x)->table->valid((x)->ptr)
#define ldb_iter_first(x) (x)->table->first((x)->ptr)
#define ldb_iter_last(x) (x)->table->last((x)->ptr)
#define ldb_iter_seek(x, y) (x)->table->seek((x)->ptr, y)
#define ldb_iter_next(x) (x)->table->next((x)->ptr)
#define ldb_iter_prev(x) (x)->table->prev((x)->ptr)
#define ldb_iter_key(x) (x)->table->key((x)->ptr)
#define ldb_iter_value(x) (x)->table->value((x)->ptr)
#define ldb_iter_status(x) (x)->table->status((x)->ptr)

#endif /* !LDB_ITERATOR_C */

/*
 * Empty Iterator
 */

/* Return an empty iterator with the specified status. */
ldb_iter_t *
ldb_emptyiter_create(int status);

#endif /* LDB_ITERATOR_H */
