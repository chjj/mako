/*!
 * list.h - linked list macros for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_LIST_H
#define BTC_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * List
 */

#define btc_list_create(q, list_t) do {   \
  (q) = (list_t *)malloc(sizeof(list_t)); \
                                          \
  if ((q) == NULL)                        \
    abort(); /* LCOV_EXCL_LINE */         \
                                          \
  btc_list_init(q);                       \
} while (0)

#define btc_list_destroy(q) free(q)

#define btc_list_init(q) do { \
  (q)->head = NULL;           \
  (q)->tail = NULL;           \
  (q)->length = 0;            \
} while (0)

#define btc_list_reset btc_list_init

#define btc_list_insert(q, r, x, node_t) do {   \
  node_t *rr = (r), *xx = (x);                  \
                                                \
  xx->prev = rr;                                \
  xx->next = rr != NULL ? rr->next : (q)->head; \
                                                \
  if (xx->prev != NULL)                         \
    xx->prev->next = xx;                        \
                                                \
  if (xx->next != NULL)                         \
    xx->next->prev = xx;                        \
                                                \
  if (rr == NULL)                               \
    (q)->head = xx;                             \
                                                \
  if (rr == (q)->tail)                          \
    (q)->tail = xx;                             \
                                                \
  (q)->length++;                                \
} while (0)

#define btc_list_remove(q, x, node_t) do { \
  node_t *xx = (x);                        \
                                           \
  if (xx->prev != NULL)                    \
    xx->prev->next = xx->next;             \
                                           \
  if (xx->next != NULL)                    \
    xx->next->prev = xx->prev;             \
                                           \
  if (xx == (q)->head)                     \
    (q)->head = xx->next;                  \
                                           \
  if (xx == (q)->tail)                     \
    (q)->tail = xx->prev;                  \
                                           \
  xx->prev = NULL;                         \
  xx->next = NULL;                         \
                                           \
  (q)->length--;                           \
} while (0)

#define btc_list_replace(q, r, x, node_t) do { \
  node_t *rr = (r), *xx = (x);                 \
                                               \
  xx->prev = rr->prev;                         \
  xx->next = rr->next;                         \
                                               \
  if (rr->prev != NULL)                        \
    rr->prev->next = xx;                       \
                                               \
  if (rr->next != NULL)                        \
    rr->next->prev = xx;                       \
                                               \
  if (rr == (q)->head)                         \
    (q)->head = xx;                            \
                                               \
  if (rr == (q)->tail)                         \
    (q)->tail = xx;                            \
                                               \
  rr->prev = NULL;                             \
  rr->next = NULL;                             \
} while (0)

#define btc_list_unshift(q, x, node_t) btc_list_insert(q, NULL, x, node_t)
#define btc_list_push(q, x, node_t) btc_list_insert(q, (q)->tail, x, node_t)
#define btc_list_shift(q, node_t) btc_list_remove(q, (q)->head, node_t)
#define btc_list_pop(q, node_t) btc_list_remove(q, (q)->tail, node_t)

/*
 * Queue
 */

#define btc_queue_init btc_list_init
#define btc_queue_reset btc_list_reset

#define btc_queue_push(q, x) do { \
  if ((q)->head == NULL)          \
    (q)->head = (x);              \
                                  \
  if ((q)->tail != NULL)          \
    (q)->tail->next = (x);        \
                                  \
  (q)->tail = (x);                \
  (q)->length++;                  \
} while (0)

#define btc_queue_shift(q) do {  \
  if ((q)->head != NULL) {       \
    (q)->head = (q)->head->next; \
    (q)->length--;               \
                                 \
    if ((q)->head == NULL)       \
      (q)->tail = NULL;          \
  }                              \
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* BTC_LIST_H */
