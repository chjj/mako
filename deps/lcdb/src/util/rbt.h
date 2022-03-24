/*!
 * rbt.h - red-black tree for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_RBT_H
#define LDB_RBT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Types
 */

typedef union rb_val_s {
  void *p;
  int64_t si;
  uint64_t ui;
} rb_val_t;

typedef enum rb_color {
  RB_BLACK = 0,
  RB_RED = 1
} rb_color_t;

typedef struct rb_node_s {
  rb_val_t key;
  rb_val_t value;
  rb_color_t color;
  struct rb_node_s *parent;
  struct rb_node_s *left;
  struct rb_node_s *right;
} rb_node_t;

typedef int rb_cmp_f(rb_val_t, rb_val_t, void *);
typedef void rb_clear_f(rb_node_t *);
typedef void rb_copy_f(rb_node_t *, const rb_node_t *);

struct rb_tree_s;

typedef struct rb_iter_s {
  const struct rb_tree_s *tree;
  const rb_node_t *root;
  const rb_node_t *node;
} rb_iter_t;

typedef struct rb_tree_s {
  rb_node_t *root;
  rb_cmp_f *compare;
  void *arg;
  int unique;
  size_t size;
  rb_iter_t iter;
} rb_tree_t;

typedef rb_tree_t rb_map_t;
typedef rb_tree_t rb_set_t;
typedef rb_tree_t rb_set64_t;

/*
 * Aliases
 */

/* Node */
#define rb_node_destroy ldb_rb_node_destroy

/* Tree */
#define rb_tree_init ldb_rb_tree_init
#define rb_tree_clear ldb_rb_tree_clear
#define rb_tree_copy ldb_rb_tree_copy
#define rb_tree_get ldb_rb_tree_get
#define rb_tree_put ldb_rb_tree_put
#define rb_tree_del ldb_rb_tree_del
#define rb_tree_iterator ldb_rb_tree_iterator

/* Iterator */
#define rb_iter_init ldb_rb_iter_init
#define rb_iter_compare ldb_rb_iter_compare
#define rb_iter_valid ldb_rb_iter_valid
#define rb_iter_reset ldb_rb_iter_reset
#define rb_iter_first ldb_rb_iter_first
#define rb_iter_last ldb_rb_iter_last
#define rb_iter_seek ldb_rb_iter_seek
#define rb_iter_prev ldb_rb_iter_prev
#define rb_iter_next ldb_rb_iter_next
#define rb_iter_start ldb_rb_iter_start
#define rb_iter_kv ldb_rb_iter_kv
#define rb_iter_k ldb_rb_iter_k
#define rb_iter_v ldb_rb_iter_v

/* Map */
#define rb_map_get ldb_rb_map_get
#define rb_map_has ldb_rb_map_has
#define rb_map_put ldb_rb_map_put
#define rb_map_del ldb_rb_map_del
#define rb_map_kv ldb_rb_map_kv
#define rb_map_k ldb_rb_map_k
#define rb_map_v ldb_rb_map_v

/* Set */
#define rb_set_has ldb_rb_set_has
#define rb_set_put ldb_rb_set_put
#define rb_set_del ldb_rb_set_del
#define rb_set_k ldb_rb_set_k

/* Set64 */
#define rb_set64_compare ldb_rb_set64_compare
#define rb_set64_has ldb_rb_set64_has
#define rb_set64_put ldb_rb_set64_put
#define rb_set64_del ldb_rb_set64_del
#define rb_set64_k ldb_rb_set64_k

/*
 * Node
 */

void
rb_node_destroy(rb_node_t *node);

/*
 * Tree
 */

void
rb_tree_init(rb_tree_t *tree, rb_cmp_f *compare, void *arg, int unique);

void
rb_tree_clear(rb_tree_t *tree, rb_clear_f *clear);

#define rb_tree_reset rb_tree_clear

void
rb_tree_copy(rb_tree_t *z, const rb_tree_t *x, rb_copy_f *copy);

rb_node_t *
rb_tree_get(const rb_tree_t *tree, rb_val_t key);

rb_node_t *
rb_tree_put(rb_tree_t *tree, rb_val_t key, rb_val_t value);

rb_node_t *
rb_tree_del(rb_tree_t *tree, rb_val_t key);

rb_iter_t
rb_tree_iterator(const rb_tree_t *tree);

#define rb_tree_iterate(t, k, v) \
  rb_iter_iterate(t, (rb_iter_t *)&(t)->iter, k, v)

#define rb_tree_keys(t, k) rb_iter_keys(t, (rb_iter_t *)&(t)->iter, k)
#define rb_tree_values(t, v) rb_iter_values(t, (rb_iter_t *)&(t)->iter, v)

/*
 * Iterator
 */

void
rb_iter_init(rb_iter_t *iter, const rb_tree_t *tree);

int
rb_iter_compare(const rb_iter_t *iter, rb_val_t key);

int
rb_iter_valid(const rb_iter_t *iter);

void
rb_iter_reset(rb_iter_t *iter);

void
rb_iter_first(rb_iter_t *iter);

void
rb_iter_last(rb_iter_t *iter);

void
rb_iter_seek(rb_iter_t *iter, rb_val_t key);

int
rb_iter_prev(rb_iter_t *iter);

int
rb_iter_next(rb_iter_t *iter);

#define rb_iter_key(iter) (iter)->node->key
#define rb_iter_value(iter) (iter)->node->value

int
rb_iter_start(rb_iter_t *iter, const rb_tree_t *tree);

int
rb_iter_kv(const rb_iter_t *iter, rb_val_t *key, rb_val_t *value);

int
rb_iter_k(const rb_iter_t *iter, rb_val_t *key);

int
rb_iter_v(const rb_iter_t *iter, rb_val_t *value);

#define rb_iter_iterate(t, it, k, v) \
  for (rb_iter_start(it, t); rb_iter_kv(it, &(k), &(v)); rb_iter_next(it))

#define rb_iter_keys(t, it, k) \
  for (rb_iter_start(it, t); rb_iter_k(it, &(k)); rb_iter_next(it))

#define rb_iter_values(t, it, v) \
  for (rb_iter_start(it, t); rb_iter_v(it, &(v)); rb_iter_next(it))

/*
 * Map
 */

#define rb_map_init(tree, compare, arg) rb_tree_init(tree, compare, arg, 1)
#define rb_map_clear rb_tree_clear
#define rb_map_reset rb_tree_clear
#define rb_map_copy rb_tree_copy

void *
rb_map_get(const rb_tree_t *tree, const void *key);

int
rb_map_has(const rb_tree_t *tree, const void *key);

int
rb_map_put(rb_tree_t *tree, const void *key, const void *value);

rb_node_t *
rb_map_del(rb_tree_t *tree, const void *key);

int
rb_map_kv(const rb_iter_t *iter, void **key, void **value);

int
rb_map_k(const rb_iter_t *iter, void **key);

int
rb_map_v(const rb_iter_t *iter, void **value);

#define rb_map__iter(t, it, k, v) \
  for (rb_iter_start(it, t); rb_map_kv(it, &(k), &(v)); rb_iter_next(it))

#define rb_map__keys(t, it, k) \
  for (rb_iter_start(it, t); rb_map_k(it, &(k)); rb_iter_next(it))

#define rb_map__values(t, it, v) \
  for (rb_iter_start(it, t); rb_map_v(it, &(v)); rb_iter_next(it))

#define rb_map_iterate(t, k, v) rb_map__iter(t, (rb_iter_t *)&(t)->iter, k, v)
#define rb_map_keys(t, k) rb_map__keys(t, (rb_iter_t *)&(t)->iter, k)
#define rb_map_values(t, v) rb_map__values(t, (rb_iter_t *)&(t)->iter, v)

/*
 * Set
 */

#define rb_set_init(tree, compare, arg) rb_tree_init(tree, compare, arg, 1)
#define rb_set_clear rb_tree_clear
#define rb_set_reset rb_tree_clear
#define rb_set_copy rb_tree_copy

int
rb_set_has(const rb_tree_t *tree, const void *item);

int
rb_set_put(rb_tree_t *tree, const void *item);

void *
rb_set_del(rb_tree_t *tree, const void *item);

int
rb_set_k(const rb_iter_t *iter, void **key);

#define rb__set_keys(t, it, k) \
  for (rb_iter_start(it, t); rb_set_k(it, &(k)); rb_iter_next(it))

#define rb_set_iterate(t, k) rb__set_keys(t, (rb_iter_t *)&(t)->iter, k)

/*
 * Set64
 */

#define rb_set64_init(tree) rb_tree_init(tree, rb_set64_compare, NULL, 1)
#define rb_set64_clear(tree) rb_tree_clear(tree, NULL)
#define rb_set64_reset rb_set64_clear
#define rb_set64_copy(z, x) rb_tree_copy(z, x, NULL)

int
rb_set64_compare(rb_val_t x, rb_val_t y, void *arg);

int
rb_set64_has(const rb_tree_t *tree, uint64_t item);

int
rb_set64_put(rb_tree_t *tree, uint64_t item);

int
rb_set64_del(rb_tree_t *tree, uint64_t item);

int
rb_set64_k(const rb_iter_t *iter, uint64_t *key);

#define rb__set64_keys(t, it, k) \
  for (rb_iter_start(it, t); rb_set64_k(it, &(k)); rb_iter_next(it))

#define rb_set64_iterate(t, k) rb__set64_keys(t, (rb_iter_t *)&(t)->iter, k)

#endif /* LDB_RBT_H */
