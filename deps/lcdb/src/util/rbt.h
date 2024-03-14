/*!
 * rbt.h - red-black tree for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_RBT_H
#define LDB_RBT_H

#include <stddef.h>
#include <stdint.h>
#include "internal.h"

/*
 * Types
 */

typedef union rb_val_s {
  void *ptr;
  uint64_t ui;
  int64_t si;
} rb_val_t;

typedef enum rb_color {
  RB_BLACK = 0,
  RB_RED = 1
} rb_color_t;

typedef struct rb_node_s {
  rb_val_t key;
  rb_val_t val;
  rb_color_t color;
  struct rb_node_s *parent;
  struct rb_node_s *left;
  struct rb_node_s *right;
} rb_node_t;

typedef int rb_cmp_f(rb_val_t, rb_val_t, void *);
typedef void rb_clear_f(rb_node_t *);
typedef void rb_copy_f(rb_node_t *, const rb_node_t *);

typedef struct rb_tree_s {
  rb_node_t *root;
  rb_cmp_f *compare;
  void *arg;
  size_t size;
} rb_tree_t;

typedef struct rb_iter_s {
  const struct rb_tree_s *tree;
  const rb_node_t *root;
  const rb_node_t *node;
} rb_iter_t;

typedef rb_tree_t rb_map_t;
typedef rb_tree_t rb_set_t;
typedef rb_tree_t rb_set64_t;

typedef struct rb_entry_s {
  void *key;
  void *val;
} rb_entry_t;

/*
 * Union Helpers
 */

LDB_UNUSED static rb_val_t
rb_ptr(const void *ptr) {
  rb_val_t val;
  val.ptr = (void *)ptr;
  return val;
}

LDB_UNUSED static rb_val_t
rb_ui(uint64_t ui) {
  rb_val_t val;
  val.ui = ui;
  return val;
}

LDB_UNUSED static rb_val_t
rb_si(int64_t si) {
  rb_val_t val;
  val.si = si;
  return val;
}

/*
 * Aliases
 */

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
#define rb_iter_valid ldb_rb_iter_valid
#define rb_iter_first ldb_rb_iter_first
#define rb_iter_last ldb_rb_iter_last
#define rb_iter_seek ldb_rb_iter_seek
#define rb_iter_prev ldb_rb_iter_prev
#define rb_iter_next ldb_rb_iter_next
#define rb_iter_start ldb_rb_iter_start

/* Map */
#define rb_map_get ldb_rb_map_get
#define rb_map_has ldb_rb_map_has
#define rb_map_put ldb_rb_map_put
#define rb_map_del ldb_rb_map_del

/* Set */
#define rb_set_has ldb_rb_set_has
#define rb_set_put ldb_rb_set_put
#define rb_set_del ldb_rb_set_del

/* Set64 */
#define rb_set64_has ldb_rb_set64_has
#define rb_set64_put ldb_rb_set64_put
#define rb_set64_del ldb_rb_set64_del

/*
 * Tree
 */

#define RB_TREE_INIT(compare) { \
  /* .root = */ NULL,           \
  /* .compare = */ (compare),   \
  /* .arg = */ NULL,            \
  /* .size = */ 0               \
}

void
rb_tree_init(rb_tree_t *tree, rb_cmp_f *compare, void *arg);

void
rb_tree_clear(rb_tree_t *tree, rb_clear_f *clear);

void
rb_tree_copy(rb_tree_t *z, const rb_tree_t *x, rb_copy_f *copy);

#define rb_tree_has(tree, key) (rb_tree_get(tree, key) != NULL)

rb_node_t *
rb_tree_get(const rb_tree_t *tree, rb_val_t key);

int
rb_tree_put(rb_tree_t *tree, rb_val_t key, rb_node_t **result);

int
rb_tree_del(rb_tree_t *tree, rb_val_t key, rb_node_t *result);

rb_iter_t
rb_tree_iterator(const rb_tree_t *tree);

#define rb_tree_each(tree, it)     \
  for (rb_iter_start(&(it), tree); \
       rb_iter_valid(&(it));       \
       rb_iter_next(&(it)))

/*
 * Iterator
 */

void
rb_iter_init(rb_iter_t *iter, const rb_tree_t *tree);

int
rb_iter_valid(const rb_iter_t *iter);

void
rb_iter_first(rb_iter_t *iter);

void
rb_iter_last(rb_iter_t *iter);

void
rb_iter_seek(rb_iter_t *iter, rb_val_t key);

void
rb_iter_prev(rb_iter_t *iter);

void
rb_iter_next(rb_iter_t *iter);

#define rb_iter_key(iter) ((iter)->node->key)
#define rb_iter_val(iter) ((iter)->node->val)

void
rb_iter_start(rb_iter_t *iter, const rb_tree_t *tree);

#define rb_iter_each(iter)  \
  for (rb_iter_first(iter); \
       rb_iter_valid(iter); \
       rb_iter_next(iter))

#define rb_iter_backwards(iter) \
  for (rb_iter_last(iter);      \
       rb_iter_valid(iter);     \
       rb_iter_prev(iter))

#define rb_key_ptr(it) ((it).node->key.ptr)
#define rb_key_ui(it) ((it).node->key.ui)
#define rb_key_si(it) ((it).node->key.si)

#define rb_val_ptr(it) ((it).node->val.ptr)
#define rb_val_ui(it) ((it).node->val.ui)
#define rb_val_si(it) ((it).node->val.si)

/*
 * Map
 */

#define RB_MAP_INIT RB_TREE_INIT
#define rb_map_init rb_tree_init
#define rb_map_clear rb_tree_clear
#define rb_map_copy rb_tree_copy

void *
rb_map_get(const rb_tree_t *tree, const void *key);

int
rb_map_has(const rb_tree_t *tree, const void *key);

int
rb_map_put(rb_tree_t *tree, const void *key, const void *val);

int
rb_map_del(rb_tree_t *tree, const void *key, rb_entry_t *result);

#define rb_map_iterator rb_tree_iterator
#define rb_map_each rb_tree_each

/*
 * Set
 */

#define RB_SET_INIT RB_TREE_INIT
#define rb_set_init rb_tree_init
#define rb_set_clear rb_tree_clear
#define rb_set_copy rb_tree_copy

int
rb_set_has(const rb_tree_t *tree, const void *item);

int
rb_set_put(rb_tree_t *tree, const void *item);

void *
rb_set_del(rb_tree_t *tree, const void *item);

#define rb_set_iterator rb_tree_iterator
#define rb_set_each rb_tree_each

/*
 * Set64
 */

#define RB_SET64_INIT RB_TREE_INIT(rb_set64_compare)
#define rb_set64_init(tree) rb_tree_init(tree, rb_set64_compare, NULL)
#define rb_set64_clear(tree) rb_tree_clear(tree, NULL)
#define rb_set64_copy(z, x) rb_tree_copy(z, x, NULL)

LDB_UNUSED static int
rb_set64_compare(rb_val_t x, rb_val_t y, void *arg) {
  (void)arg;
  return (x.ui > y.ui) - (x.ui < y.ui);
}

int
rb_set64_has(const rb_tree_t *tree, uint64_t item);

int
rb_set64_put(rb_tree_t *tree, uint64_t item);

int
rb_set64_del(rb_tree_t *tree, uint64_t item);

#define rb_set64_iterator rb_tree_iterator
#define rb_set64_each rb_tree_each

#endif /* LDB_RBT_H */
