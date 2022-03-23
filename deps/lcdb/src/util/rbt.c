/*!
 * rbt.c - red-black tree for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "rbt.h"

/*
 * Constants
 */

#define BLACK RB_BLACK
#define RED RB_RED

/*
 * Globals
 */

static rb_node_t sentinel;
static rb_node_t *NIL = &sentinel;

/*
 * Node
 */

static rb_node_t *
rb_node_create(rb_val_t key, rb_val_t value) {
  rb_node_t *node = malloc(sizeof(rb_node_t));

  if (node == NULL)
    abort(); /* LCOV_EXCL_LINE */

  node->key = key;
  node->value = value;
  node->color = RED;
  node->parent = NIL;
  node->left = NIL;
  node->right = NIL;

  return node;
}

void
rb_node_destroy(rb_node_t *node) {
  if (node != NIL)
    free(node);
}

static void
rb_node_clear(rb_node_t *node, rb_clear_f *clear) {
  if (node != NIL) {
    rb_node_clear(node->left, clear);
    rb_node_clear(node->right, clear);

    if (clear != NULL)
      clear(node);

    free(node);
  }
}

static rb_node_t *
rb_node_clone(const rb_node_t *x, rb_copy_f *copy) {
  rb_node_t *z = malloc(sizeof(rb_node_t));

  if (z == NULL)
    abort(); /* LCOV_EXCL_LINE */

  *z = *x;

  if (copy != NULL)
    copy(z, x);

  return z;
}

static rb_node_t *
rb_node_snapshot(rb_node_t *parent, rb_node_t *node, rb_copy_f *copy) {
  if (node != NIL) {
    node = rb_node_clone(node, copy);
    node->parent = parent;
    node->left = rb_node_snapshot(node, node->left, copy);
    node->right = rb_node_snapshot(node, node->right, copy);
  }

  return node;
}

static rb_node_t *
rb_node_swap(rb_node_t *x, rb_node_t *y) {
  rb_val_t x_key = x->key;
  rb_val_t x_value = x->value;

  x->key = y->key;
  x->value = y->value;
  y->key = x_key;
  y->value = x_value;

  return y;
}

static rb_node_t *
rb_node_min(const rb_node_t *z) {
  if (z == NIL)
    return (rb_node_t *)z;

  while (z->left != NIL)
    z = z->left;

  return (rb_node_t *)z;
}

static rb_node_t *
rb_node_max(const rb_node_t *z) {
  if (z == NIL)
    return (rb_node_t *)z;

  while (z->right != NIL)
    z = z->right;

  return (rb_node_t *)z;
}

static rb_node_t *
rb_node_successor(const rb_node_t *x) {
  const rb_node_t *y;

  if (x->right != NIL) {
    x = x->right;

    while (x->left != NIL)
      x = x->left;

    return (rb_node_t *)x;
  }

  y = x->parent;

  while (y != NIL && x == y->right) {
    x = y;
    y = y->parent;
  }

  return (rb_node_t *)y;
}

static rb_node_t *
rb_node_predecessor(const rb_node_t *x) {
  const rb_node_t *y;

  if (x->left != NIL) {
    x = x->left;

    while (x->right != NIL)
      x = x->right;

    return (rb_node_t *)x;
  }

  y = x->parent;

  while (y != NIL && x == y->left) {
    x = y;
    y = y->parent;
  }

  return (rb_node_t *)y;
}

/*
 * Tree
 */

void
rb_tree_init(rb_tree_t *tree, rb_cmp_f *compare, void *arg, int unique) {
  tree->root = NIL;
  tree->compare = compare;
  tree->arg = arg;
  tree->unique = unique;
  tree->size = 0;
}

void
rb_tree_clear(rb_tree_t *tree, rb_clear_f *clear) {
  rb_node_clear(tree->root, clear);
  tree->root = NIL;
}

void
rb_tree_copy(rb_tree_t *z, const rb_tree_t *x, rb_copy_f *copy) {
  z->root = rb_node_snapshot(NIL, x->root, copy);
  z->compare = x->compare;
  z->arg = x->arg;
  z->unique = x->unique;
  z->size = x->size;
}

static void
rb_tree_rotl(rb_tree_t *tree, rb_node_t *x) {
  rb_node_t *y = x->right;

  x->right = y->left;

  if (y->left != NIL)
    y->left->parent = x;

  y->parent = x->parent;

  if (x->parent == NIL) {
    tree->root = y;
  } else {
    if (x == x->parent->left)
      x->parent->left = y;
    else
      x->parent->right = y;
  }

  y->left = x;
  x->parent = y;
}

static void
rb_tree_rotr(rb_tree_t *tree, rb_node_t *x) {
  rb_node_t *y = x->left;

  x->left = y->right;

  if (y->right != NIL)
    y->right->parent = x;

  y->parent = x->parent;

  if (x->parent == NIL) {
    tree->root = y;
  } else {
    if (x == x->parent->right)
      x->parent->right = y;
    else
      x->parent->left = y;
  }

  y->right = x;
  x->parent = y;
}

static void
rb_tree_insert_fixup(rb_tree_t *tree, rb_node_t *x) {
  x->color = RED;

  while (x != tree->root && x->parent->color == RED) {
    if (x->parent == x->parent->parent->left) {
      rb_node_t *y = x->parent->parent->right;

      if (y != NIL && y->color == RED) {
        x->parent->color = BLACK;
        y->color = BLACK;
        x->parent->parent->color = RED;
        x = x->parent->parent;
      } else {
        if (x == x->parent->right) {
          x = x->parent;
          rb_tree_rotl(tree, x);
        }

        x->parent->color = BLACK;
        x->parent->parent->color = RED;

        rb_tree_rotr(tree, x->parent->parent);
      }
    } else {
      rb_node_t *y = x->parent->parent->left;

      if (y != NIL && y->color == RED) {
        x->parent->color = BLACK;
        y->color = BLACK;
        x->parent->parent->color = RED;
        x = x->parent->parent;
      } else {
        if (x == x->parent->left) {
          x = x->parent;
          rb_tree_rotr(tree, x);
        }

        x->parent->color = BLACK;
        x->parent->parent->color = RED;

        rb_tree_rotl(tree, x->parent->parent);
      }
    }
  }

  tree->root->color = BLACK;
}

static void
rb_tree_remove_fixup(rb_tree_t *tree, rb_node_t *x) {
  while (x != tree->root && x->color == BLACK) {
    if (x == x->parent->left) {
      rb_node_t *w = x->parent->right;

      if (w->color == RED) {
        w->color = BLACK;
        x->parent->color = RED;
        rb_tree_rotl(tree, x->parent);
        w = x->parent->right;
      }

      if (w->left->color == BLACK && w->right->color == BLACK) {
        w->color = RED;
        x = x->parent;
      } else {
        if (w->right->color == BLACK) {
          w->left->color = BLACK;
          w->color = RED;
          rb_tree_rotr(tree, w);
          w = x->parent->right;
        }

        w->color = x->parent->color;
        x->parent->color = BLACK;
        w->right->color = BLACK;

        rb_tree_rotl(tree, x->parent);

        x = tree->root;
      }
    } else {
      rb_node_t *w = x->parent->left;

      if (w->color == RED) {
        w->color = BLACK;
        x->parent->color = RED;
        rb_tree_rotr(tree, x->parent);
        w = x->parent->left;
      }

      if (w->right->color == BLACK && w->left->color == BLACK) {
        w->color = RED;
        x = x->parent;
      } else {
        if (w->left->color == BLACK) {
          w->right->color = BLACK;
          w->color = RED;
          rb_tree_rotl(tree, w);
          w = x->parent->left;
        }

        w->color = x->parent->color;
        x->parent->color = BLACK;
        w->left->color = BLACK;

        rb_tree_rotr(tree, x->parent);

        x = tree->root;
      }
    }
  }

  x->color = BLACK;
}

static rb_node_t *
rb_tree_remove_node(rb_tree_t *tree, rb_node_t *z) {
  rb_node_t *y = z;
  rb_node_t *x;

  if (z->left != NIL && z->right != NIL)
    y = rb_node_successor(z);

  x = y->left == NIL ? y->right : y->left;

  x->parent = y->parent;

  if (y->parent == NIL) {
    tree->root = x;
  } else {
    if (y == y->parent->left)
      y->parent->left = x;
    else
      y->parent->right = x;
  }

  if (y != z) {
    /* z.(k,v) = y.(k,v) */
    z = rb_node_swap(z, y);
  }

  if (y->color == BLACK)
    rb_tree_remove_fixup(tree, x);

  tree->size -= 1;

  return z;
}

rb_node_t *
rb_tree_get(const rb_tree_t *tree, rb_val_t key) {
  const rb_node_t *current = tree->root;

  while (current != NIL) {
    int cmp = tree->compare(key, current->key, tree->arg);

    if (cmp == 0)
      return (rb_node_t *)current;

    if (cmp < 0)
      current = current->left;
    else
      current = current->right;
  }

  return NULL;
}

rb_node_t *
rb_tree_put(rb_tree_t *tree, rb_val_t key, rb_val_t value) {
  rb_node_t *current = tree->root;
  rb_node_t *parent = NULL;
  rb_node_t *node;
  int left = 0;

  while (current != NIL) {
    int cmp = tree->compare(key, current->key, tree->arg);

    if (tree->unique && cmp == 0) {
      /* Conflict. Return the node. */
      return current;
    }

    parent = current;

    if (cmp < 0) {
      current = current->left;
      left = 1;
    } else {
      current = current->right;
      left = 0;
    }
  }

  tree->size += 1;

  node = rb_node_create(key, value);

  if (!parent) {
    tree->root = node;
    rb_tree_insert_fixup(tree, node);
    return NULL;
  }

  node->parent = parent;

  if (left)
    parent->left = node;
  else
    parent->right = node;

  rb_tree_insert_fixup(tree, node);

  return NULL;
}

rb_node_t *
rb_tree_del(rb_tree_t *tree, rb_val_t key) {
  rb_node_t *current = tree->root;

  while (current != NIL) {
    int cmp = tree->compare(key, current->key, tree->arg);

    if (cmp == 0)
      return rb_tree_remove_node(tree, current);

    if (cmp < 0)
      current = current->left;
    else
      current = current->right;
  }

  return NULL;
}

rb_iter_t
rb_tree_iterator(const rb_tree_t *tree) {
  rb_iter_t iter;
  rb_iter_init(&iter, tree);
  return iter;
}

/*
 * Iterator
 */

void
rb_iter_init(rb_iter_t *iter, const rb_tree_t *tree) {
  iter->tree = tree;
  iter->root = tree->root;
  iter->node = NIL;
}

int
rb_iter_compare(const rb_iter_t *iter, rb_val_t key) {
  return iter->tree->compare(iter->node->key, key, iter->tree->arg);
}

int
rb_iter_valid(const rb_iter_t *iter) {
  return iter->node != NIL;
}

void
rb_iter_reset(rb_iter_t *iter) {
  iter->node = iter->root;
}

void
rb_iter_seek_first(rb_iter_t *iter) {
  iter->node = rb_node_min(iter->root);
}

void
rb_iter_seek_last(rb_iter_t *iter) {
  iter->node = rb_node_max(iter->root);
}

void
rb_iter_seek(rb_iter_t *iter, rb_val_t key) {
  const rb_node_t *current = iter->root;
  const rb_node_t *result = NIL;

  while (current != NIL) {
    int cmp = iter->tree->compare(key, current->key, iter->tree->arg);

    if (cmp == 0) {
      result = current;
      break;
    }

    if (cmp < 0) {
      result = current;
      current = current->left;
    } else {
      current = current->right;
    }
  }

  iter->node = result;
}

int
rb_iter_prev(rb_iter_t *iter) {
  if (iter->node == NIL)
    return 0;

  iter->node = rb_node_predecessor(iter->node);

  return 1;
}

int
rb_iter_next(rb_iter_t *iter) {
  if (iter->node == NIL)
    return 0;

  iter->node = rb_node_successor(iter->node);

  return 1;
}

int
rb_iter_start(rb_iter_t *iter, const rb_tree_t *tree) {
  rb_iter_init(iter, tree);
  rb_iter_seek_first(iter);
  return 0;
}

int
rb_iter_kv(const rb_iter_t *iter, rb_val_t *key, rb_val_t *value) {
  if (iter->node == NIL)
    return 0;

  *key = iter->node->key;
  *value = iter->node->value;

  return 1;
}

int
rb_iter_k(const rb_iter_t *iter, rb_val_t *key) {
  if (iter->node == NIL)
    return 0;

  *key = iter->node->key;

  return 1;
}

int
rb_iter_v(const rb_iter_t *iter, rb_val_t *value) {
  if (iter->node == NIL)
    return 0;

  *value = iter->node->value;

  return 1;
}

/*
 * Map
 */

void *
rb_map_get(const rb_tree_t *tree, const void *key) {
  const rb_node_t *node;
  rb_val_t k;

  k.p = (void *)key;

  node = rb_tree_get(tree, k);

  if (node == NULL)
    return NULL;

  return node->value.p;
}

int
rb_map_has(const rb_tree_t *tree, const void *key) {
  rb_val_t k;

  k.p = (void *)key;

  return rb_tree_get(tree, k) != NULL;
}

int
rb_map_put(rb_tree_t *tree, const void *key, const void *value) {
  rb_val_t k, v;

  k.p = (void *)key;
  v.p = (void *)value;

  return rb_tree_put(tree, k, v) == NULL;
}

rb_node_t *
rb_map_del(rb_tree_t *tree, const void *key) {
  rb_val_t k;

  k.p = (void *)key;

  return rb_tree_del(tree, k);
}

int
rb_map_kv(const rb_iter_t *iter, void **key, void **value) {
  if (iter->node == NIL)
    return 0;

  *key = iter->node->key.p;
  *value = iter->node->value.p;

  return 1;
}

int
rb_map_k(const rb_iter_t *iter, void **key) {
  if (iter->node == NIL)
    return 0;

  *key = iter->node->key.p;

  return 1;
}

int
rb_map_v(const rb_iter_t *iter, void **value) {
  if (iter->node == NIL)
    return 0;

  *value = iter->node->value.p;

  return 1;
}

/*
 * Set
 */

int
rb_set_has(const rb_tree_t *tree, const void *item) {
  rb_val_t key;

  key.p = (void *)item;

  return rb_tree_get(tree, key) != NULL;
}

int
rb_set_put(rb_tree_t *tree, const void *item) {
  rb_val_t key, val;

  key.p = (void *)item;
  val.p = NULL;

  return rb_tree_put(tree, key, val) == NULL;
}

void *
rb_set_del(rb_tree_t *tree, const void *item) {
  rb_node_t *node;
  rb_val_t key;

  key.p = (void *)item;

  node = rb_tree_del(tree, key);

  if (node != NULL) {
    void *old = node->key.p;
    rb_node_destroy(node);
    return old;
  }

  return NULL;
}

int
rb_set_k(const rb_iter_t *iter, void **key) {
  if (iter->node == NIL)
    return 0;

  *key = iter->node->key.p;

  return 1;
}

/*
 * Set64
 */

int
rb_set64_compare(rb_val_t x, rb_val_t y, void *arg) {
  (void)arg;

  if (x.ui == y.ui)
    return 0;

  return x.ui < y.ui ? -1 : 1;
}

int
rb_set64_has(const rb_tree_t *tree, uint64_t item) {
  rb_val_t key;

  key.ui = item;

  return rb_tree_get(tree, key) != NULL;
}

int
rb_set64_put(rb_tree_t *tree, uint64_t item) {
  rb_val_t key, val;

  key.ui = item;
  val.ui = 0;

  return rb_tree_put(tree, key, val) == NULL;
}

int
rb_set64_del(rb_tree_t *tree, uint64_t item) {
  rb_node_t *node;
  rb_val_t key;

  key.ui = item;

  node = rb_tree_del(tree, key);

  if (node != NULL) {
    rb_node_destroy(node);
    return 1;
  }

  return 0;
}

int
rb_set64_k(const rb_iter_t *iter, uint64_t *key) {
  if (iter->node == NIL)
    return 0;

  *key = iter->node->key.ui;

  return 1;
}
