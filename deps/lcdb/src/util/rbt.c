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
 * Macros
 */

#define ROOT(x) ((x)->root != NULL ? (x)->root : NIL)

/*
 * Globals
 */

static rb_node_t sentinel;
static rb_node_t *NIL = &sentinel;

/*
 * Node
 */

static rb_node_t *
rb_node_create(rb_val_t key) {
  rb_node_t *node = malloc(sizeof(rb_node_t));

  if (node == NULL)
    abort(); /* LCOV_EXCL_LINE */

  node->key = key;
  node->color = RED;
  node->parent = NIL;
  node->left = NIL;
  node->right = NIL;

#ifdef __chibicc__
  node->val.ui = 0;
#else
  memset(&node->val, 0, sizeof(node->val));
#endif

  return node;
}

static void
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
#ifdef __chibicc__
  uint64_t x_key = x->key.ui;
  uint64_t x_val = x->val.ui;

  x->key.ui = y->key.ui;
  x->val.ui = y->val.ui;
  y->key.ui = x_key;
  y->val.ui = x_val;
#else
  rb_val_t x_key = x->key;
  rb_val_t x_val = x->val;

  x->key = y->key;
  x->val = y->val;
  y->key = x_key;
  y->val = x_val;
#endif

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
rb_tree_init(rb_tree_t *tree, rb_cmp_f *compare, void *arg) {
  tree->root = NIL;
  tree->compare = compare;
  tree->arg = arg;
  tree->size = 0;
}

void
rb_tree_clear(rb_tree_t *tree, rb_clear_f *clear) {
  rb_node_clear(ROOT(tree), clear);
  tree->root = NIL;
  tree->size = 0;
}

void
rb_tree_copy(rb_tree_t *z, const rb_tree_t *x, rb_copy_f *copy) {
  z->root = rb_node_snapshot(NIL, ROOT(x), copy);
  z->compare = x->compare;
  z->arg = x->arg;
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
  rb_node_t *current = ROOT(tree);

  while (current != NIL) {
    int cmp = tree->compare(key, current->key, tree->arg);

    if (cmp == 0)
      return current;

    if (cmp < 0)
      current = current->left;
    else
      current = current->right;
  }

  return NULL;
}

int
rb_tree_put(rb_tree_t *tree, rb_val_t key, rb_node_t **result) {
  rb_node_t *current = ROOT(tree);
  rb_node_t *parent = NULL;
  rb_node_t *node;
  int left = 0;

  while (current != NIL) {
    int cmp = tree->compare(key, current->key, tree->arg);

    if (cmp == 0) {
      if (result != NULL)
        *result = current;
      return 0;
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

  node = rb_node_create(key);

  if (parent == NULL) {
    tree->root = node;
  } else {
    node->parent = parent;

    if (left)
      parent->left = node;
    else
      parent->right = node;
  }

  rb_tree_insert_fixup(tree, node);

  tree->size += 1;

  if (result != NULL)
    *result = node;

  return 1;
}

int
rb_tree_del(rb_tree_t *tree, rb_val_t key, rb_node_t *result) {
  rb_node_t *current = ROOT(tree);

  while (current != NIL) {
    int cmp = tree->compare(key, current->key, tree->arg);

    if (cmp == 0) {
      current = rb_tree_remove_node(tree, current);

      if (result != NULL) {
#ifdef __chibicc__
        result->key.ui = current->key.ui;
        result->val.ui = current->val.ui;
#else
        result->key = current->key;
        result->val = current->val;
#endif
      }

      rb_node_destroy(current);

      return 1;
    }

    if (cmp < 0)
      current = current->left;
    else
      current = current->right;
  }

  return 0;
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
  iter->root = ROOT(tree);
  iter->node = NIL;
}

int
rb_iter_valid(const rb_iter_t *iter) {
  return iter->node != NIL;
}

void
rb_iter_first(rb_iter_t *iter) {
  iter->node = rb_node_min(iter->root);
}

void
rb_iter_last(rb_iter_t *iter) {
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

void
rb_iter_prev(rb_iter_t *iter) {
  iter->node = rb_node_predecessor(iter->node);
}

void
rb_iter_next(rb_iter_t *iter) {
  iter->node = rb_node_successor(iter->node);
}

void
rb_iter_start(rb_iter_t *iter, const rb_tree_t *tree) {
  rb_iter_init(iter, tree);
  rb_iter_first(iter);
}

/*
 * Map
 */

void *
rb_map_get(const rb_tree_t *tree, const void *key) {
  const rb_node_t *node = rb_tree_get(tree, rb_ptr(key));

  if (node == NULL)
    return NULL;

  return node->val.ptr;
}

int
rb_map_has(const rb_tree_t *tree, const void *key) {
  return rb_tree_get(tree, rb_ptr(key)) != NULL;
}

int
rb_map_put(rb_tree_t *tree, const void *key, const void *val) {
  rb_node_t *node;

  if (rb_tree_put(tree, rb_ptr(key), &node)) {
    node->val = rb_ptr(val);
    return 1;
  }

  return 0;
}

int
rb_map_del(rb_tree_t *tree, const void *key, rb_entry_t *result) {
  rb_node_t node;

  if (rb_tree_del(tree, rb_ptr(key), &node)) {
    if (result != NULL) {
      result->key = node.key.ptr;
      result->val = node.val.ptr;
    }
    return 1;
  }

  return 0;
}

/*
 * Set
 */

int
rb_set_has(const rb_tree_t *tree, const void *item) {
  return rb_tree_get(tree, rb_ptr(item)) != NULL;
}

int
rb_set_put(rb_tree_t *tree, const void *item) {
  return rb_tree_put(tree, rb_ptr(item), NULL);
}

void *
rb_set_del(rb_tree_t *tree, const void *item) {
  rb_node_t node;

  if (rb_tree_del(tree, rb_ptr(item), &node))
    return node.key.ptr;

  return NULL;
}

/*
 * Set64
 */

int
rb_set64_has(const rb_tree_t *tree, uint64_t item) {
  return rb_tree_get(tree, rb_ui(item)) != NULL;
}

int
rb_set64_put(rb_tree_t *tree, uint64_t item) {
  return rb_tree_put(tree, rb_ui(item), NULL);
}

int
rb_set64_del(rb_tree_t *tree, uint64_t item) {
  return rb_tree_del(tree, rb_ui(item), NULL);
}
