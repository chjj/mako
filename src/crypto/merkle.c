/*!
 * merkle.c - merkle trees for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <mako/crypto/hash.h>
#include <mako/crypto/merkle.h>

/* Notes about unbalanced merkle trees:
 *
 * Bitcoin hashes odd nodes with themselves,
 * allowing an attacker to add a duplicate
 * TXID, creating an even number of leaves
 * and computing the same root (CVE-2012-2459).
 * In contrast, RFC 6962 simply propagates
 * odd nodes up.
 *
 * RFC 6962:
 *
 *              R
 *             / \
 *            /   \
 *           /     \
 *          /       \
 *         /         \
 *        k           j <-- same as below
 *       / \          |
 *      /   \         |
 *     /     \        |
 *    h       i       j
 *   / \     / \     / \
 *  a   b   c   d   e   f
 *
 * Bitcoin Behavior:
 *
 *              R
 *             / \
 *            /   \
 *           /     \
 *          /       \
 *         /         \
 *        k           l <-- HASH(j || j)
 *       / \          |
 *      /   \         |
 *     /     \        |
 *    h       i       j
 *   / \     / \     / \
 *  a   b   c   d   e   f
 *
 * This creates a situation where these leaves:
 *
 *        R
 *       / \
 *      /   \
 *     /     \
 *    d       e <-- HASH(c || c)
 *   / \     / \
 *  a   b   c   c
 *
 * Compute the same root as:
 *
 *       R
 *      / \
 *     /   \
 *    d     e <-- HASH(c || c)
 *   / \    |
 *  a   b   c
 *
 * Why does this matter? Duplicate TXIDs are
 * invalid right? They're spending the same
 * inputs! The problem arises in certain
 * implementation optimizations which may
 * mark a block hash invalid. In other words,
 * an invalid block shares the same block
 * hash as a valid one!
 *
 * See:
 *   https://tools.ietf.org/html/rfc6962#section-2.1
 *   https://nvd.nist.gov/vuln/detail/CVE-2012-2459
 *   https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2459
 *   https://bitcointalk.org/?topic=81749
 */

int
btc_merkle_root(uint8_t *root, uint8_t *nodes, size_t size) {
  uint8_t *left, *right, *last;
  int malleated = 0;
  size_t i;

  if (size == 0) {
    memset(root, 0, 32);
    return 1;
  }

  last = &nodes[0 * 32];

  while (size > 1) {
    for (i = 0; i < size; i += 2) {
      left = &nodes[(i + 0) * 32];
      right = left;

      if (i + 1 < size) {
        right = &nodes[(i + 1) * 32];

        if (i + 2 == size && memcmp(left, right, 32) == 0)
          malleated = 1;
      }

      last = &nodes[(i / 2) * 32];

      btc_hash256_root(last, left, right);
    }

    size = (size + 1) / 2;
  }

  memcpy(root, last, 32);

  return malleated == 0;
}
