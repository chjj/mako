/*!
 * atomic.h - atomics for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_ATOMICS_H
#define LDB_ATOMICS_H

#include <stddef.h>
#include <limits.h>
#include "internal.h"

/*
 * Compiler Compat
 */

/* Ignore the GCC impersonators. */
#if defined(__GNUC__) && !defined(__clang__)        \
                      && !defined(__llvm__)         \
                      && !defined(__INTEL_COMPILER) \
                      && !defined(__ICC)            \
                      && !defined(__CC_ARM)         \
                      && !defined(__TINYC__)        \
                      && !defined(__PCC__)          \
                      && !defined(__NWCC__)
#  define LDB_GNUC_REAL LDB_GNUC_PREREQ
#else
#  define LDB_GNUC_REAL(maj, min) 0
#endif

#if LDB_GNUC_REAL(4, 7)
#  define LDB_CLANG_ATOMICS
#elif LDB_GNUC_REAL(4, 6) && defined(__arm__)
#  define LDB_GNUC_ATOMICS
#elif LDB_GNUC_REAL(4, 5) && defined(__BFIN__)
#  define LDB_GNUC_ATOMICS
#elif LDB_GNUC_REAL(4, 3) && (defined(__mips__) || defined(__xtensa__))
#  define LDB_GNUC_ATOMICS
#elif LDB_GNUC_REAL(4, 2) && (defined(__sh__) || defined(__sparc__))
#  define LDB_GNUC_ATOMICS
#elif LDB_GNUC_REAL(4, 1) && (defined(__alpha__)  \
                           || defined(__i386__)   \
                           || defined(__amd64__)  \
                           || defined(__x86_64__) \
                           || defined(_IBMR2)     \
                           || defined(__s390__)   \
                           || defined(__s390x__))
#  define LDB_GNUC_ATOMICS
#elif LDB_GNUC_REAL(3, 0) && defined(__ia64__)
#  define LDB_GNUC_ATOMICS
#elif defined(__clang__) && defined(__ATOMIC_RELAXED)
#  define LDB_CLANG_ATOMICS
#elif defined(_WIN32)
#  define LDB_MSVC_ATOMICS
#endif

#if (defined(LDB_CLANG_ATOMICS) \
  || defined(LDB_GNUC_ATOMICS)  \
  || defined(LDB_MSVC_ATOMICS))
#  define LDB_HAVE_ATOMICS
#endif

/*
 * Backend Selection
 */

#if defined(LDB_MSVC_ATOMICS)
#  define ldb_atomic(type) volatile long
#  define ldb_atomic_ptr(type) void *volatile
#elif defined(LDB_HAVE_ATOMICS)
#  define ldb_atomic(type) volatile type
#  define ldb_atomic_ptr(type) type *volatile
#else /* !LDB_HAVE_ATOMICS */
#  define ldb_atomic(type) long
#  define ldb_atomic_ptr(type) void *
#endif /* !LDB_HAVE_ATOMICS */

/*
 * Memory Order
 */

#if defined(__ATOMIC_RELAXED)
#  define ldb_order_relaxed __ATOMIC_RELAXED
#else
#  define ldb_order_relaxed 0
#endif

#if defined(__ATOMIC_CONSUME)
#  define ldb_order_consume __ATOMIC_CONSUME
#else
#  define ldb_order_consume 1
#endif

#if defined(__ATOMIC_ACQUIRE)
#  define ldb_order_acquire __ATOMIC_ACQUIRE
#else
#  define ldb_order_acquire 2
#endif

#if defined(__ATOMIC_RELEASE)
#  define ldb_order_release __ATOMIC_RELEASE
#else
#  define ldb_order_release 3
#endif

#if defined(__ATOMIC_ACQ_REL)
#  define ldb_order_acq_rel __ATOMIC_ACQ_REL
#else
#  define ldb_order_acq_rel 4
#endif

#if defined(__ATOMIC_SEQ_CST)
#  define ldb_order_seq_cst __ATOMIC_SEQ_CST
#else
#  define ldb_order_seq_cst 5
#endif

/*
 * Builtins
 */

#if defined(LDB_CLANG_ATOMICS)

#define ldb_atomic_fetch_add(object, operand, order) \
  __atomic_fetch_add(object, operand, order)

#define ldb_atomic_fetch_sub(object, operand, order) \
  __atomic_fetch_sub(object, operand, order)

#define ldb_atomic_load(object, order) \
  __atomic_load_n(object, order)

#define ldb_atomic_store(object, desired, order) \
  __atomic_store_n(object, desired, order)

#define ldb_atomic_load_ptr ldb_atomic_load
#define ldb_atomic_store_ptr ldb_atomic_store

#elif defined(LDB_GNUC_ATOMICS)

#define ldb_atomic_fetch_add(object, operand, order) \
  __sync_fetch_and_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  __sync_fetch_and_sub(object, operand)

#define ldb_atomic_load(object, order) \
  (__sync_synchronize(), *(object))

#define ldb_atomic_store(object, desired, order) do { \
  *(object) = (desired);                              \
  __sync_synchronize();                               \
} while (0)

#define ldb_atomic_load_ptr ldb_atomic_load
#define ldb_atomic_store_ptr ldb_atomic_store

#elif defined(LDB_MSVC_ATOMICS)

long
ldb_atomic__fetch_add(volatile long *object, long operand);

long
ldb_atomic__load(volatile long *object);

void
ldb_atomic__store(volatile long *object, long desired);

void *
ldb_atomic__load_ptr(void *volatile *object);

void
ldb_atomic__store_ptr(void *volatile *object, void *desired);

#define ldb_atomic_fetch_add(object, operand, order) \
  ldb_atomic__fetch_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic__fetch_add(object, -(operand))

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((volatile long *)(object))

#define ldb_atomic_store(object, desired, order) \
  ldb_atomic__store(object, desired)

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void *volatile *)(object))

#define ldb_atomic_store_ptr(object, desired, order) \
  ldb_atomic__store_ptr((void *volatile *)(object), (void *)(desired))

#else /* !LDB_MSVC_ATOMICS */

long
ldb_atomic__fetch_add(long *object, long operand);

long
ldb_atomic__load(long *object);

void
ldb_atomic__store(long *object, long desired);

void *
ldb_atomic__load_ptr(void **object);

void
ldb_atomic__store_ptr(void **object, void *desired);

#define ldb_atomic_fetch_add(object, operand, order) \
  ldb_atomic__fetch_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic__fetch_add(object, -(operand))

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((long *)(object))

#define ldb_atomic_store(object, desired, order) \
  ldb_atomic__store(object, desired)

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void **)(object))

#define ldb_atomic_store_ptr(object, desired, order) \
  ldb_atomic__store_ptr((void **)(object), (void *)(desired))

#endif /* !LDB_MSVC_ATOMICS */

#endif /* LDB_ATOMICS_H */
