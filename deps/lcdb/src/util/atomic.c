/*!
 * atomic.c - atomics for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include "atomic.h"

#if defined(LDB_CLANG_ATOMICS) || defined(LDB_GNUC_ATOMICS)

int
ldb_atomic_no_empty_translation_unit(void);

int
ldb_atomic_no_empty_translation_unit(void) {
  return 0;
}

#elif defined(LDB_MSVC_ATOMICS)

#include <windows.h>

long
ldb_atomic__fetch_add(volatile long *object, long operand) {
  /* Windows 98 or above. */
  return InterlockedExchangeAdd(object, operand);
}

long
ldb_atomic__load(volatile long *object) {
  /* Windows 98 or above. */
  return InterlockedCompareExchange(object, 0, 0);
}

void
ldb_atomic__store(volatile long *object, long desired) {
  /* Windows 95 or above. */
  (void)InterlockedExchange(object, desired);
}

void *
ldb_atomic__load_ptr(void *volatile *object) {
#ifdef _WIN64
  /* Windows XP or above. */
  return InterlockedCompareExchangePointer(object, NULL, NULL);
#else
  /* Windows 98 or above. */
  return InterlockedCompareExchange((volatile long *)object, 0, 0);
#endif
}

void
ldb_atomic__store_ptr(void *volatile *object, void *desired) {
#ifdef _WIN64
  /* Windows XP or above. */
  (void)InterlockedExchangePointer(object, desired);
#else
  /* Windows 98 or above. */
  (void)InterlockedExchange((volatile long *)object, desired);
#endif
}

#else /* !LDB_MSVC_ATOMICS */

#include "port.h"

static ldb_mutex_t ldb_atomic_lock = LDB_MUTEX_INITIALIZER;

long
ldb_atomic__fetch_add(long *object, long operand) {
  long result;
  ldb_mutex_lock(&ldb_atomic_lock);
  result = *object;
  *object += operand;
  ldb_mutex_unlock(&ldb_atomic_lock);
  return result;
}

long
ldb_atomic__load(long *object) {
  long result;
  ldb_mutex_lock(&ldb_atomic_lock);
  result = *object;
  ldb_mutex_unlock(&ldb_atomic_lock);
  return result;
}

void
ldb_atomic__store(long *object, long desired) {
  ldb_mutex_lock(&ldb_atomic_lock);
  *object = desired;
  ldb_mutex_unlock(&ldb_atomic_lock);
}

void *
ldb_atomic__load_ptr(void **object) {
  void *result;
  ldb_mutex_lock(&ldb_atomic_lock);
  result = *object;
  ldb_mutex_unlock(&ldb_atomic_lock);
  return result;
}

void
ldb_atomic__store_ptr(void **object, void *desired) {
  ldb_mutex_lock(&ldb_atomic_lock);
  *object = desired;
  ldb_mutex_unlock(&ldb_atomic_lock);
}

#endif /* !LDB_MSVC_ATOMICS */
