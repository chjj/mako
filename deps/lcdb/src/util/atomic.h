/*!
 * atomic.h - atomics for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Resources:
 *   https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
 */

#ifndef LDB_ATOMICS_H
#define LDB_ATOMICS_H

#include <stddef.h>
#include <limits.h>
#include "internal.h"

/*
 * Backend Selection
 */

#if !defined(_WIN32) && !defined(LDB_PTHREAD)
/* Skip. We're single-threaded. */
#elif defined(LDB_HAVE_STDATOMIC)
#  define LDB_STD_ATOMICS
#elif defined(__clang__)
#  ifdef __has_extension
#    if __has_extension(c_atomic) /* 3.1 */
#      define LDB_GNUC_ATOMICS
#    endif
#  endif
#elif defined(__INTEL_COMPILER) || defined(__ICC)
#  if __INTEL_COMPILER >= 1300 /* 13.0 */
#    define LDB_GNUC_ATOMICS
#  elif __INTEL_COMPILER >= 1110 /* 11.1 */
#    define LDB_SYNC_ATOMICS
#  elif __INTEL_COMPILER >= 800 /* 8.0 */
#    if defined(__ia64__)
#      define LDB_SYNC_ATOMICS
#    elif defined(__i386__) || defined(__x86_64__)
#      define LDB_ASM_ATOMICS
#    endif
#  endif
#elif defined(__CC_ARM)
#  if defined(__GNUC__) && __ARMCC_VERSION >= 410000 /* 4.1 */
#    define LDB_ARMCC_ATOMICS
#  endif
#elif defined(__TINYC__)
#  if (__TINYC__ + 0) > 927 /* 0.9.27 */
#    define LDB_TINYC_ATOMICS
#  elif defined(__i386__) || defined(__x86_64__)
#    define LDB_ASM_ATOMICS
#  endif
#elif defined(__PCC__)
#  if defined(__i386__) || defined(__x86_64__)
#    define LDB_ASM_ATOMICS
#  endif
#elif defined(__NWCC__)
/* Nothing. */
#elif defined(__GNUC__)
#  if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4) /* 4.3 */
#    if __SIZEOF_SIZE_T__ < 8 || defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)
#      if LDB_GNUC_PREREQ(4, 7)
#        define LDB_GNUC_ATOMICS
#      else
#        define LDB_SYNC_ATOMICS
#      endif
#    endif
#  elif LDB_GNUC_PREREQ(4, 2) && defined(__sparc_v9__)
#    define LDB_SYNC_ATOMICS
#  elif LDB_GNUC_PREREQ(4, 1) && (defined(__alpha__)   \
                               || defined(__x86_64__)  \
                               || defined(__powerpc__) \
                               || defined(__s390__))
#    define LDB_SYNC_ATOMICS
#  elif LDB_GNUC_PREREQ(3, 0) && defined(__ia64__)
#    define LDB_SYNC_ATOMICS
#  endif
#  if !defined(LDB_GNUC_ATOMICS) && !defined(LDB_SYNC_ATOMICS)
#    if LDB_GNUC_PREREQ(2, 8) && (defined(__i386__) || defined(__x86_64__))
#      define LDB_ASM_ATOMICS
#    endif
#  endif
#elif defined(__chibicc__)
#  define LDB_CHIBICC_ATOMICS
#elif defined(__sun) && defined(__SVR4)
#  if defined(__SUNPRO_C) && __SUNPRO_C >= 0x5110 /* 12.2 */
#    define LDB_SUN_ATOMICS
#  endif
#elif defined(_AIX) && defined(__PPC__)
#  if defined(__IBMC__) && __IBMC__ >= 800 /* 8.0 */
#    define LDB_AIX_ATOMICS
#  endif
#elif defined(__hpux) && defined(__ia64)
#  if defined(__HP_cc) && __HP_cc >= 55000 /* A.05.50 */
#    define LDB_HPUX_ATOMICS
#  endif
#endif

#if (defined(LDB_STD_ATOMICS)     \
  || defined(LDB_GNUC_ATOMICS)    \
  || defined(LDB_SYNC_ATOMICS)    \
  || defined(LDB_ASM_ATOMICS)     \
  || defined(LDB_TINYC_ATOMICS)   \
  || defined(LDB_CHIBICC_ATOMICS) \
  || defined(LDB_ARMCC_ATOMICS)   \
  || defined(LDB_SUN_ATOMICS)     \
  || defined(LDB_AIX_ATOMICS)     \
  || defined(LDB_HPUX_ATOMICS))
#  define LDB_HAVE_ATOMICS
#elif defined(_WIN32)
#  define LDB_MSVC_ATOMICS
#  define LDB_HAVE_ATOMICS
#elif defined(LDB_PTHREAD)
#  define LDB_PTHREAD_ATOMICS
#endif

/*
 * Types
 */

#if defined(_MSC_VER) && _MSC_VER >= 1400 /* VS 2005 */
#  define LDB_HAVE_INTRIN
#endif

#if defined(_WIN64) && (defined(LDB_HAVE_INTRIN) || !defined(LDB_MSVC_ATOMICS))
typedef signed __int64 ldb_word_t;
#elif defined(LDB_AIX_ATOMICS) && !defined(__64BIT__)
typedef int ldb_word_t;
#else
typedef long ldb_word_t;
#endif

#if defined(LDB_STD_ATOMICS) || defined(LDB_TINYC_ATOMICS)
#  include <stdint.h>
#  define ldb_atomic(type) _Atomic(intptr_t)
#  define ldb_atomic_ptr(type) _Atomic(type *)
#elif defined(LDB_GNUC_ATOMICS) || defined(LDB_SYNC_ATOMICS)
#  define ldb_atomic(type) volatile type
#  define ldb_atomic_ptr(type) type *volatile
#elif defined(LDB_ASM_ATOMICS)  \
   || defined(LDB_AIX_ATOMICS)  \
   || defined(LDB_MSVC_ATOMICS)
#  define ldb_atomic(type) volatile ldb_word_t
#  define ldb_atomic_ptr(type) void *volatile
#elif defined(LDB_CHIBICC_ATOMICS)
#  define ldb_atomic(type) _Atomic(long)
#  define ldb_atomic_ptr(type) _Atomic(type *)
#elif defined(LDB_ARMCC_ATOMICS)
#  include <stdint.h>
#  define ldb_atomic(type) volatile intptr_t
#  define ldb_atomic_ptr(type) void *volatile
#elif defined(LDB_SUN_ATOMICS) || defined(LDB_HPUX_ATOMICS)
#  define ldb_atomic(type) volatile long
#  define ldb_atomic_ptr(type) void *volatile
#else
#  define ldb_atomic(type) long
#  define ldb_atomic_ptr(type) void *
#endif

/*
 * Memory Order
 */

#if defined(LDB_STD_ATOMICS)
#  define ldb_order_relaxed memory_order_relaxed
#  define ldb_order_consume memory_order_consume
#  define ldb_order_acquire memory_order_acquire
#  define ldb_order_release memory_order_release
#  define ldb_order_acq_rel memory_order_acq_rel
#  define ldb_order_seq_cst memory_order_seq_cst
#elif defined(__ATOMIC_RELAXED)
#  define ldb_order_relaxed __ATOMIC_RELAXED
#  define ldb_order_consume __ATOMIC_CONSUME
#  define ldb_order_acquire __ATOMIC_ACQUIRE
#  define ldb_order_release __ATOMIC_RELEASE
#  define ldb_order_acq_rel __ATOMIC_ACQ_REL
#  define ldb_order_seq_cst __ATOMIC_SEQ_CST
#else
#  define ldb_order_relaxed 0
#  define ldb_order_consume 1
#  define ldb_order_acquire 2
#  define ldb_order_release 3
#  define ldb_order_acq_rel 4
#  define ldb_order_seq_cst 5
#endif

/*
 * Initialization
 */

#ifdef LDB_STD_ATOMICS
#  define ldb_atomic_init atomic_init
#  define ldb_atomic_init_ptr atomic_init
#else
#  define ldb_atomic_init(object, desired) \
    ldb_atomic_store(object, desired, ldb_order_relaxed)
#  define ldb_atomic_init_ptr(object, desired) \
    ldb_atomic_store_ptr(object, desired, ldb_order_relaxed)
#endif

/*
 * Builtins
 */

#if defined(LDB_STD_ATOMICS)

/*
 * Standard Atomics
 * https://en.cppreference.com/w/c/atomic
 */

#include <stdatomic.h>

#define ldb_atomic_store atomic_store_explicit
#define ldb_atomic_store_ptr atomic_store_explicit
#define ldb_atomic_load atomic_load_explicit
#define ldb_atomic_load_ptr atomic_load_explicit
#define ldb_atomic_exchange atomic_exchange

LDB_STATIC intptr_t
ldb_atomic_compare_exchange(_Atomic(intptr_t) *object,
                            intptr_t expected,
                            intptr_t desired) {
  atomic_compare_exchange_strong(object, &expected, desired);
  return expected;
}

#define ldb_atomic_fetch_add atomic_fetch_add_explicit
#define ldb_atomic_fetch_sub atomic_fetch_sub_explicit

#elif defined(LDB_GNUC_ATOMICS)

/*
 * GNU Atomics
 * https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
 */

#define ldb_atomic_store __atomic_store_n
#define ldb_atomic_store_ptr __atomic_store_n
#define ldb_atomic_load __atomic_load_n
#define ldb_atomic_load_ptr __atomic_load_n

#define ldb_atomic_exchange(object, desired) \
  __atomic_exchange_n(object, desired, 5)

#define ldb_atomic_compare_exchange(object, expected, desired)  \
__extension__ ({                                                \
  __typeof__(*(object) + 0) _exp = (expected);                  \
  __atomic_compare_exchange_n(object, &_exp, desired, 0, 5, 5); \
  _exp;                                                         \
})

#define ldb_atomic_fetch_add __atomic_fetch_add
#define ldb_atomic_fetch_sub __atomic_fetch_sub

#elif defined(LDB_SYNC_ATOMICS)

/*
 * Sync Atomics
 * https://gcc.gnu.org/onlinedocs/gcc/_005f_005fsync-Builtins.html
 */

#define ldb_compiler_barrier() __asm__ __volatile__ ("" ::: "memory")

#if defined(__i386__) || defined(__x86_64__)
#  define ldb_hardware_fence ldb_compiler_barrier
#else
#  define ldb_hardware_fence __sync_synchronize
#endif

#define ldb_atomic_store(object, desired, order) do { \
  ldb_hardware_fence();                               \
  *(object) = (desired);                              \
  ldb_compiler_barrier();                             \
} while (0)

#define ldb_atomic_store_ptr ldb_atomic_store

#define ldb_atomic_load(object, order) __extension__ ({ \
  __typeof__(*(object) + 0) _result;                    \
  ldb_compiler_barrier();                               \
  _result = *(object);                                  \
  ldb_hardware_fence();                                 \
  _result;                                              \
})

#define ldb_atomic_load_ptr(object, order) __extension__ ({ \
  __typeof__(**(object)) *_result;                          \
  ldb_compiler_barrier();                                   \
  _result = *(object);                                      \
  ldb_hardware_fence();                                     \
  _result;                                                  \
})

#if defined(__i386__) || defined(__x86_64__)
#  define ldb_atomic_exchange __sync_lock_test_and_set
#else
#  define ldb_atomic_exchange(object, desired) \
     (__sync_synchronize(), __sync_lock_test_and_set(object, desired))
#endif

#define ldb_atomic_compare_exchange __sync_val_compare_and_swap

#define ldb_atomic_fetch_add(object, operand, order) \
  __sync_fetch_and_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  __sync_fetch_and_sub(object, operand)

#elif defined(LDB_ASM_ATOMICS)

/*
 * ASM Atomics
 */

#define ldb_compiler_barrier() __asm__ __volatile__ ("" ::: "memory")

#define ldb_atomic_store(object, desired, order) do { \
  ldb_compiler_barrier();                             \
  *(object) = (desired);                              \
  ldb_compiler_barrier();                             \
} while (0)

#define ldb_atomic_store_ptr ldb_atomic_store

LDB_STATIC ldb_word_t
ldb_atomic__load(volatile ldb_word_t *object) {
  ldb_word_t result;
  ldb_compiler_barrier();
  result = *object;
  ldb_compiler_barrier();
  return result;
}

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((volatile ldb_word_t *)(object))

LDB_STATIC void *
ldb_atomic__load_ptr(void *volatile *object) {
  void *result;
  ldb_compiler_barrier();
  result = *object;
  ldb_compiler_barrier();
  return result;
}

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void *volatile *)(object))

LDB_STATIC ldb_word_t
ldb_atomic_exchange(volatile ldb_word_t *object, ldb_word_t desired) {
  __asm__ __volatile__ (
    "xchg %1, %0\n"
    : "+m" (*object),
      "+a" (desired)
    :: "memory"
  );
  return desired;
}

LDB_STATIC ldb_word_t
ldb_atomic_compare_exchange(volatile ldb_word_t *object,
                            ldb_word_t expected,
                            ldb_word_t desired) {
  __asm__ __volatile__ (
    "lock; cmpxchg %2, %0\n"
    : "+m" (*object),
      "+a" (expected)
    : "d" (desired)
    : "cc", "memory"
  );
  return expected;
}

LDB_STATIC ldb_word_t
ldb_atomic__fetch_add(volatile ldb_word_t *object, ldb_word_t operand) {
  __asm__ __volatile__ (
    "lock; xadd %1, %0\n"
    : "+m" (*object),
      "+a" (operand)
    :: "cc", "memory"
  );
  return operand;
}

#define ldb_atomic_fetch_add(object, operand, order) \
  ldb_atomic__fetch_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic__fetch_add(object, -(ldb_word_t)(operand))

#elif defined(LDB_TINYC_ATOMICS)

/*
 * Tiny Atomics
 * https://github.com/TinyCC/tinycc/blob/48df89e/include/stdatomic.h
 */

#define ldb_atomic_store __atomic_store
#define ldb_atomic_store_ptr __atomic_store
#define ldb_atomic_load __atomic_load
#define ldb_atomic_load_ptr __atomic_load

#define ldb_atomic_exchange(object, desired) \
  __atomic_exchange(object, desired, 5)

#define ldb_atomic_compare_exchange(object, expected, desired) ({ \
  intptr_t _exp = (expected);                                     \
  __atomic_compare_exchange(object, &_exp, desired, 0, 5, 5);     \
  _exp;                                                           \
})

#define ldb_atomic_fetch_add __atomic_fetch_add
#define ldb_atomic_fetch_sub __atomic_fetch_sub

#elif defined(LDB_CHIBICC_ATOMICS)

/*
 * Chibi Atomics
 * https://github.com/rui314/chibicc/blob/0a5d08c/include/stdatomic.h
 */

#define ldb_atomic_load(object, order) (*(object))
#define ldb_atomic_load_ptr ldb_atomic_load
#define ldb_atomic_store(object, desired, order) (*(object) = (desired))
#define ldb_atomic_store_ptr ldb_atomic_store
#define ldb_atomic_exchange __builtin_atomic_exchange

#define ldb_atomic_compare_exchange(object, expected, desired) ({ \
  long _exp = (expected);                                         \
  __builtin_compare_and_swap(object, &_exp, desired);             \
  _exp;                                                           \
})

#define ldb_atomic_fetch_add(object, operand, order) \
  ((*(object) += (long)(operand)) - (long)(operand))

#define ldb_atomic_fetch_sub(object, operand, order) \
  ((*(object) -= (long)(operand)) + (long)(operand))

#elif defined(LDB_ARMCC_ATOMICS)

/*
 * ARMCC Atomics
 * https://developer.arm.com/documentation/dui0491/c/Compiler-specific-Features/GNU-builtin-functions
 */

#define ldb_atomic_store(object, desired, order) do { \
  __sync_synchronize();                               \
  *(object) = (desired);                              \
  __schedule_barrier();                               \
} while (0)

#define ldb_atomic_store_ptr ldb_atomic_store

#define ldb_atomic__load(type, object) ({ \
  type _result;                           \
  __schedule_barrier();                   \
  _result = *(object);                    \
  __sync_synchronize();                   \
  _result;                                \
})

#define ldb_atomic_load(object, order) ldb_atomic__load(intptr_t, object)
#define ldb_atomic_load_ptr(object, order) ldb_atomic__load(void *, object)

#define ldb_atomic_exchange(object, desired) \
   (__sync_synchronize(), __sync_lock_test_and_set(object, desired))

#define ldb_atomic_compare_exchange __sync_val_compare_and_swap

#define ldb_atomic_fetch_add(object, operand, order) \
  __sync_fetch_and_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  __sync_fetch_and_sub(object, operand)

#elif defined(LDB_SUN_ATOMICS)

/*
 * Sun Atomics
 * https://docs.oracle.com/cd/E19253-01/816-5180/atomic-ops-9f/index.html
 * https://docs.oracle.com/cd/E18659_01/html/821-1384/gjzmf.html
 */

#include <sys/atomic.h> /* Solaris 10 (SunOS 5.10) */
#include <mbarrier.h> /* Sun Studio 12.2 */

#define ldb_compiler_barrier __compiler_barrier

#if defined(__i386) || defined(__x86_64)
#  define ldb_hardware_fence __compiler_barrier
#else
#  define ldb_hardware_fence __machine_rw_barrier
#endif

#define ldb_atomic_store(object, desired, order) do { \
  ldb_hardware_fence();                               \
  *(object) = (desired);                              \
  ldb_compiler_barrier();                             \
} while (0)

#define ldb_atomic_store_ptr ldb_atomic_store

static inline long
ldb_atomic__load(volatile long *object) {
  long result;
  ldb_compiler_barrier();
  result = *object;
  ldb_hardware_fence();
  return result;
}

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((volatile long *)(object))

static inline void *
ldb_atomic__load_ptr(void *volatile *object) {
  void *result;
  ldb_compiler_barrier();
  result = *object;
  ldb_hardware_fence();
  return result;
}

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void *volatile *)(object))

#define ldb_atomic_exchange(object, desired) \
  ((long)atomic_swap_ulong((volatile unsigned long *)(object), desired))

#define ldb_atomic_compare_exchange(object, expected, desired) \
  ((long)atomic_cas_ulong((volatile unsigned long *)(object),  \
                          expected, desired))

#define ldb_atomic_fetch_add(object, operand, order)                       \
  ((long)atomic_add_long_nv((volatile unsigned long *)(object), operand) - \
   (long)(operand))

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic_fetch_add(object, -(long)(operand), order)

#elif defined(LDB_AIX_ATOMICS)

/*
 * AIX Atomics
 * https://www.ibm.com/docs/en/xl-c-aix/13.1.3?topic=functions-synchronization-atomic-built-in
 */

#ifdef __64BIT__
#  define ldb_load_word __ldarx
#  define ldb_store_word __stdcx
#else
#  define ldb_load_word __lwarx
#  define ldb_store_word __stwcx
#endif

#define ldb_atomic_store(object, desired, order) do { \
  __lwsync();                                         \
  *(object) = (desired);                              \
  __fence();                                          \
} while (0)

#define ldb_atomic_store_ptr ldb_atomic_store

static ldb_word_t
ldb_atomic__load(volatile ldb_word_t *object) {
  ldb_word_t result;
  __fence();
  result = *object;
  __isync();
  return result;
}

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((volatile ldb_word_t *)(object))

static void *
ldb_atomic__load_ptr(void *volatile *object) {
  void *result;
  __fence();
  result = *object;
  __isync();
  return result;
}

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void *volatile *)(object))

static ldb_word_t
ldb_atomic_exchange(volatile ldb_word_t *object, ldb_word_t desired) {
  ldb_word_t old;
  __sync();
  do {
    old = ldb_load_word(object);
  } while (ldb_store_word(object, desired) == 0);
  __isync();
  return old;
}

static ldb_word_t
ldb_atomic_compare_exchange(volatile ldb_word_t *object,
                            ldb_word_t expected,
                            ldb_word_t desired) {
  ldb_word_t old;
  __sync();
  do {
    old = ldb_load_word(object);
  } while (ldb_store_word(object, old == expected ? desired : old) == 0);
  __isync();
  return old;
}

static ldb_word_t
ldb_atomic__fetch_add(volatile ldb_word_t *object, ldb_word_t operand) {
  ldb_word_t old;
  __sync();
  do {
    old = ldb_load_word(object);
  } while (ldb_store_word(object, old + operand) == 0);
  __isync();
  return old;
}

#define ldb_atomic_fetch_add(object, operand, order) \
  ldb_atomic__fetch_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic__fetch_add(object, -(ldb_word_t)(operand))

#undef ldb_load_word
#undef ldb_store_word

#elif defined(LDB_HPUX_ATOMICS)

/*
 * HP-UX Atomics
 *
 * References:
 *
 *   [ASM] Inline assembly for Itanium-based HP-UX
 *     Hewlett-Packard Company
 *     https://web.archive.org/web/20061212162944/
 *     http://h21007.www2.hp.com/dspp/files/unprotected/Itanium/inline_assem_ERS.pdf
 *
 *   [SPIN] Implementing Spinlocks on the Intel Itanium Architecture and PA-RISC
 *     T. Ekqvist, D. Graves
 *     https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.129.5445
 *
 *   [HPC] HP C/aC++ for Integrity Servers Software
 *     Hewlett Packard Enterprise Development LP
 *     https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c02888785-2
 */

#include <limits.h>
#include <machine/sys/inline.h>

#if ULONG_MAX >> 31 >> 31 >> 1 == 1
#  define LDB_SZ_W _SZ_D
#else
#  define LDB_SZ_W _SZ_W
#endif

#define LDB_ASM_FENCE ((_Asm_fence)(_UP_MEM_FENCE | _DOWN_MEM_FENCE))

#define ldb_compiler_barrier() _Asm_sched_fence(LDB_ASM_FENCE)
#define ldb_hardware_fence _Asm_mf

/* GCC generates st.rel and ld.acq instructions.
 *
 * HP C A.06.15 adds _Asm_st and _Asm_ld, but I'm
 * unable to find any documentation on them aside
 * from some very brief mentions. See [HPC].
 *
 * [SPIN] uses _Asm_st_volatile, but who knows
 * what the _Asm_ld_volatile parameters look like.
 */
#define ldb_atomic_store(object, desired, order) do { \
  ldb_hardware_fence();                               \
  *(object) = (desired);                              \
  ldb_compiler_barrier();                             \
} while (0)

#define ldb_atomic_store_ptr ldb_atomic_store

static long
ldb_atomic__load(volatile long *object) {
  long result;
  ldb_compiler_barrier();
  result = *object;
  ldb_hardware_fence();
  return result;
}

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((volatile long *)(object))

static void *
ldb_atomic__load_ptr(void *volatile *object) {
  void *result;
  ldb_compiler_barrier();
  result = *object;
  ldb_hardware_fence();
  return result;
}

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void *volatile *)(object))

#define ldb_exchange(object, desired) (         \
  _Asm_mf(), /* xchg uses acquire semantics. */ \
  (long)_Asm_xchg(LDB_SZ_W,                     \
                  (void *)(object),             \
                  (unsigned long)(desired),     \
                  _LDHINT_NONE,                 \
                  LDB_ASM_FENCE)                \
)

/* We want to mimic GCC, which generates:
 *
 *   mov ar.ccv, cmpxchg.rel, mf
 *
 * To have it as an expression, we can generate:
 *
 *   mov ar.ccv, mf, cmpxchg.acq
 */
#define ldb_atomic_compare_exchange(object, expected, desired) ( \
  _Asm_mov_to_ar(_AREG_CCV,                                      \
                 (unsigned long)(expected),                      \
                 LDB_ASM_FENCE),                                 \
  _Asm_mf(),                                                     \
  (long)_Asm_cmpxchg(LDB_SZ_W,                                   \
                     _SEM_ACQ,                                   \
                     (void *)(object),                           \
                     (unsigned long)(desired),                   \
                     _LDHINT_NONE,                               \
                     LDB_ASM_FENCE)                              \
)

/* _Asm_fetchadd exists, but only allows immediates. See [ASM]. */
static long
ldb_atomic_fetch_add(volatile long *object, long operand, int order) {
  long cur = ldb_atomic__load(object);
  long old, val;
  do {
    old = cur;
    val = old + operand;
    cur = ldb_atomic_compare_exchange(object, old, val);
  } while (cur != old);
  return old;
}

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic_fetch_add(object, -(long)(operand), order)

#elif defined(LDB_MSVC_ATOMICS)

/*
 * MSVC Atomics
 */

void
ldb_atomic__store(volatile ldb_word_t *object, ldb_word_t desired);

void
ldb_atomic__store_ptr(void *volatile *object, void *desired);

ldb_word_t
ldb_atomic__load(volatile ldb_word_t *object);

void *
ldb_atomic__load_ptr(void *volatile *object);

ldb_word_t
ldb_atomic__exchange(volatile ldb_word_t *object, ldb_word_t desired);

ldb_word_t
ldb_atomic__compare_exchange(volatile ldb_word_t *object,
                             ldb_word_t expected,
                             ldb_word_t desired);

ldb_word_t
ldb_atomic__fetch_add(volatile ldb_word_t *object, ldb_word_t operand);

#define ldb_atomic_store(object, desired, order) \
  ldb_atomic__store(object, desired)

#define ldb_atomic_store_ptr(object, desired, order) \
  ldb_atomic__store_ptr((void *volatile *)(object), (void *)(desired))

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((volatile ldb_word_t *)(object))

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void *volatile *)(object))

#define ldb_atomic_exchange ldb_atomic__exchange
#define ldb_atomic_compare_exchange ldb_atomic__compare_exchange

#define ldb_atomic_fetch_add(object, operand, order) \
  ldb_atomic__fetch_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic__fetch_add(object, -(ldb_word_t)(operand))

#elif defined(LDB_PTHREAD_ATOMICS)

/*
 * Mutex Fallback
 */

void
ldb_atomic__store(long *object, long desired);

void
ldb_atomic__store_ptr(void **object, void *desired);

long
ldb_atomic__load(long *object);

void *
ldb_atomic__load_ptr(void **object);

long
ldb_atomic__exchange(long *object, long desired);

long
ldb_atomic__compare_exchange(long *object, long expected, long desired);

long
ldb_atomic__fetch_add(long *object, long operand);

#define ldb_atomic_store(object, desired, order) \
  ldb_atomic__store(object, desired)

#define ldb_atomic_store_ptr(object, desired, order) \
  ldb_atomic__store_ptr((void **)(object), (void *)(desired))

#define ldb_atomic_load(object, order) \
  ldb_atomic__load((long *)(object))

#define ldb_atomic_load_ptr(object, order) \
  ldb_atomic__load_ptr((void **)(object))

#define ldb_atomic_exchange ldb_atomic__exchange
#define ldb_atomic_compare_exchange ldb_atomic__compare_exchange

#define ldb_atomic_fetch_add(object, operand, order) \
  ldb_atomic__fetch_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic__fetch_add(object, -(long)(operand))

#else /* !LDB_PTHREAD_ATOMICS */

/*
 * Single-Threaded Fallback
 */

#define ldb_atomic_store(object, desired, order) (*(object) = (desired))
#define ldb_atomic_store_ptr ldb_atomic_store
#define ldb_atomic_load(object, order) (*(object))
#define ldb_atomic_load_ptr ldb_atomic_load

LDB_STATIC long
ldb_atomic_exchange(long *object, long desired) {
  long result = *object;
  *object = desired;
  return result;
}

LDB_STATIC long
ldb_atomic_compare_exchange(long *object, long expected, long desired) {
  long result = *object;
  if (*object == expected)
    *object = desired;
  return result;
}

LDB_STATIC long
ldb_atomic__fetch_add(long *object, long operand) {
  long result = *object;
  *object += operand;
  return result;
}

#define ldb_atomic_fetch_add(object, operand, order) \
  ldb_atomic__fetch_add(object, operand)

#define ldb_atomic_fetch_sub(object, operand, order) \
  ldb_atomic__fetch_add(object, -(long)(operand))

#endif /* !LDB_PTHREAD_ATOMICS */

#endif /* LDB_ATOMICS_H */
