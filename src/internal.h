/*!
 * internal.h - internal utils for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_INTERNAL_H
#define BTC_INTERNAL_H

#include <stddef.h>
#include <mako/common.h>

/*
 * Language Standard
 */

#ifdef __STDC_VERSION__
#  define BTC_STDC_VERSION __STDC_VERSION__
#else
#  define BTC_STDC_VERSION 0L
#endif

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
#  define BTC_GNUC
#endif

/* Ignore the MSVC impersonators. */
#if defined(_MSC_VER) && !defined(__clang__)        \
                      && !defined(__llvm__)         \
                      && !defined(__INTEL_COMPILER) \
                      && !defined(__ICL)
#  define BTC_MSVC
#endif

/*
 * GNUC Compat
 */

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && !defined(__TINYC__) \
                                                 && !defined(__NWCC__)
#  define BTC_GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#  define BTC_GNUC_PREREQ(maj, min) 0
#endif

/*
 * Clang Compat
 */

#if defined(__has_builtin) && !defined(__NWCC__)
#  define BTC_HAS_BUILTIN __has_builtin
#else
#  define BTC_HAS_BUILTIN(x) 0
#endif

/*
 * Builtins
 */

#undef LIKELY
#undef UNLIKELY
#undef UNPREDICTABLE

#if BTC_GNUC_PREREQ(3, 0) || BTC_HAS_BUILTIN(__builtin_expect)
#  define LIKELY(x) __builtin_expect(x, 1)
#  define UNLIKELY(x) __builtin_expect(x, 0)
#else
#  define LIKELY(x) (x)
#  define UNLIKELY(x) (x)
#endif

#if BTC_HAS_BUILTIN(__builtin_unpredictable)
#  define UNPREDICTABLE __builtin_unpredictable
#else
#  define UNPREDICTABLE(x) (x)
#endif

/*
 * Sanity Checks
 */

#undef CHECK_ALWAYS
#undef CHECK_NEVER
#undef CHECK

#define CHECK_ALWAYS(expr) do { \
  if (UNLIKELY(!(expr)))        \
    btc_abort();                \
} while (0)

#define CHECK_NEVER(expr) do { \
  (void)(expr);                \
} while (0)

#if !defined(BTC_COVERAGE)
#  define CHECK CHECK_ALWAYS
#else
#  define CHECK CHECK_NEVER
#endif

/*
 * Assertions
 */

#undef ASSERT_ALWAYS
#undef ASSERT_NEVER
#undef ASSERT

#define ASSERT_ALWAYS(expr) do {                \
  if (UNLIKELY(!(expr)))                        \
    btc_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

#define ASSERT_NEVER(expr) do { \
  (void)(expr);                 \
} while (0)

#if defined(BTC_DEBUG) && !defined(BTC_COVERAGE)
#  define ASSERT ASSERT_ALWAYS
#else
#  define ASSERT ASSERT_NEVER
#endif

/*
 * Static Assertions
 */

#undef STATIC_ASSERT

#if BTC_STDC_VERSION >= 201112L && !defined(__chibicc__)
#  define STATIC_ASSERT(expr) _Static_assert(expr, "check failed")
#elif BTC_GNUC_PREREQ(2, 7) || defined(__clang__)
#  define STATIC_ASSERT_2(x, y) \
     typedef char btc_assert_ ## y[(x) ? 1 : -1] __attribute__((__unused__))
#  define STATIC_ASSERT_1(x, y) STATIC_ASSERT_2(x, y)
#  define STATIC_ASSERT(expr) STATIC_ASSERT_1(expr, __LINE__)
#else
#  define STATIC_ASSERT(expr) struct btc_assert_empty
#endif

/*
 * Keywords/Attributes
 */

#if BTC_STDC_VERSION >= 199901L
#  define BTC_INLINE inline
#elif BTC_GNUC_PREREQ(2, 7)
#  define BTC_INLINE __inline__
#elif defined(_MSC_VER) && _MSC_VER >= 900
#  define BTC_INLINE __inline
#else
#  define BTC_INLINE
#endif

#if BTC_STDC_VERSION >= 201112L
#  define BTC_NORETURN _Noreturn
#elif BTC_GNUC_PREREQ(2, 7)
#  define BTC_NORETURN __attribute__((__noreturn__))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#  define BTC_NORETURN __declspec(noreturn)
#else
#  define BTC_NORETURN
#endif

#if BTC_STDC_VERSION > 201710L
#  define BTC_UNUSED [[maybe_unused]]
#elif BTC_GNUC_PREREQ(2, 7) || defined(__clang__)
#  define BTC_UNUSED __attribute__((__unused__))
#else
#  define BTC_UNUSED
#endif

#if BTC_GNUC_PREREQ(3, 0)
#  define BTC_MALLOC __attribute__((__malloc__))
#else
#  define BTC_MALLOC
#endif

#if defined(__GNUC__) && __GNUC__ >= 2
#  define BTC_EXTENSION __extension__
#else
#  define BTC_EXTENSION
#endif

/*
 * Types
 */

#ifdef BTC_HAVE_INT128
BTC_EXTENSION typedef unsigned __int128 btc_uint128_t;
BTC_EXTENSION typedef signed __int128 btc_int128_t;
#endif

/*
 * Value Barrier
 */

#if defined(BTC_HAVE_ASM)
#define BTC_BARRIER(type, prefix) \
static BTC_INLINE type            \
prefix ## _barrier(type x) {      \
  __asm__ ("" : "+r" (x));        \
  return x;                       \
}
#else
#define BTC_BARRIER(type, prefix) \
static BTC_INLINE type            \
prefix ## _barrier(type x) {      \
  return x;                       \
}
#endif

/*
 * Sanity Checks
 */

#if (-1 & 3) != 3
#  error "Two's complement is required."
#endif

/*
 * Macros
 */

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))
#define BTC_MIN(x, y) ((x) < (y) ? (x) : (y))
#define BTC_MAX(x, y) ((x) > (y) ? (x) : (y))
#define BTC_ABS(x) ((x) < 0 ? -(x) : (x))
#define BTC_CMP(x, y) (((x) > (y)) - ((x) < (y)))

/*
 * Helpers
 */

BTC_EXTERN BTC_NORETURN void
btc_assert_fail(const char *file, int line, const char *expr);

BTC_EXTERN BTC_NORETURN void
btc_abort(void);

BTC_EXTERN BTC_MALLOC void *
btc_malloc(size_t size);

BTC_EXTERN BTC_MALLOC void *
btc_realloc(void *ptr, size_t size);

BTC_EXTERN void
btc_free(void *ptr);

#endif /* BTC_INTERNAL_H */
