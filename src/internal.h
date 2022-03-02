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

#if defined(__cplusplus)
#  define BTC_STDC_VERSION 0L
#  define BTC_CPP_VERSION (__cplusplus + 0L)
#elif defined(__STDC_VERSION__)
#  define BTC_STDC_VERSION __STDC_VERSION__
#  define BTC_CPP_VERSION 0L
#else
#  define BTC_STDC_VERSION 0L
#  define BTC_CPP_VERSION 0L
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
    btc__abort();               \
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

#define ASSERT_ALWAYS(expr) do {                 \
  if (UNLIKELY(!(expr)))                         \
    btc__assert_fail(__FILE__, __LINE__, #expr); \
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
#elif BTC_CPP_VERSION >= 201703L
#  define STATIC_ASSERT(expr) static_assert(expr)
#elif BTC_CPP_VERSION >= 201103L
#  define STATIC_ASSERT(expr) static_assert(expr, "check failed")
#elif BTC_GNUC_PREREQ(2, 7) || defined(__clang__) || defined(__TINYC__)
#  define STATIC_ASSERT_2(x, y) \
     typedef char btc__assert_ ## y[(x) ? 1 : -1] __attribute__((unused))
#  define STATIC_ASSERT_1(x, y) STATIC_ASSERT_2(x, y)
#  define STATIC_ASSERT(expr) STATIC_ASSERT_1(expr, __LINE__)
#else
#  define STATIC_ASSERT(expr) struct btc__assert_empty
#endif

/*
 * Keywords/Attributes
 */

#undef noreturn
#undef unused

#if BTC_STDC_VERSION >= 199901L
#  define BTC_INLINE inline
#elif BTC_CPP_VERSION >= 199711L
#  define BTC_INLINE inline
#elif BTC_GNUC_PREREQ(2, 7)
#  define BTC_INLINE __inline__
#elif defined(_MSC_VER) && _MSC_VER >= 900
#  define BTC_INLINE __inline
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x560) \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x560)
#  define BTC_INLINE inline
#else
#  define BTC_INLINE
#endif

#if BTC_STDC_VERSION >= 199901L
#  define BTC_RESTRICT restrict
#elif BTC_GNUC_PREREQ(3, 0)
#  define BTC_RESTRICT __restrict__
#elif defined(_MSC_VER) && _MSC_VER >= 1400
#  define BTC_RESTRICT __restrict
#elif defined(__SUNPRO_C) && __SUNPRO_C >= 0x530
#  define BTC_RESTRICT _Restrict
#else
#  define BTC_RESTRICT
#endif

#if BTC_STDC_VERSION >= 201112L
#  define BTC_NORETURN _Noreturn
#elif BTC_CPP_VERSION >= 201103L
#  define BTC_NORETURN [[noreturn]]
#elif BTC_GNUC_PREREQ(2, 7)
#  define BTC_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#  define BTC_NORETURN __declspec(noreturn)
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x590) \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
#  define BTC_NORETURN __attribute__((noreturn))
#else
#  define BTC_NORETURN
#endif

#if BTC_STDC_VERSION > 201710L
#  define BTC_UNUSED [[maybe_unused]]
#elif BTC_CPP_VERSION >= 201703L
#  define BTC_UNUSED [[maybe_unused]]
#elif BTC_GNUC_PREREQ(2, 7) || defined(__clang__) || defined(__TINYC__)
#  define BTC_UNUSED __attribute__((unused))
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

/*
 * Helpers
 */

#define btc_assert_fail btc__assert_fail
#define btc_abort btc__abort
#define btc_malloc btc__malloc
#define btc_realloc btc__realloc
#define btc_free btc__free

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif /* BTC_INTERNAL_H */
