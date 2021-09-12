/*!
 * internal.h - internal utils for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_INTERNAL_H
#define BTC_INTERNAL_H

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

#if BTC_GNUC_PREREQ(3, 0) || BTC_HAS_BUILTIN(__builtin_expect)
#  define LIKELY(x) __builtin_expect(x, 1)
#  define UNLIKELY(x) __builtin_expect(x, 0)
#else
#  define LIKELY(x) (x)
#  define UNLIKELY(x) (x)
#endif

/*
 * Sanity Checks
 */

#undef CHECK_ALWAYS
#undef CHECK_NEVER
#undef CHECK

#define CHECK_ALWAYS(expr) do { \
  if (UNLIKELY(!(expr)))        \
    btc__abort();           \
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
#elif BTC_GNUC_PREREQ(2, 7) || defined(__clang__)
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
#elif BTC_GNUC_PREREQ(2, 7) || defined(__clang__)
#  define BTC_UNUSED __attribute__((unused))
#else
#  define BTC_UNUSED
#endif

/*
 * Helpers
 */

#define btc_abort btc__abort

BTC_NORETURN void
btc__assert_fail(const char *file, int line, const char *expr);

BTC_NORETURN void
btc__abort(void);

#endif /* BTC_INTERNAL_H */
