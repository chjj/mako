/*!
 * internal.h - internal utils for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_INTERNAL_H
#define LDB_INTERNAL_H

#include <stddef.h>
#include "extern.h"

/*
 * Language Standard
 */

#if defined(__cplusplus)
#  define LDB_STDC_VERSION 0L
#  define LDB_CPP_VERSION (__cplusplus + 0L)
#elif defined(__STDC_VERSION__)
#  define LDB_STDC_VERSION __STDC_VERSION__
#  define LDB_CPP_VERSION 0L
#else
#  define LDB_STDC_VERSION 0L
#  define LDB_CPP_VERSION 0L
#endif

/*
 * GNUC Compat
 */

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && !defined(__TINYC__) \
                                                 && !defined(__NWCC__)
#  define LDB_GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#  define LDB_GNUC_PREREQ(maj, min) 0
#endif

/*
 * Clang Compat
 */

#if defined(__has_builtin) && !defined(__NWCC__)
#  define LDB_HAS_BUILTIN __has_builtin
#else
#  define LDB_HAS_BUILTIN(x) 0
#endif

/*
 * Builtins
 */

#undef LIKELY
#undef UNLIKELY

#if LDB_GNUC_PREREQ(3, 0) || LDB_HAS_BUILTIN(__builtin_expect)
#  define LIKELY(x) __builtin_expect(x, 1)
#  define UNLIKELY(x) __builtin_expect(x, 0)
#else
#  define LIKELY(x) (x)
#  define UNLIKELY(x) (x)
#endif

/*
 * Static Assertions
 */

#undef STATIC_ASSERT

#if LDB_STDC_VERSION >= 201112L && !defined(__chibicc__)
#  define STATIC_ASSERT(expr) _Static_assert(expr, "check failed")
#elif LDB_CPP_VERSION >= 201703L
#  define STATIC_ASSERT(expr) static_assert(expr)
#elif LDB_CPP_VERSION >= 201103L
#  define STATIC_ASSERT(expr) static_assert(expr, "check failed")
#elif LDB_GNUC_PREREQ(2, 7) || defined(__clang__) || defined(__TINYC__)
#  define STATIC_ASSERT_2(x, y) \
     typedef char ldb__assert_ ## y[(x) ? 1 : -1] __attribute__((unused))
#  define STATIC_ASSERT_1(x, y) STATIC_ASSERT_2(x, y)
#  define STATIC_ASSERT(expr) STATIC_ASSERT_1(expr, __LINE__)
#else
#  define STATIC_ASSERT(expr) struct ldb__assert_empty
#endif

/*
 * Keywords/Attributes
 */

#undef noreturn
#undef unused

#if LDB_STDC_VERSION >= 199901L
#  define LDB_INLINE inline
#elif LDB_CPP_VERSION >= 199711L
#  define LDB_INLINE inline
#elif LDB_GNUC_PREREQ(2, 7)
#  define LDB_INLINE __inline__
#elif defined(_MSC_VER) && _MSC_VER >= 900
#  define LDB_INLINE __inline
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x560) \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x560)
#  define LDB_INLINE inline
#else
#  define LDB_INLINE
#endif

#if LDB_STDC_VERSION >= 201112L
#  define LDB_NORETURN _Noreturn
#elif LDB_CPP_VERSION >= 201103L
#  define LDB_NORETURN [[noreturn]]
#elif LDB_GNUC_PREREQ(2, 7)
#  define LDB_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#  define LDB_NORETURN __declspec(noreturn)
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x590) \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
#  define LDB_NORETURN __attribute__((noreturn))
#else
#  define LDB_NORETURN
#endif

#if LDB_STDC_VERSION > 201710L
#  define LDB_UNUSED [[maybe_unused]]
#elif LDB_CPP_VERSION >= 201703L
#  define LDB_UNUSED [[maybe_unused]]
#elif LDB_GNUC_PREREQ(2, 7) || defined(__clang__) || defined(__TINYC__)
#  define LDB_UNUSED __attribute__((unused))
#else
#  define LDB_UNUSED
#endif

#if LDB_GNUC_PREREQ(3, 0)
#  define LDB_MALLOC __attribute__((__malloc__))
#else
#  define LDB_MALLOC
#endif

#if defined(__GNUC__) && __GNUC__ >= 2
#  define LDB_EXTENSION __extension__
#else
#  define LDB_EXTENSION
#endif

#define LDB_STATIC LDB_UNUSED static LDB_INLINE

/*
 * Macros
 */

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))
#define LDB_MIN(x, y) ((x) < (y) ? (x) : (y))
#define LDB_MAX(x, y) ((x) > (y) ? (x) : (y))

/*
 * Helpers
 */

LDB_EXTERN LDB_NORETURN void
ldb_assert_fail(const char *file, int line, const char *expr);

LDB_MALLOC void *
ldb_malloc(size_t size);

LDB_MALLOC void *
ldb_realloc(void *ptr, size_t size);

LDB_EXTERN void
ldb_free(void *ptr);

#endif /* LDB_INTERNAL_H */
