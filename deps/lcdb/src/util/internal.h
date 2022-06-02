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

#ifdef __STDC_VERSION__
#  define LDB_STDC_VERSION __STDC_VERSION__
#else
#  define LDB_STDC_VERSION 0L
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
#elif LDB_GNUC_PREREQ(2, 7) || defined(__clang__)
#  define STATIC_ASSERT_2(x, y) \
     typedef char ldb_assert_ ## y[(x) ? 1 : -1] __attribute__((__unused__))
#  define STATIC_ASSERT_1(x, y) STATIC_ASSERT_2(x, y)
#  define STATIC_ASSERT(expr) STATIC_ASSERT_1(expr, __LINE__)
#else
#  define STATIC_ASSERT(expr) struct ldb_assert_empty
#endif

/*
 * Keywords/Attributes
 */

#if LDB_STDC_VERSION >= 199901L
#  define LDB_INLINE inline
#elif LDB_GNUC_PREREQ(2, 7)
#  define LDB_INLINE __inline__
#elif defined(_MSC_VER) && _MSC_VER >= 900
#  define LDB_INLINE __inline
#else
#  define LDB_INLINE
#endif

#if LDB_STDC_VERSION >= 201112L
#  define LDB_NORETURN _Noreturn
#elif LDB_GNUC_PREREQ(2, 7)
#  define LDB_NORETURN __attribute__((__noreturn__))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#  define LDB_NORETURN __declspec(noreturn)
#else
#  define LDB_NORETURN
#endif

#if LDB_STDC_VERSION > 201710L
#  define LDB_UNUSED [[maybe_unused]]
#elif LDB_GNUC_PREREQ(2, 7) || defined(__clang__)
#  define LDB_UNUSED __attribute__((__unused__))
#else
#  define LDB_UNUSED
#endif

#if LDB_GNUC_PREREQ(3, 0)
#  define LDB_MALLOC __attribute__((__malloc__))
#else
#  define LDB_MALLOC
#endif

#define LDB_STATIC LDB_UNUSED static LDB_INLINE

/*
 * Macros
 */

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))
#define LDB_MIN(x, y) ((x) < (y) ? (x) : (y))
#define LDB_MAX(x, y) ((x) > (y) ? (x) : (y))
#define LDB_CMP(x, y) (((x) > (y)) - ((x) < (y)))

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
