/*!
 * tests.h - test utils for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/mako
 */

#ifndef BTC_TESTS_H
#define BTC_TESTS_H

#include <stddef.h>

#undef ASSERT

#define ASSERT(expr) do {                        \
  if (!(expr))                                   \
    test_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

#if defined(__cplusplus)
#  define TEST_STDC_VERSION 0L
#  define TEST_CPP_VERSION (__cplusplus + 0L)
#elif defined(__STDC_VERSION__)
#  define TEST_STDC_VERSION __STDC_VERSION__
#  define TEST_CPP_VERSION 0L
#else
#  define TEST_STDC_VERSION 0L
#  define TEST_CPP_VERSION 0L
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && !defined(__TINYC__) \
                                                 && !defined(__NWCC__)
#  define TEST_GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#  define TEST_GNUC_PREREQ(maj, min) 0
#endif

#if TEST_STDC_VERSION >= 201112L
#  define TEST_NORETURN _Noreturn
#elif TEST_CPP_VERSION >= 201103L
#  define TEST_NORETURN [[noreturn]]
#elif TEST_GNUC_PREREQ(2, 7)
#  define TEST_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#  define TEST_NORETURN __declspec(noreturn)
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x590) \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
#  define TEST_NORETURN __attribute__((noreturn))
#else
#  define TEST_NORETURN
#endif

#ifndef BTC_PREFIX
#  if defined(_WIN32)
#    define BTC_PREFIX ".\\tmp"
#  else
#    define BTC_PREFIX "./tmp"
#  endif
#endif

TEST_NORETURN void
test_assert_fail(const char *file, int line, const char *expr);

void
hex_parse(unsigned char *zp, size_t zn, const char *xp);

void
hex_decode(unsigned char *zp, size_t *zn, const char *xp);

int
btc_rimraf(const char *path);

#endif /* BTC_TESTS_H */
