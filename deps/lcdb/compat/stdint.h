/*!
 * compat/stdint.h - <stdint.h> shim for c89
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://gist.github.com/chjj/f61887c598fd5b82fb4a7d8f55637a77
 */

/* Platform assumptions:
 *
 *  - Must be a 32 or 64 bit system with CHAR_BIT==8.
 *  - Must be ILP32, LP64, or LLP64 (the latter being windows only).
 *  - All pointers must be the same width (no near/far 16 bit nonsense).
 *  - size_t and ptrdiff_t must be exactly the width of a pointer.
 *  - The compiler must support a 64 bit integer type.
 *
 * Most platforms we want to support fulfill these requirements.
 *
 * Note that we do not define {WCHAR,WINT,SIG_ATOMIC}_{MIN,MAX}.
 */

#ifndef COMPAT_STDINT_H
#define COMPAT_STDINT_H

#include <limits.h>
#include <stddef.h>

/*
 * 64-bit Integers
 */

#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__WATCOMC__)
typedef signed __int64 int64_t;
typedef unsigned __int64 uint64_t;
#  define INT64_MIN _I64_MIN
#  define INT64_MAX _I64_MAX
#  define UINT64_MAX _UI64_MAX
#  define INT64_C(x) x ## i64
#  define UINT64_C(x) x ## ui64
#elif ULONG_MAX >> 31 >> 31 >> 1 == 1
typedef signed long int64_t;
typedef unsigned long uint64_t;
#  define INT64_MIN LONG_MIN
#  define INT64_MAX LONG_MAX
#  define UINT64_MAX ULONG_MAX
#  define INT64_C(x) x ## L
#  define UINT64_C(x) x ## UL
#else
#  if defined(__GNUC__) && __GNUC__ >= 2
__extension__ typedef signed long long int64_t;
__extension__ typedef unsigned long long uint64_t;
#  else
typedef signed long long int64_t;
typedef unsigned long long uint64_t;
#  endif
#  define INT64_MIN (-INT64_MAX - 1)
#  define INT64_MAX INT64_C(9223372036854775807)
#  define UINT64_MAX UINT64_C(18446744073709551615)
#  define INT64_C(x) x ## LL
#  define UINT64_C(x) x ## ULL
#endif

/*
 * Pointer Integers
 */

#ifdef _WIN64
/* Windows 64-bit is LLP64. */
typedef int64_t intptr_t;
typedef uint64_t uintptr_t;
#  define INTPTR_MIN INT64_MIN
#  define INTPTR_MAX INT64_MAX
#  define UINTPTR_MAX UINT64_MAX
#else
/* Assume only ILP32 or LP64. */
typedef signed long intptr_t;
typedef unsigned long uintptr_t;
#  define INTPTR_MIN LONG_MIN
#  define INTPTR_MAX LONG_MAX
#  define UINTPTR_MAX ULONG_MAX
#endif

/*
 * Integers
 */

typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

typedef signed char int_least8_t;
typedef signed short int_least16_t;
typedef signed int int_least32_t;
typedef int64_t int_least64_t;
typedef unsigned char uint_least8_t;
typedef unsigned short uint_least16_t;
typedef unsigned int uint_least32_t;
typedef uint64_t uint_least64_t;

typedef int8_t int_fast8_t;
typedef intptr_t int_fast16_t;
typedef intptr_t int_fast32_t;
typedef int64_t int_fast64_t;
typedef uint8_t uint_fast8_t;
typedef uintptr_t uint_fast16_t;
typedef uintptr_t uint_fast32_t;
typedef uint64_t uint_fast64_t;

typedef int64_t intmax_t;
typedef uint64_t uintmax_t;

/*
 * Limits
 */

#define INT8_MIN SCHAR_MIN
#define INT16_MIN SHRT_MIN
#define INT32_MIN INT_MIN
#define INT8_MAX SCHAR_MAX
#define INT16_MAX SHRT_MAX
#define INT32_MAX INT_MAX
#define UINT8_MAX UCHAR_MAX
#define UINT16_MAX USHRT_MAX
#define UINT32_MAX UINT_MAX

#define INT_LEAST8_MIN SCHAR_MIN
#define INT_LEAST16_MIN SHRT_MIN
#define INT_LEAST32_MIN INT_MIN
#define INT_LEAST64_MIN INT64_MIN
#define INT_LEAST8_MAX SCHAR_MAX
#define INT_LEAST16_MAX SHRT_MAX
#define INT_LEAST32_MAX INT_MAX
#define INT_LEAST64_MAX INT64_MAX
#define UINT_LEAST8_MAX UCHAR_MAX
#define UINT_LEAST16_MAX USHRT_MAX
#define UINT_LEAST32_MAX UINT_MAX
#define UINT_LEAST64_MAX UINT64_MAX

#define INT_FAST8_MIN INT8_MIN
#define INT_FAST16_MIN INTPTR_MIN
#define INT_FAST32_MIN INTPTR_MIN
#define INT_FAST64_MIN INT64_MIN
#define INT_FAST8_MAX INT8_MAX
#define INT_FAST16_MAX INTPTR_MAX
#define INT_FAST32_MAX INTPTR_MAX
#define INT_FAST64_MAX INT64_MAX
#define UINT_FAST8_MAX UINT8_MAX
#define UINT_FAST16_MAX UINTPTR_MAX
#define UINT_FAST32_MAX UINTPTR_MAX
#define UINT_FAST64_MAX UINT64_MAX

#define INTMAX_MIN INT64_MIN
#define INTMAX_MAX INT64_MAX
#define UINTMAX_MAX UINT64_MAX

#ifndef PTRDIFF_MIN
#  define PTRDIFF_MIN INTPTR_MIN
#  define PTRDIFF_MAX INTPTR_MAX
#endif

#ifndef SIZE_MAX
#  define SIZE_MAX UINTPTR_MAX
#endif

/*
 * Macros
 */

#define INT8_C(x) x
#define INT16_C(x) x
#define INT32_C(x) x

#define UINT8_C(x) x
#define UINT16_C(x) x
#define UINT32_C(x) x ## U

#define INTMAX_C INT64_C
#define UINTMAX_C UINT64_C

/*
 * Sanity Check
 */

typedef char compat_integer_sanity_check
  [sizeof(int8_t) == 1 && sizeof(uint8_t) == 1 &&
   sizeof(int16_t) == 2 && sizeof(uint16_t) == 2 &&
   sizeof(int32_t) == 4 && sizeof(uint32_t) == 4 &&
   sizeof(int64_t) == 8 && sizeof(uint64_t) == 8 &&
   sizeof(intptr_t) == sizeof(void *) &&
   sizeof(uintptr_t) == sizeof(void *) &&
   sizeof(ptrdiff_t) == sizeof(void *) &&
   sizeof(size_t) == sizeof(void *) &&
   sizeof(void *) >= 4 && CHAR_BIT == 8 ? 1 : -1]
#if defined(__cplusplus) && (__cplusplus + 0L) >= 201703L
  [[maybe_unused]]
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202300L
  [[maybe_unused]]
#elif defined(__TINYC__) || defined(__NWCC__)
/* Nothing. */
#elif (defined(__GNUC__) && __GNUC__ >= 3) || defined(__clang__)
  __attribute__((__unused__))
#endif
  ;

#endif /* COMPAT_STDINT_H */
