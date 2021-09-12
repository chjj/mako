/*!
 * internal.h - internal utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_INTERNAL_H
#define TORSION_INTERNAL_H

/*
 * Language Standard
 */

#if defined(__cplusplus)
#  define TORSION_STDC_VERSION 0L
#  define TORSION_CPP_VERSION (__cplusplus + 0L)
#elif defined(__STDC_VERSION__)
#  define TORSION_STDC_VERSION __STDC_VERSION__
#  define TORSION_CPP_VERSION 0L
#else
#  define TORSION_STDC_VERSION 0L
#  define TORSION_CPP_VERSION 0L
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
#  define TORSION_GNUC
#endif

/* Ignore the MSVC impersonators. */
#if defined(_MSC_VER) && !defined(__clang__)        \
                      && !defined(__llvm__)         \
                      && !defined(__INTEL_COMPILER) \
                      && !defined(__ICL)
#  define TORSION_MSVC
#endif

/*
 * GNUC Compat
 */

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && !defined(__TINYC__) \
                                                 && !defined(__NWCC__)
#  define TORSION_GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#  define TORSION_GNUC_PREREQ(maj, min) 0
#endif

/*
 * Clang Compat
 */

#if defined(__has_builtin) && !defined(__NWCC__)
#  define TORSION_HAS_BUILTIN __has_builtin
#else
#  define TORSION_HAS_BUILTIN(x) 0
#endif

/*
 * Builtins
 */

#undef LIKELY
#undef UNLIKELY
#undef UNPREDICTABLE

#if TORSION_GNUC_PREREQ(3, 0) || TORSION_HAS_BUILTIN(__builtin_expect)
#  define LIKELY(x) __builtin_expect(x, 1)
#  define UNLIKELY(x) __builtin_expect(x, 0)
#else
#  define LIKELY(x) (x)
#  define UNLIKELY(x) (x)
#endif

#if TORSION_HAS_BUILTIN(__builtin_unpredictable)
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
    torsion__abort();           \
} while (0)

#define CHECK_NEVER(expr) do { \
  (void)(expr);                \
} while (0)

#if !defined(TORSION_COVERAGE)
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

#define ASSERT_ALWAYS(expr) do {                     \
  if (UNLIKELY(!(expr)))                             \
    torsion__assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

#define ASSERT_NEVER(expr) do { \
  (void)(expr);                 \
} while (0)

#if defined(TORSION_DEBUG) && !defined(TORSION_COVERAGE)
#  define ASSERT ASSERT_ALWAYS
#else
#  define ASSERT ASSERT_NEVER
#endif

/*
 * Static Assertions
 */

#undef STATIC_ASSERT

#if TORSION_STDC_VERSION >= 201112L && !defined(__chibicc__)
#  define STATIC_ASSERT(expr) _Static_assert(expr, "check failed")
#elif TORSION_CPP_VERSION >= 201703L
#  define STATIC_ASSERT(expr) static_assert(expr)
#elif TORSION_CPP_VERSION >= 201103L
#  define STATIC_ASSERT(expr) static_assert(expr, "check failed")
#elif TORSION_GNUC_PREREQ(2, 7) || defined(__clang__) || defined(__TINYC__)
#  define STATIC_ASSERT_2(x, y) \
     typedef char torsion__assert_ ## y[(x) ? 1 : -1] __attribute__((unused))
#  define STATIC_ASSERT_1(x, y) STATIC_ASSERT_2(x, y)
#  define STATIC_ASSERT(expr) STATIC_ASSERT_1(expr, __LINE__)
#else
#  define STATIC_ASSERT(expr) struct torsion__assert_empty
#endif

/*
 * Keywords/Attributes
 */

#undef noreturn
#undef unused

#if TORSION_STDC_VERSION >= 199901L
#  define TORSION_INLINE inline
#elif TORSION_CPP_VERSION >= 199711L
#  define TORSION_INLINE inline
#elif TORSION_GNUC_PREREQ(2, 7)
#  define TORSION_INLINE __inline__
#elif defined(_MSC_VER) && _MSC_VER >= 900
#  define TORSION_INLINE __inline
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x560) \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x560)
#  define TORSION_INLINE inline
#else
#  define TORSION_INLINE
#endif

#if TORSION_STDC_VERSION >= 199901L
#  define TORSION_RESTRICT restrict
#elif TORSION_GNUC_PREREQ(3, 0)
#  define TORSION_RESTRICT __restrict__
#elif defined(_MSC_VER) && _MSC_VER >= 1400
#  define TORSION_RESTRICT __restrict
#elif defined(__SUNPRO_C) && __SUNPRO_C >= 0x530
#  define TORSION_RESTRICT _Restrict
#else
#  define TORSION_RESTRICT
#endif

#if TORSION_STDC_VERSION >= 201112L
#  define TORSION_NORETURN _Noreturn
#elif TORSION_CPP_VERSION >= 201103L
#  define TORSION_NORETURN [[noreturn]]
#elif TORSION_GNUC_PREREQ(2, 7)
#  define TORSION_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#  define TORSION_NORETURN __declspec(noreturn)
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x590) \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
#  define TORSION_NORETURN __attribute__((noreturn))
#else
#  define TORSION_NORETURN
#endif

#if TORSION_STDC_VERSION > 201710L
#  define TORSION_UNUSED [[maybe_unused]]
#elif TORSION_CPP_VERSION >= 201703L
#  define TORSION_UNUSED [[maybe_unused]]
#elif TORSION_GNUC_PREREQ(2, 7) || defined(__clang__) || defined(__TINYC__)
#  define TORSION_UNUSED __attribute__((unused))
#else
#  define TORSION_UNUSED
#endif

#if defined(__GNUC__) && __GNUC__ >= 2
#  define TORSION_EXTENSION __extension__
#else
#  define TORSION_EXTENSION
#endif

/*
 * Endianness
 */

/* Any decent compiler should be able to optimize this out. */
static const unsigned long torsion__endian_check TORSION_UNUSED = 1;

#define TORSION_BIGENDIAN \
  (*((const unsigned char *)&torsion__endian_check) == 0)

/*
 * Configuration
 */

#ifndef TORSION_HAVE_CONFIG
/* TORSION_HAVE_CONFIG signals that the config
 * will be passed in via the commandline (-D).
 * Otherwise, auto configuration is useful if
 * you're using an awful build system like gyp.
 *
 * Start by clearing everything...
 */
#undef TORSION_HAVE_ASM
#undef TORSION_HAVE_INT128
#undef TORSION_TLS
#undef TORSION_HAVE_PTHREAD

/* Ensure we get some cdefs. */
#include <limits.h>

/* Detect inline ASM support.
 *
 * The following compilers support GNU-style ASM:
 *
 *   - GNU C Compiler 2.0 (gcc)
 *   - Clang (clang)
 *   - Intel C Compiler (icc)
 *   - ARM C Compiler (armcc)
 *   - Sun Studio 12.0
 *   - IBM XL C (xlc)
 *   - Tiny C Compiler (tcc)
 *   - Portable C Compiler (pcc)
 *   - Nils Weller's C Compiler (nwcc)
 *
 * gcc, clang, icc, armcc, pcc, and nwcc define
 * __GNUC__ under the right circumstances. tcc
 * defines GNUC on various BSDs, but not Linux.
 *
 * We do not check for legacy XL C (the AIX and
 * z/OS assemblers are weird).
 */
#if defined(__native_client__)
/* Unsupported under PNaCl. Restricted under NaCl. */
#elif defined(__CC_ARM) && !defined(__clang__)
/* Incompatible assembler syntax. */
#elif defined(__NWCC__)
/* No support for %q/%k prefix on operands. */
#elif (defined(__GNUC__) && __GNUC__ >= 2)           \
   || (defined(__clang__))                           \
   || (defined(__INTEL_COMPILER))                    \
   || (defined(__SUNPRO_C) && __SUNPRO_C >= 0x590)   \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590) \
   || (defined(__TINYC__))
#  define TORSION_HAVE_ASM
#endif

/* Detect __int128 support. */
#if defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER)
#  if defined(__SIZEOF_INT128__) && defined(__SIZEOF_POINTER__)
#    if __SIZEOF_POINTER__ >= 8 && !defined(__NWCC__)
#      define TORSION_HAVE_INT128
#    endif
#  endif
#endif

/* Basically a stripped down version of our old file[1].
 * It only includes the compilers we for sure know work.
 *
 * [1] https://github.com/bcoin-org/libtorsion/blob/2fe6cd3/src/tls.h
 */
#if defined(_EFI_CDEFS_H)
/* No threads in UEFI. */
#elif defined(_TLIBC_CDECL_)
#  define TORSION_TLS __thread
#elif defined(__COSMOPOLITAN__)
/* Not portable. */
#elif defined(__clang__) || defined(__llvm__)
#  ifdef __has_feature
#    if __has_feature(tls)
#      if defined(_WIN32)
#        define TORSION_TLS __declspec(thread)
#      else
#        define TORSION_TLS __thread
#      endif
#    endif
#  endif
#  ifdef __ANDROID__
#    if !defined(__clang_major__) || __clang_major__ < 5
#      undef TORSION_TLS
#    endif
#  endif
#elif defined(__INTEL_COMPILER)
#  if defined(_WIN32) && __INTEL_COMPILER >= 1000
#    define TORSION_TLS __declspec(thread)
#  elif defined(__linux__) && __INTEL_COMPILER >= 810
#    if TORSION_GNUC_PREREQ(3, 3)
#      define TORSION_TLS __thread
#    endif
#  elif defined(__APPLE__) && __INTEL_COMPILER >= 1500
#    define TORSION_TLS __thread
#  endif
#elif defined(__GNUC__) && !defined(__CC_ARM)  \
                        && !defined(__TINYC__) \
                        && !defined(__PCC__)   \
                        && !defined(__NWCC__)
#  if TORSION_GNUC_PREREQ(4, 3)
#    define TORSION_TLS __thread
#  elif TORSION_GNUC_PREREQ(3, 3)
#    if defined(__ELF__) && (defined(__i386__) || defined(__x86_64__))
#      define TORSION_TLS __thread
#    endif
#  endif
#elif (defined(_MSC_VER) && _MSC_VER >= 1100)          \
   || (defined(__WATCOMC__) && __WATCOMC__ >= 1100)    \
   || (defined(__BORLANDC__) && __BORLANDC__ >= 0x520) \
   || (defined(__ZTC__) && __ZTC__ >= 0x750)           \
   || (defined(__DMC__))
#  if !defined(__WATCOMC__) || !defined(__LINUX__)
#    define TORSION_TLS __declspec(thread)
#  endif
#elif defined(__ARMCC_VERSION) && !defined(__CC_NORCROFT)
#  if __ARMCC_VERSION >= 410000
#    define TORSION_TLS __thread
#  endif
#elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x560)   \
   || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x560) \
   || (defined(__HP_cc) && __HP_cc >= 53600)         \
   || (defined(__HP_aCC) && __HP_aCC >= 53600)       \
   || (defined(__PCC__) && __PCC__ >= 1)             \
   || (defined(__chibicc__))                         \
   || (defined(__NWCC__))
#  define TORSION_TLS __thread
#elif defined(__xlC__) && defined(_AIX)
#  if defined(_THREAD_SAFE) && defined(HAVE_QTLS)
#    define TORSION_TLS __thread
#  endif
#elif TORSION_STDC_VERSION >= 201112L
#  ifndef __STDC_NO_THREADS__
#    define TORSION_TLS _Thread_local
#  endif
#elif TORSION_CPP_VERSION >= 201103L
#  define TORSION_TLS thread_local
#endif

/* Detect builtin pthread support. */
#if defined(_EFI_CDEFS_H)
/* No threads in UEFI. */
#elif defined(_TLIBC_CDECL_)
/* Requires -lsgx_pthread. We could use the
   sgx_thread API which is guaranteed to be
   available, but we don't need it. */
#elif defined(__COSMOPOLITAN__)
/* No pthread support (yet). */
#elif defined(__linux__)
#  if defined(__GLIBC__)
#    ifdef __GLIBC_PREREQ
#      if __GLIBC_PREREQ(2, 4)
#        define TORSION_HAVE_PTHREAD
#      endif
#    endif
#  elif defined(__BIONIC__)
#    define TORSION_HAVE_PTHREAD
#  elif defined(__UCLIBC__)
/*   No support. */
#  elif defined(__NEWLIB__)
/*   No support. */
#  elif defined(__dietlibc__)
/*   No support. */
#  else
#    include <stddef.h>
#    ifdef __DEFINED_size_t /* musl */
#      define TORSION_HAVE_PTHREAD
#    endif
#  endif
#elif defined(__WATCOMC__) && defined(__LINUX__)
#  define TORSION_HAVE_PTHREAD
#elif defined(__APPLE__) && defined(__MACH__)
#  include <AvailabilityMacros.h>
#  if MAC_OS_X_VERSION_MAX_ALLOWED >= 1040
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__FreeBSD__)
#  include <sys/param.h>
#  if defined(__FreeBSD_version) && __FreeBSD_version >= 700055
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__OpenBSD__)
#  include <sys/param.h>
#  if defined(OpenBSD) && OpenBSD >= 201805
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__NetBSD__)
#  include <sys/param.h>
#  if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 299001200
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__DragonFly__)
#  include <sys/param.h>
#  if defined(__DragonFly_version) && __DragonFly_version >= 200400
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__sun) && defined(__SVR4)
#  define TORSION_HAVE_PTHREAD
#elif defined(__CYGWIN__)
#  include <cygwin/version.h>
#  if CYGWIN_VERSION_API_MAJOR > 0 || CYGWIN_VERSION_API_MINOR >= 38
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__gnu_hurd__)
#  if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 28)
#      define TORSION_HAVE_PTHREAD
#    endif
#  endif
#elif defined(_AIX)
#  if defined(__xlC__) && defined(_THREAD_SAFE)
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__MVS__)
#  if defined(_ALL_SOURCE) || defined(_OPEN_THREADS) || defined(_UNIX03_THREADS)
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__QNXNTO__) || defined(__HAIKU__)
#  define TORSION_HAVE_PTHREAD
#endif

/* Allow some overrides. */
#ifdef TORSION_NO_ASM
#  undef TORSION_HAVE_ASM
#endif

#ifdef TORSION_NO_INT128
#  undef TORSION_HAVE_INT128
#endif

#ifdef TORSION_NO_TLS
#  undef TORSION_TLS
#endif

#ifdef TORSION_NO_PTHREAD
#  undef TORSION_HAVE_PTHREAD
#endif

#endif /* !TORSION_HAVE_CONFIG */

/*
 * Types
 */

#ifdef TORSION_HAVE_INT128
TORSION_EXTENSION typedef unsigned __int128 torsion_uint128_t;
TORSION_EXTENSION typedef signed __int128 torsion_int128_t;
#endif

/*
 * Value Barrier
 */

#if defined(TORSION_HAVE_ASM)
#define TORSION_BARRIER(type, prefix) \
static TORSION_INLINE type            \
prefix ## _barrier(type x) {          \
  __asm__ ("" : "+r" (x));            \
  return x;                           \
}
#else
#define TORSION_BARRIER(type, prefix) \
static TORSION_INLINE type            \
prefix ## _barrier(type x) {          \
  return x;                           \
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

#define ENTROPY_SIZE 32
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Helpers
 */

#define torsion_abort torsion__abort

TORSION_NORETURN void
torsion__assert_fail(const char *file, int line, const char *expr);

TORSION_NORETURN void
torsion__abort(void);

/*
 * Character Transcoding
 */

extern const int torsion__ascii[256];
extern const int torsion__native[256];

/* We could check the character set in preprocessor, but the
 * standard has some very strange wording around character
 * constants in preprocessor. Specifically, the standard says,
 *
 *   "Whether the numeric value for these character constants
 *    matches the value obtained when an identical character
 *    constant occurs in an expression (other than within a
 *    #if or #elif directive) is implementation-defined."[1]
 *
 * I suppose this can be taken to mean that the preprocessor
 * may use the source character set instead of the execution
 * character set. Vague wording like this has often been the
 * justification for compiler developers to do wacky stuff,
 * so we instead check the character set at "runtime". Every
 * compiler should treat this as a constant expression and
 * optimize it out.
 *
 * [1] ANSI/ISO 9899-1990, Page 87, Section 6.8.1 ("Conditional Inclusion")
 */
#define torsion_a (' ' == 32 && '0' == 48 && 'A' == 65 && 'a' == 97)
#define torsion_ascii(c) (torsion_a ? ((c) & 0xff) : torsion__ascii[(c) & 0xff])
#define torsion_native(c) (torsion_a ? (c) : torsion__native[(c) & 0xff])

#endif /* TORSION_INTERNAL_H */
