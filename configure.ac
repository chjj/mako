dnl configure.ac - autoconf script for mako
dnl Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
dnl https://github.com/chjj/mako

m4_define(MAKO_PKG_VERSION, 0.0.0)
m4_define(MAKO_ABI_VERSION, 0:0:0)

#
# Initialization
#

AC_PREREQ([2.64])
AC_INIT([mako], [m4_substr(MAKO_PKG_VERSION, 0)],
        [https://github.com/chjj/mako/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([include/mako/bip39.h])
AC_CANONICAL_HOST
AC_LANG_ASSERT([C])
AC_PROG_CC

AM_INIT_AUTOMAKE([1.11 foreign subdir-objects tar-v7 dist-zip])
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_SILENT_RULES([yes])

LT_PREREQ([2.2.8])
LT_INIT([static disable-shared])

#
# Sanity Checks
#

AC_CHECK_DEFINE([__wasi__], [
  AS_IF([test x"$WASI" = x''], [
    AC_MSG_ERROR([./configure must be run with ./scripts/wasi-configure])
  ])
], [
  AS_IF([test x"$WASI" != x''], [
    AC_MSG_WARN([WASI env var set but environment is not wasi])
    AS_UNSET([WASI])
  ])
])

AC_CHECK_DEFINE([__EMSCRIPTEN__], [
  AS_IF([test x"$EMSCRIPTEN" = x''], [
    AC_MSG_ERROR([./configure must be run with emconfigure])
  ])
], [
  AS_IF([test x"$EMSCRIPTEN" != x''], [
    AC_MSG_WARN([EMSCRIPTEN env var set but environment is not emscripten])
    AS_UNSET([EMSCRIPTEN])
  ])
])

AS_CASE([$host_os], [mingw*], [MINGW="$CC"], [AS_UNSET([MINGW])])

#
# Options
#

AC_ARG_ENABLE(
  asm,
  AS_HELP_STRING([--enable-asm],
                 [use inline assembly if available [default=yes]]),
  [enable_asm=$enableval],
  [enable_asm=yes]
)

AC_ARG_ENABLE(
  coverage,
  AS_HELP_STRING([--enable-coverage],
                 [enable coverage [default=no]]),
  [enable_coverage=$enableval],
  [enable_coverage=no]
)

AC_ARG_ENABLE(
  debug,
  AS_HELP_STRING([--enable-debug],
                 [enable debug build [default=no]]),
  [enable_debug=$enableval],
  [enable_debug=no]
)

AC_ARG_ENABLE(
  int128,
  AS_HELP_STRING([--enable-int128],
                 [use __int128 if available [default=yes]]),
  [enable_int128=$enableval],
  [enable_int128=yes]
)

AC_ARG_ENABLE(
  leveldb,
  AS_HELP_STRING([--enable-leveldb],
                 [use leveldb [default=no]]),
  [enable_leveldb=$enableval],
  [enable_leveldb=no]
)

AC_ARG_ENABLE(
  lsm,
  AS_HELP_STRING([--enable-lsm],
                 [use sqlite4 lsm [default=no]]),
  [enable_lsm=$enableval],
  [enable_lsm=no]
)

AC_ARG_ENABLE(
  node,
  AS_HELP_STRING([--enable-node],
                 [build the fullnode [default=yes]]),
  [enable_node=$enableval],
  [enable_node=yes]
)

AC_ARG_ENABLE(
  tests,
  AS_HELP_STRING([--enable-tests],
                 [enable tests [default=yes]]),
  [enable_tests=$enableval],
  [enable_tests=yes]
)

AC_ARG_ENABLE(
  tls,
  AS_HELP_STRING([--enable-tls],
                 [use thread-local storage if available [default=yes]]),
  [enable_tls=$enableval],
  [enable_tls=yes]
)

#
# Global Flags
#

AX_CHECK_DEFINE([limits.h], [__GLIBC__], [
  AX_CHECK_COMPILE_FLAG([-std=c90], [CFLAGS="$CFLAGS -std=c90"], [
    AX_CHECK_COMPILE_FLAG([-std=c89], [CFLAGS="$CFLAGS -std=c89"])
  ])
])

AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM([[]], [[
#   if !defined(__GNUC__) || __GNUC__ < 4
      choke me
#   endif
  ]])
], [
  AX_CHECK_COMPILE_FLAG([-fvisibility=hidden],
                        [CFLAGS="$CFLAGS -fvisibility=hidden"])
])

AS_CASE([$host_os], [darwin*], [
  AX_CHECK_COMPILE_FLAG([-mmacosx-version-min=10.7],
                        [CFLAGS="$CFLAGS -mmacosx-version-min=10.7"])
])

#
# Compiler Fixes
#

# Encourage the user to build with xlc_r.
AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM([[]], [[
#   if defined(__xlC__) && defined(_AIX) && !defined(_THREAD_SAFE)
      choke me
#   endif
  ]])
], [], [
  AC_MSG_WARN([Please use a thread-safe compiler invocation.])
  AC_MSG_WARN([For example, './configure CC=xlc_r'.])
])

# Hack to get OpenWatcom's owcc working.
AC_CHECK_DEFINE([__WATCOMC__], [
  grep -v '#define PACKAGE_STRING' confdefs.h > confdefs.h.tmp
  mv -f confdefs.h.tmp confdefs.h
])

#
# Feature Testing
#

has_64bit=no
has_asm=no
has_big=no
has_clock=no
has_int128=no
has_pthread=no
has_tls=no
has_zlib=no

AC_MSG_CHECKING(for 64-bit support)
AC_COMPILE_IFELSE([
  AC_LANG_SOURCE([[
    typedef char check_voidptr_t[sizeof(void *) >= 8 ? 1 : -1];
    int main(void) {
      return 0;
    }
  ]])
], [has_64bit=yes])
AC_MSG_RESULT([$has_64bit])

AS_IF([test x"$enable_asm" = x'yes'], [
  AC_MSG_CHECKING(for inline asm support)
  AC_LINK_IFELSE([
    AC_LANG_SOURCE([[
      int main(void) {
        unsigned long z = 953;
        unsigned long x = 109;
        unsigned long y = 577;
        unsigned long c;
        __asm__ __volatile__ (
#     if defined(__amd64__) || defined(__amd64)
          "movq \@S|@0, %q1\n"
#     elif defined(__x86_64__) || defined(__x86_64)
          "movq \@S|@0, %q1\n"
#     elif defined(__i386__) || defined(__i386) || defined(i386)
          "movl \@S|@0, %k1\n"
#     else
          ""
#     endif
          : "+r" (z), "=&r" (c)
#     if defined(__wasm__) || defined(__EMSCRIPTEN__)
          :
#     elif defined(__TINYC__)
          : "rm" (x), "rm" (y)
#     else
          : "%rm" (x), "rm" (y)
#     endif
          : "cc", "memory"
        );
        return z & 0x7f;
      }
    ]])
  ], [
    has_asm=yes
  ])
  AC_MSG_RESULT([$has_asm])
])

AC_C_BIGENDIAN([has_big=yes], [:], [
  AC_MSG_ERROR([cannot determine endianness])
], [
  AC_MSG_ERROR([universal endianness])
])

AC_MSG_CHECKING(for clock_gettime support)
AC_LINK_IFELSE([
  AC_LANG_SOURCE([[
#   include <time.h>
    int main(void) {
      struct timespec ts;
      (void)clock_gettime((clockid_t)CLOCK_REALTIME, &ts);
      (void)clock_gettime((clockid_t)CLOCK_MONOTONIC, &ts);
      return ts.tv_sec & ts.tv_nsec & 0x7f;
    }
  ]])
], [
  has_clock=yes
])
AC_MSG_RESULT([$has_clock])

AS_IF([test x"$enable_int128" = x'yes'], [
  AC_MSG_CHECKING(for int128 support)
  AC_LINK_IFELSE([
    AC_LANG_SOURCE([[
      typedef signed __int128 xint128_t;
      typedef unsigned __int128 xuint128_t;
      typedef char check_voidptr_t[sizeof(void *) >= 8 ? 1 : -1];
      typedef char check_int128_t[sizeof(xint128_t) == 16 ? 1 : -1];
      typedef char check_uint128_t[sizeof(xuint128_t) == 16 ? 1 : -1];
      int main(int argc, char **argv) {
        xint128_t c = argv[0][0];
        xuint128_t r = argc + c;
        while (argc--) r *= r;
        return r >> 121;
      }
    ]])
  ], [
    has_int128=yes
  ])
  AC_MSG_RESULT([$has_int128])
])

AS_IF([test x"$MINGW$WASI$EMSCRIPTEN" = x''], [
  AX_PTHREAD([has_pthread=yes])
])

AS_IF([test x"$enable_tls" = x'yes'], [
  AX_TLS([has_tls=yes])
])

AS_IF([test x"$enable_tests" = x'yes'], [
  AC_CHECK_HEADER([zlib.h], [
    AC_CHECK_LIB([z], [compress2], [has_zlib=yes])
  ])
])

#
# Flags
#

mako_save_CFLAGS="$CFLAGS"

AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],
                      [CFLAGS="$CFLAGS -Werror=unknown-warning-option"])
AX_CHECK_COMPILE_FLAG([-pedantic], [WARN_FLAGS="$WARN_FLAGS -pedantic"])
AX_CHECK_COMPILE_FLAG([-Wall], [WARN_FLAGS="$WARN_FLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([-Wextra], [WARN_FLAGS="$WARN_FLAGS -Wextra"])
AX_CHECK_COMPILE_FLAG([-Wcast-align], [WARN_FLAGS="$WARN_FLAGS -Wcast-align"])
AX_CHECK_COMPILE_FLAG([-Wcast-align=strict],
                      [WARN_FLAGS="$WARN_FLAGS -Wcast-align=strict"])
AX_CHECK_COMPILE_FLAG([-Wconditional-uninitialized],
                      [WARN_FLAGS="$WARN_FLAGS -Wconditional-uninitialized"])
AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes],
                      [WARN_FLAGS="$WARN_FLAGS -Wmissing-prototypes"])
AX_CHECK_COMPILE_FLAG([-Wno-implicit-fallthrough],
                      [WARN_FLAGS="$WARN_FLAGS -Wno-implicit-fallthrough"])
AX_CHECK_COMPILE_FLAG([-Wno-long-long],
                      [WARN_FLAGS="$WARN_FLAGS -Wno-long-long"])
AX_CHECK_COMPILE_FLAG([-Wno-overlength-strings],
                      [WARN_FLAGS="$WARN_FLAGS -Wno-overlength-strings"])
AX_CHECK_COMPILE_FLAG([-Wshadow], [WARN_FLAGS="$WARN_FLAGS -Wshadow"])
AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes],
                      [WARN_FLAGS="$WARN_FLAGS -Wstrict-prototypes"])
AX_CHECK_COMPILE_FLAG([-Wundef], [WARN_FLAGS="$WARN_FLAGS -Wundef"])

CFLAGS="$mako_save_CFLAGS"

AC_SUBST([WARN_FLAGS])

AC_CHECK_DEFINE([__WATCOMC__], [
  AX_CHECK_COMPILE_FLAG([-Wno-n201], [CFLAGS="$CFLAGS -Wno-n201"])
  AX_CHECK_COMPILE_FLAG([-Wno-n202], [CFLAGS="$CFLAGS -Wno-n202"])
])

AS_IF([test x"$enable_coverage" = x'yes'], [
  CFLAGS="$CFLAGS -O0 --coverage"
])

AS_IF([test x"$enable_debug" = x'yes'], [
  AX_CHECK_COMPILE_FLAG([-g], [CFLAGS="$CFLAGS -g"])
])

AS_IF([test x"$has_tls" = x'yes'], [
  CFLAGS="$CFLAGS $ax_cv_tls_cflags"
])

AS_IF([test x"$MINGW" != x''], [
  # Ensure we are redistributable on windows.
  LDFLAGS="$LDFLAGS -static-libgcc"
])

#
# Defines
#

AS_IF([test x"$has_asm" = x'yes'], [
  AC_DEFINE([BTC_HAVE_ASM])
])

AS_IF([test x"$has_big" = x'yes'], [
  AC_DEFINE([BTC_BIGENDIAN])
])

AS_IF([test x"$has_clock" = x'yes'], [
  AC_DEFINE([BTC_HAVE_CLOCK])
])

AS_IF([test x"$enable_coverage" = x'yes'], [
  AC_DEFINE([BTC_COVERAGE])
])

AS_IF([test x"$enable_debug" = x'yes'], [
  AC_DEFINE([BTC_DEBUG])
])

AS_IF([test x"$has_int128" = x'yes'], [
  AC_DEFINE([BTC_HAVE_INT128])
])

AS_IF([test x"$has_pthread" = x'yes'], [
  AC_DEFINE([BTC_HAVE_PTHREAD])
])

AS_IF([test x"$has_tls" = x'yes'], [
  AC_DEFINE_UNQUOTED([BTC_TLS], [$ax_cv_tls_keyword])
  AC_DEFINE_UNQUOTED([RDB_TLS], [$ax_cv_tls_keyword])
])

AS_IF([test x"$has_zlib" = x'yes'], [
  AC_DEFINE([BTC_HAVE_ZLIB])
])

#
# Feature Test Macros
#

AS_IF([test x"$MINGW" != x''], [
  AC_DEFINE([_WIN32_WINNT], [0x501])
])

AX_CHECK_DEFINE([limits.h], [__GLIBC__], [
  AC_DEFINE([_GNU_SOURCE])
])

AS_CASE([$host_os], [solaris*], [
  AC_DEFINE([_TS_ERRNO])
])

AS_CASE([$host_os], [aix*], [
  AC_DEFINE([_THREAD_SAFE_ERRNO])
])

AS_IF([test x"$has_64bit" != x'yes'], [
  # https://twitter.com/hyc_symas/status/678604015127683074
  AC_DEFINE([MDB_VL32])
])

#
# Libraries
#

AS_IF([test x"$MINGW" != x''], [
  LIBS="$LIBS -lkernel32 -ladvapi32 -lshell32 -lws2_32"
], [
  LIBS="$LIBS -lm"

  AS_IF([test x"$has_pthread" = x'yes'], [
    CC="$PTHREAD_CC"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    LIBS="$LIBS $PTHREAD_LIBS"
  ])
])

#
# Configuration
#

AC_SUBST([ABI_VERSION], [MAKO_ABI_VERSION])

AS_IF([test x"$MINGW" != x''], [
  AC_SUBST([LOG_COMPILER], [wine])
])

AS_IF([test x"$WASI" != x''], [
  AC_SUBST([LOG_COMPILER], ['$(top_builddir)/scripts/wasi-run'])
])

AS_IF([test x"$EMSCRIPTEN" != x''], [
  AC_SUBST([LOG_COMPILER], [node])
])

AS_IF([test x"$has_zlib" = x'yes'], [
  AC_SUBST([ZLIB], ['-lz'])
])

AS_IF([test x"$WASI$EMSCRIPTEN" != x''], [
  enable_node=no
])

AM_CONDITIONAL([ENABLE_LEVELDB], [test x"$enable_leveldb" = x'yes'])
AM_CONDITIONAL([ENABLE_LSM], [test x"$enable_lsm" = x'yes'])
AM_CONDITIONAL([ENABLE_NODE], [test x"$enable_node" = x'yes'])
AM_CONDITIONAL([ENABLE_SHARED], [test x"$enable_shared" = x'yes'])
AM_CONDITIONAL([ENABLE_TESTS], [test x"$enable_tests" = x'yes'])
AM_CONDITIONAL([HAVE_PTHREAD], [test x"$has_pthread" = x'yes'])
AM_CONDITIONAL([MINGW], [test x"$MINGW" != x''])

AC_CONFIG_FILES([deps/lmdb/Makefile
                 deps/lsm1/Makefile
                 deps/lsm2/Makefile
                 deps/rdb/Makefile
                 Makefile
                 test/Makefile
                 libmako.pc])

#
# Output
#

AC_OUTPUT

AC_MSG_NOTICE([Build Options:

  64-bit     = $has_64bit
  asm        = $has_asm
  big        = $has_big
  clock      = $has_clock
  coverage   = $enable_coverage
  debug      = $enable_debug
  emscripten = $EMSCRIPTEN
  int128     = $has_int128
  leveldb    = $enable_leveldb
  lsm        = $enable_lsm
  node       = $enable_node
  pthread    = $has_pthread
  tests      = $enable_tests
  tls        = $has_tls
  wasi       = $WASI
  zlib       = $has_zlib

  PREFIX     = $prefix
  HOST       = $host
  CC         = $CC
  CPPFLAGS   = $CPPFLAGS
  CFLAGS     = $CFLAGS
  WARN_FLAGS = $WARN_FLAGS
  LDFLAGS    = $LDFLAGS
  DEFS       = $DEFS
  LIBS       = $LIBS
])
