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

echo > confdefs.h

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

AC_CHECK_DEFINE([__WATCOMC__], [
  AS_IF([test x"$WATCOM" = x''], [
    AC_MSG_ERROR([./configure must be run with ./scripts/watcom-configure])
  ])
], [
  AC_MSG_WARN([WATCOM env var set but environment is not watcom])
  AS_UNSET([WATCOM])
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
  node,
  AS_HELP_STRING([--enable-node],
                 [build the fullnode [default=yes]]),
  [enable_node=$enableval],
  [enable_node=yes]
)

AC_ARG_ENABLE(
  portable,
  AS_HELP_STRING([--enable-portable],
                 [be as portable as possible [default=no]]),
  [enable_portable=$enableval],
  [enable_portable=no]
)

AC_ARG_ENABLE(
  pthread,
  AS_HELP_STRING([--enable-pthread],
                 [use pthread [default=yes]]),
  [enable_pthread=$enableval],
  [enable_pthread=yes]
)

AC_ARG_ENABLE(
  tests,
  AS_HELP_STRING([--enable-tests],
                 [enable tests [default=yes]]),
  [enable_tests=$enableval],
  [enable_tests=yes]
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

#
# System Libraries
#

AS_IF([test x"$MINGW" != x''], [
  LIBS="$LIBS -lkernel32 -ladvapi32 -lws2_32"
], [
  AC_SEARCH_LIBS([gethostbyname], [nsl])
  AC_SEARCH_LIBS([socket], [socket])

  AS_CASE([$host_os], [haiku], [
    LIBS="-lnetwork $LIBS"
  ])

  AS_IF([test x"$enable_pthread$WATCOM$WASI$EMSCRIPTEN" = x'yes'], [
    AX_PTHREAD([
      CC="$PTHREAD_CC"
      CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
      LIBS="$PTHREAD_LIBS $LIBS"

      AC_DEFINE([BTC_PTHREAD])
      AC_DEFINE([LDB_PTHREAD])
    ])
  ])

  AC_SEARCH_LIBS([clock_gettime], [rt])
  AC_SEARCH_LIBS([sqrt], [m])
])

#
# Feature Testing
#

has_asm=no
has_big=no
has_clock=no
has_fdatasync=no
has_gethostname=no
has_getifaddrs=no
has_int128=no
has_pread=no
has_rfc3493=no
has_zlib=no

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
  # Mimic CMake in the case of universal endianness.
  AC_CHECK_DEFINE([__powerpc__], [has_big=yes])
])

AS_IF([test x"$enable_portable" = x'yes'], [
  AS_IF([test x"$MINGW" != x''], [
    has_gethostname=yes
  ])
], [
  AC_MSG_CHECKING(for clock_gettime support)
  AC_LINK_IFELSE([
    AC_LANG_SOURCE([[
#     include <time.h>
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

  AC_MSG_CHECKING(for fdatasync support)
  AC_LINK_IFELSE([
    AC_LANG_SOURCE([[
#     include <unistd.h>
      int main(void) {
        return fdatasync(1);
      }
    ]])
  ], [
    has_fdatasync=yes
  ])
  AC_MSG_RESULT([$has_fdatasync])

  AS_IF([test x"$MINGW" != x''], [
    has_gethostname=yes
    has_getifaddrs=no
    has_rfc3493=yes
  ], [
    AC_MSG_CHECKING(for gethostname support)
    AC_LINK_IFELSE([
      AC_LANG_SOURCE([[
#       include <unistd.h>
        int main(void) {
          char name[256];
          return gethostname(name, sizeof(name));
        }
      ]])
    ], [
      has_gethostname=yes
    ])
    AC_MSG_RESULT([$has_gethostname])

    AC_MSG_CHECKING(for getifaddrs support)
    AC_LINK_IFELSE([
      AC_LANG_SOURCE([[
#       include <sys/types.h>
#       include <ifaddrs.h>
#       include <net/if.h>
        int main(void) {
          struct ifaddrs *addrs;
          return getifaddrs(&addrs);
        }
      ]])
    ], [
      has_getifaddrs=yes
    ])
    AC_MSG_RESULT([$has_getifaddrs])

    AC_MSG_CHECKING(for rfc3493 support)
    AC_LINK_IFELSE([
      AC_LANG_SOURCE([[
#       include <stddef.h>
#       include <sys/types.h>
#       include <sys/socket.h>
#       include <netinet/in.h>
#       include <netdb.h>
        int main(void) {
          struct sockaddr_storage storage;
          struct sockaddr_in6 sai6;
          struct addrinfo *info;
          return getaddrinfo("localhost", NULL, NULL, &info);
        }
     ]])
    ], [
      has_rfc3493=yes
    ])
    AC_MSG_RESULT([$has_rfc3493])
  ])

  AC_MSG_CHECKING(for pread support)
  AC_LINK_IFELSE([
    AC_LANG_SOURCE([[
#     include <unistd.h>
      int main(void) {
        char buf[32];
        return pread(0, buf, sizeof(buf), 0);
      }
    ]])
  ], [
    has_pread=yes
  ])
  AC_MSG_RESULT([$has_pread])
])

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

AS_IF([test x"$enable_tests" = x'yes'], [
  AC_CHECK_HEADER([zlib.h], [
    AC_CHECK_LIB([z], [compress2], [has_zlib=yes])
  ])
])

#
# Flags
#

AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],
                      [CFLAGS="$CFLAGS -Werror=unknown-warning-option"])
AX_CHECK_COMPILE_FLAG([-pedantic], [CFLAGS="$CFLAGS -pedantic"])
AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
AX_CHECK_COMPILE_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"])
AX_CHECK_COMPILE_FLAG([-Wcast-align=strict],
                      [CFLAGS="$CFLAGS -Wcast-align=strict"])
AX_CHECK_COMPILE_FLAG([-Wconditional-uninitialized],
                      [CFLAGS="$CFLAGS -Wconditional-uninitialized"])
AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes],
                      [CFLAGS="$CFLAGS -Wmissing-prototypes"])
AX_CHECK_COMPILE_FLAG([-Wno-implicit-fallthrough],
                      [CFLAGS="$CFLAGS -Wno-implicit-fallthrough"])
AX_CHECK_COMPILE_FLAG([-Wno-long-long], [CFLAGS="$CFLAGS -Wno-long-long"])
AX_CHECK_COMPILE_FLAG([-Wno-overlength-strings],
                      [CFLAGS="$CFLAGS -Wno-overlength-strings"])
AX_CHECK_COMPILE_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"])
AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes],
                      [CFLAGS="$CFLAGS -Wstrict-prototypes"])
AX_CHECK_COMPILE_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"])

AS_IF([test x"$WATCOM" != x''], [
  AX_CHECK_COMPILE_FLAG([-Wno-n201], [CFLAGS="$CFLAGS -Wno-n201"])
  AX_CHECK_COMPILE_FLAG([-Wno-n202], [CFLAGS="$CFLAGS -Wno-n202"])
])

AS_IF([test x"$enable_coverage" = x'yes'], [
  CFLAGS="$CFLAGS -O0 --coverage"
])

AS_IF([test x"$enable_debug" = x'yes'], [
  AX_CHECK_COMPILE_FLAG([-g], [CFLAGS="$CFLAGS -g"])
])

AS_IF([test x"$MINGW" != x''], [
  # Ensure we are redistributable on windows.
  LDFLAGS="$LDFLAGS -static-libgcc"
  # Much compatibility.
  AS_IF([test x"$enable_portable $MINGW_ARCH" = x'yes i686'], [
    CFLAGS="$CFLAGS -march=i486 -mtune=i686"
  ])
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
  AC_DEFINE([LDB_COVERAGE])
])

AS_IF([test x"$enable_debug" = x'yes'], [
  AC_DEFINE([BTC_DEBUG])
  AC_DEFINE([LDB_DEBUG])
])

AS_IF([test x"$has_fdatasync" = x'yes'], [
  AC_DEFINE([LDB_HAVE_FDATASYNC])
])

AS_IF([test x"$has_gethostname" = x'yes'], [
  AC_DEFINE([BTC_HAVE_GETHOSTNAME])
])

AS_IF([test x"$has_getifaddrs" = x'yes'], [
  AC_DEFINE([BTC_HAVE_GETIFADDRS])
])

AS_IF([test x"$has_int128" = x'yes'], [
  AC_DEFINE([BTC_HAVE_INT128])
])

AS_IF([test x"$enable_portable" = x'yes'], [
  AC_DEFINE([BTC_PORTABLE])
])

AS_IF([test x"$has_pread" = x'yes'], [
  AC_DEFINE([LDB_HAVE_PREAD])
])

AS_IF([test x"$has_rfc3493" = x'yes'], [
  AC_DEFINE([BTC_HAVE_RFC3493])
])

AS_IF([test x"$has_zlib" = x'yes'], [
  AC_DEFINE([BTC_HAVE_ZLIB])
])

#
# Libraries
#

AS_IF([test x"$has_zlib" = x'yes'], [
  AC_SUBST([ZLIB], ['-lz'])
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

AS_IF([test x"$WASI$EMSCRIPTEN" != x''], [
  enable_node=no
])

AM_CONDITIONAL([ENABLE_LEVELDB], [test x"$enable_leveldb" = x'yes'])
AM_CONDITIONAL([ENABLE_NODE], [test x"$enable_node" = x'yes'])
AM_CONDITIONAL([ENABLE_SHARED], [test x"$enable_shared" = x'yes'])
AM_CONDITIONAL([ENABLE_TESTS], [test x"$enable_tests" = x'yes'])
AM_CONDITIONAL([MINGW], [test x"$MINGW" != x''])

AC_CONFIG_FILES([deps/lcdb/Makefile
                 deps/lcdb/contrib/lwdb/Makefile
                 Makefile
                 test/Makefile
                 libmako.pc])

#
# Output
#

AC_OUTPUT

AC_MSG_NOTICE([Build Options:

  coverage   = $enable_coverage
  debug      = $enable_debug
  leveldb    = $enable_leveldb
  node       = $enable_node
  portable   = $enable_portable
  pthread    = $enable_pthread
  tests      = $enable_tests

  PREFIX     = $prefix
  HOST       = $host
  CC         = $CC
  CPPFLAGS   = $CPPFLAGS
  CFLAGS     = $CFLAGS
  LDFLAGS    = $LDFLAGS
  DEFS       = $DEFS
  LIBS       = $LIBS
])
