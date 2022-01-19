# ax_tls.m4 - thread-local storage test for autoconf
# Copyright (c) 2021, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/libtorsion
#
# SYNOPSIS
#
#   AX_TLS([action-if-found], [action-if-not-found])
#
# DESCRIPTION
#
#   Check for thread-local storage support and keyword.
#
#   Also checks for necessary flags and whether TLS is
#   emulated by the compiler / support libraries.

AC_DEFUN([AX_TLS], [
  AC_CACHE_CHECK([for thread-local storage flags], [ax_cv_tls_cflags], [
    ax_cv_tls_cflags=''

    # XL requires a special flag. Don't ask me why.
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[]], [[
#       if !defined(__xlC__) && !defined(__ibmxl__)
          choke me
#       endif
      ]])
    ], [
      ax_tls_save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS -qtls"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
                        [ax_cv_tls_cflags='-qtls'])
      CFLAGS="$ax_tls_save_CFLAGS"
    ])
  ])

  AC_CACHE_CHECK([for thread-local storage keyword], [ax_cv_tls_keyword], [
    ax_cv_tls_keyword=none

    # Append XL -qtls flag if present.
    ax_tls_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $ax_cv_tls_cflags"

    # Various TLS keywords.
    #
    # The last keyword is not widely known, but there is evidence
    # that Compaq C for Tru64 UNIX supported it at one point.
    ax_tls_keywords='__thread __declspec(thread) __declspec(__thread)'

    # Prepend or append _Thread_local according to the C standard.
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[]], [[
#       ifndef __cplusplus
          choke me
#       endif
      ]])
    ], [
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[]], [[
#         if !defined(__cplusplus) || (__cplusplus + 0L) < 201103L
            choke me
#         endif
        ]])
      ], [ax_tls_keywords="thread_local $ax_tls_keywords"],
         [ax_tls_keywords="$ax_tls_keywords thread_local"])
    ], [
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[]], [[
#         if !defined(__STDC_VERSION__) || (__STDC_VERSION__ + 0L) < 201112L
            choke me
#         endif
        ]])
      ], [ax_tls_keywords="_Thread_local $ax_tls_keywords"],
         [ax_tls_keywords="$ax_tls_keywords _Thread_local"])
    ])

    # We try to run the executable when not cross compiling. There
    # are far too many instances of TLS code successfully building
    # but not running.
    for ax_tls_keyword in $ax_tls_keywords; do
      ax_tls_found=no

      # The thread-local variable must have external linkage otherwise
      # the optimizer may remove the TLS code. GCC and Clang refuse to
      # optimize the below code (even with -O3 enabled).
      ax_tls_c="$ax_tls_keyword int x; int main(void) { x = 1; return !x; }"

      AC_RUN_IFELSE([AC_LANG_SOURCE([[$ax_tls_c]])], [ax_tls_found=yes], [], [
        AC_LINK_IFELSE([AC_LANG_SOURCE([[$ax_tls_c]])], [ax_tls_found=yes])
      ])

      AS_IF([test x"$ax_tls_found" = x'yes'], [
        ax_cv_tls_keyword="$ax_tls_keyword"
        break
      ])
    done

    CFLAGS="$ax_tls_save_CFLAGS"
  ])

  AC_CACHE_CHECK([for thread-local storage emulation], [ax_cv_tls_emulated], [
    ax_cv_tls_emulated=no

    # See above for code rationale.
    echo "$ax_cv_tls_keyword int x;" > conftest.c
    echo 'int main(void) { x = 1; return !x; }' >> conftest.c

    AS_IF([${CC-cc} -S -o conftest.s conftest.c $ax_cv_tls_cflags > /dev/null 2>& 1], [
      # There is evidence that some non-GNU platforms also do TLS
      # emulation. It's possible this includes 32-bit AIX, but I
      # cannot confirm this.
      #
      # TODO: Find other platforms with emulated TLS and figure
      #       out how to detect it.
      AS_IF([grep __emutls_get_address conftest.s > /dev/null 2>& 1],
            [ax_cv_tls_emulated=yes])
    ])

    rm -f conftest.c
    rm -f conftest.s
  ])

  # Define symbols a la the more widely used ax_tls.m4.
  AS_IF([test x"$ax_cv_tls_keyword" != x'none'], [
    AC_DEFINE_UNQUOTED([TLS], [$ax_cv_tls_keyword], [Define TLS keyword])

    AS_IF([test x"$ax_cv_tls_emulated" = x'yes'], [
      AC_DEFINE([TLS_EMULATED], [1], [Define if TLS is emulated])
    ])

    AC_SUBST([TLS_CFLAGS], ["$ax_cv_tls_cflags"])

    $1
  ], [
    AC_SUBST([TLS_CFLAGS], [''])

    $2
  ])
])
