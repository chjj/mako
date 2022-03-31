# ax_c_bigendian.m4 - endianness test for autoconf
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj
#
# SYNOPSIS
#
#   AX_C_BIGENDIAN([action-if-found], [action-if-not-found])
#
# DESCRIPTION
#
#   Borrow a trick from cmake for a better endianness check.

AC_DEFUN([AX_C_BIGENDIAN], [
  AC_CACHE_CHECK([for big endian], [ax_cv_endian_big], [
    ax_cv_endian_big=no
    ax_cv_endian_lit=no

    AC_LANG_CONFTEST([
      AC_LANG_SOURCE([[
        const unsigned short info_big[] = {0x5448, 0x4953, 0x2049, 0x5320,
                                           0x4249, 0x4720, 0x454e, 0x4449,
                                           0x414e, 0x2e2e, 0x0000};
        const unsigned short info_lit[] = {0x4854, 0x5349, 0x4920, 0x2053,
                                           0x494c, 0x5454, 0x454c, 0x4520,
                                           0x444e, 0x4149, 0x2e4e, 0x0000};

        int main(int argc, char **argv) {
          int require = 0;
          require += info_big[argc];
          require += info_lit[argc];
          (void)argv;
          return require;
        }
      ]])
    ])

    AS_IF([${CC-cc} -o conftest$ac_exeext conftest.$ac_ext > /dev/null 2>& 1], [
      AS_IF([grep 'THIS IS BIG ENDIAN' conftest > /dev/null 2>& 1],
            [ax_cv_endian_big=yes])
      AS_IF([grep 'THIS IS LITTLE ENDIAN' conftest > /dev/null 2>& 1],
            [ax_cv_endian_lit=yes])
    ])

    rm -f conftest.$ac_ext
    rm -f conftest$ac_exeext

    # Handle apple universal endianness.
    AS_IF([test x"$ax_cv_endian_big$ax_cv_endian_lit" = x'yesyes'], [
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[]], [[
#         if !(defined(__powerpc__) || defined(__ppc__) || defined(__PPC__))
            choke me
#         endif
        ]])
      ], [
        ax_cv_endian_big=yes
        ax_cv_endian_lit=no
      ], [
        ax_cv_endian_big=no
        ax_cv_endian_lit=yes
      ])
    ])
  ])

  AS_IF([test x"$ax_cv_endian_big$ax_cv_endian_lit" = x'nono'], [$3], [
    AS_IF([test x"$ax_cv_endian_big" = x'yes'], [$1], [$2])
  ])
])
