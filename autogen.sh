#!/bin/sh

# autogen.sh - autotools generation script
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/libtorsion

# A poor man's `autoreconf -if -Wall`.
set -e

if ! test -f configure.ac; then
  echo 'configure.ac not found.' >& 2
  exit 1
fi

ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}

if glibtoolize --version > /dev/null 2>& 1; then
  LIBTOOLIZE=${LIBTOOLIZE:-glibtoolize}
else
  LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}
fi

export WARNINGS=all

"$ACLOCAL" --force -I m4

if ! test -d build-aux; then
  mkdir build-aux
fi

"$LIBTOOLIZE" --copy --force
"$ACLOCAL" --force -I m4
"$AUTOCONF" --force
"$AUTOMAKE" --add-missing --copy --force-missing
