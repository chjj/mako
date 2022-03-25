#!/bin/sh

set -ex

type rsync > /dev/null 2>& 1
test $# -eq 1
test ! -z "$1"

prefix="$1"

test -f include/mako/bip39.h
test -f "$prefix/include/lcdb_c.h"

if test ! -d deps/lcdb; then
  mkdir deps/lcdb
fi

if test ! -d deps/lcdb/cmake; then
  mkdir deps/lcdb/cmake
fi

if test ! -d deps/lcdb/contrib; then
  mkdir deps/lcdb/contrib
fi

if test ! -d deps/lcdb/include; then
  mkdir deps/lcdb/include
fi

if test ! -d deps/lcdb/src; then
  mkdir deps/lcdb/src
fi

cp -f "$prefix/.gitignore" deps/lcdb/
cp -f "$prefix/CMakeLists.txt" deps/lcdb/
cp -f "$prefix/contrib/Makefile.am" deps/lcdb/
cp -f "$prefix/LICENSE" deps/lcdb/
cp -f "$prefix/README.md" deps/lcdb/

rsync -av "$prefix/cmake/" deps/lcdb/cmake/
rsync -av "$prefix/contrib/" deps/lcdb/contrib/
rsync -av "$prefix/include/" deps/lcdb/include/

rsync -av --exclude '*.o'         \
          --exclude '*.lo'        \
          --exclude '.deps'       \
          --exclude '.dirstamp'   \
          --exclude '.libs'       \
          --exclude '*.md'        \
          --exclude '*_test.c'    \
          --exclude '*_data.h'    \
          --exclude 'dbutil.c'    \
          --exclude 'histogram.*' \
          --exclude 'testutil.*'  \
          "$prefix/src/"          \
          deps/lcdb/src/

rm -f deps/lcdb/contrib/Makefile.am
