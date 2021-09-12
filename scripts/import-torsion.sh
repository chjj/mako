#!/bin/bash

set -ex

type rsync > /dev/null 2>& 1
test $# -eq 1
test ! -z "$1"

prefix="$1"

test -d deps
test -d "$prefix"
test -d "$prefix/cmake"
test -d "$prefix/include"
test -d "$prefix/src"

if test ! -d deps/torsion; then
  mkdir deps/torsion
fi

if test ! -d deps/torsion/cmake; then
  mkdir deps/torsion/cmake
fi

if test ! -d deps/torsion/include; then
  mkdir deps/torsion/include
fi

if test ! -d deps/torsion/src; then
  mkdir deps/torsion/src
fi

cp -f "$prefix/CMakeLists.txt" deps/torsion/
cp -f "$prefix/LICENSE" deps/torsion/

rsync -av "$prefix/cmake/" deps/torsion/cmake/
rsync -av "$prefix/include/" deps/torsion/include/

rsync -av --exclude '*.o' \
          --exclude '*.lo' \
          --exclude '.deps' \
          --exclude '.dirstamp' \
          --exclude '.libs' \
          --exclude '*.md' \
          "$prefix/src/" deps/torsion/src/
