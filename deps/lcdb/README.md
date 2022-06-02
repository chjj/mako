# lcdb

_DISCLAIMER: lcdb has **no** affiliation with or endorsement from Google Inc.
whatsoever despite the API prefix being `ldb_` (let's hope they don't [cease
and desist][cad] us again)._

A state-of-the-art database in C89 (originally designed by Jeffrey Dean and
Sanjay Ghemawat and [implemented in C++][ldb]).

## Background

[LevelDB][ldb] was _painstakingly_ ported from C++ to C89¹ for use with [mako].
_mako_ is a C project which requires an LSM tree for its UTXO database (which
in turn requires high write throughput with very effective compaction). _mako_
has a strict development policy of "do not link to libstdc++" and "do not
require a c++ compiler".

LevelDB is used by many bitcoin implementations for indexing the UTXO state.
After experimenting with various databases written in C, it was clear that
LevelDB was still the obvious choice, despite it being written in C++. Existing
databases written in C weren't cutting it in terms of performance (in some
cases maybe they were, but instead lacked effective compaction).

_mako_'s strict policy of portability plus the lack of a production-ready LSM
tree written in C ultimately led to the creation of _lcdb_.

1. Note that the platform (or user) must still provide a working `<stdint.h>`
as a build dependency.

### Portability

Portability is one of _lcdb_'s primary goals. _lcdb_ is written in such a way
that it should be usable on Windows 9x¹ as well as unices which predate
POSIX.1-2001.

Portability to this degree was achieved by sifting through copies of MSDN from
the '90s, as well as examining header files from old unix releases to see which
system calls were truly² available in practice.

_lcdb_ also offers the option to build without pthread support (with compaction
taking place on the main thread).

1. Unfortunately, kernel32.dll on Windows 9x does not provide `MoveFileEx`
which is necessary for atomic renames. This means _lcdb_ will be more prone to
recovery errors on Windows 95/98/ME.

2. A good example of the incongruence between standards and implementation is
`fdatasync(2)` and `pread(2)`. Both of them are X/Open extensions from the '90s
and are also specified in the first version of SUS. In spite of this, some
conforming OSes only began providing them in the last decade (in some cases the
past 5 years or so).

### Cross Compilation

Due to its portability, _lcdb_ is well-suited for common cross-compilation
environments like mingw and wasi-sdk.

This repo includes some helper scripts for both mingw and wasi.

Building with mingw:

``` sh
$ ./scripts/mingw-cmake cmake . -DCMAKE_BUILD_TYPE=Release
$ make
```

Building with wasi-sdk:

``` sh
$ ./scripts/wasi-cmake cmake . -DCMAKE_BUILD_TYPE=Release
$ make
```

## More Disclaimers & License Info

Despite being written in another language, _lcdb_'s codebase is largely
derivative of LevelDB's. As such, the LevelDB license must be shipped (and
conformed to) with the distribution of lcdb in every form.

_lcdb_ is still very immature and is not yet battle-hardened like LevelDB. It
will also likely be subject to breaking ABI changes in the near future. Use at
your own risk.

## Usage

The API tries to mimic the C++ API as much as it can. Users of LevelDB should
find it familiar.

Example:

``` c
#include <assert.h>
#include <lcdb.h>

int main(void) {
  ldb_dbopt_t opt = *ldb_dbopt_default;
  ldb_slice_t key, val, ret;
  ldb_t *db;
  int rc;

  opt.create_if_missing = 1;

  rc = ldb_open("tmp", &opt, &db);

  assert(rc == LDB_OK);

  key = ldb_string("hello");
  val = ldb_string("world");

  rc = ldb_put(db, &key, &val, 0);

  assert(rc == LDB_OK);

  rc = ldb_get(db, &key, &ret, 0);

  assert(rc == LDB_OK);
  assert(ldb_compare(db, &ret, &val) == 0);

  ldb_free(ret.data);
  ldb_close(db);

  return 0;
}
```

Build with:

``` sh
$ cc -o example example.c -llcdb
```

Or:

``` sh
$ cc -o example -I./include example.c liblcdb.a -lpthread
```

See the [header file][h] for more information.

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2022, Christopher Jeffrey (MIT License).

Parts of this software are based on [google/leveldb][ldb]:

- Copyright (c) 2011, The LevelDB Authors. All rights reserved.

Parts of this software are based on [google/crc32c][crc32c]:

- Copyright (c) 2017, The CRC32C Authors.

Parts of this software are based on [golang/snappy][snappy]:

- Copyright (c) 2011 The Snappy-Go Authors. All rights reserved.

See [LICENSE] for more info.

[cad]: https://github.com/Level/community/issues/66
[ldb]: https://github.com/google/leveldb
[h]: https://github.com/chjj/lcdb/blob/master/include/lcdb.h
[crc32c]: https://github.com/google/crc32c
[snappy]: https://github.com/golang/snappy
[mako]: https://github.com/chjj/mako
[LICENSE]: https://github.com/chjj/lcdb/blob/master/LICENSE
