# Makefile.am - automake file for lcdb
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/lcdb

EXTRA_DIST = CMakeLists.txt LICENSE README.md

liblcdb_la_SOURCES = include/lcdb.h                 \
                     include/lcdb_c.h               \
                     src/util/arena.c               \
                     src/util/arena.h               \
                     src/util/array.c               \
                     src/util/array.h               \
                     src/util/atomic.c              \
                     src/util/atomic.h              \
                     src/util/bloom.c               \
                     src/util/bloom.h               \
                     src/util/buffer.c              \
                     src/util/buffer.h              \
                     src/util/cache.c               \
                     src/util/cache.h               \
                     src/util/coding.h              \
                     src/util/comparator.c          \
                     src/util/comparator.h          \
                     src/util/crc32c.c              \
                     src/util/crc32c.h              \
                     src/util/env.c                 \
                     src/util/env.h                 \
                     src/util/env_mem_impl.h        \
                     src/util/env_unix_impl.h       \
                     src/util/env_win_impl.h        \
                     src/util/extern.h              \
                     src/util/hash.c                \
                     src/util/hash.h                \
                     src/util/internal.c            \
                     src/util/internal.h            \
                     src/util/logger.c              \
                     src/util/options.c             \
                     src/util/options.h             \
                     src/util/port.c                \
                     src/util/port.h                \
                     src/util/port_none_impl.h      \
                     src/util/port_unix_impl.h      \
                     src/util/port_win_impl.h       \
                     src/util/random.c              \
                     src/util/random.h              \
                     src/util/rbt.c                 \
                     src/util/rbt.h                 \
                     src/util/slice.c               \
                     src/util/slice.h               \
                     src/util/snappy.c              \
                     src/util/snappy.h              \
                     src/util/status.c              \
                     src/util/status.h              \
                     src/util/strutil.c             \
                     src/util/strutil.h             \
                     src/util/thread_pool.c         \
                     src/util/thread_pool.h         \
                     src/util/types.h               \
                     src/util/vector.c              \
                     src/util/vector.h              \
                     src/table/block.c              \
                     src/table/block.h              \
                     src/table/block_builder.c      \
                     src/table/block_builder.h      \
                     src/table/filter_block.c       \
                     src/table/filter_block.h       \
                     src/table/format.c             \
                     src/table/format.h             \
                     src/table/iterator.c           \
                     src/table/iterator.h           \
                     src/table/iterator_wrapper.h   \
                     src/table/merger.c             \
                     src/table/merger.h             \
                     src/table/table.c              \
                     src/table/table.h              \
                     src/table/table_builder.c      \
                     src/table/table_builder.h      \
                     src/table/two_level_iterator.c \
                     src/table/two_level_iterator.h \
                     src/builder.c                  \
                     src/builder.h                  \
                     src/c.c                        \
                     src/db_impl.c                  \
                     src/db_impl.h                  \
                     src/db_iter.c                  \
                     src/db_iter.h                  \
                     src/dbformat.c                 \
                     src/dbformat.h                 \
                     src/dumpfile.c                 \
                     src/dumpfile.h                 \
                     src/filename.c                 \
                     src/filename.h                 \
                     src/log_format.h               \
                     src/log_reader.c               \
                     src/log_reader.h               \
                     src/log_writer.c               \
                     src/log_writer.h               \
                     src/memtable.c                 \
                     src/memtable.h                 \
                     src/repair.c                   \
                     src/skiplist.c                 \
                     src/skiplist.h                 \
                     src/snapshot.h                 \
                     src/table_cache.c              \
                     src/table_cache.h              \
                     src/version_edit.c             \
                     src/version_edit.h             \
                     src/version_set.c              \
                     src/version_set.h              \
                     src/write_batch.c              \
                     src/write_batch.h

liblcdb_la_CFLAGS = -I$(srcdir)/include
liblcdb_la_LDFLAGS = -static

noinst_LTLIBRARIES = liblcdb.la
