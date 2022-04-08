# Makefile.am - automake file for lcdb
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/lcdb

#
# Headers
#

lcdb_headers = include/lcdb.h                 \
               include/lcdb_c.h               \
               src/util/arena.h               \
               src/util/array.h               \
               src/util/atomic.h              \
               src/util/bloom.h               \
               src/util/buffer.h              \
               src/util/cache.h               \
               src/util/coding.h              \
               src/util/comparator.h          \
               src/util/crc32c.h              \
               src/util/env.h                 \
               src/util/env_mem_impl.h        \
               src/util/env_unix_impl.h       \
               src/util/env_win_impl.h        \
               src/util/extern.h              \
               src/util/hash.h                \
               src/util/internal.h            \
               src/util/options.h             \
               src/util/port.h                \
               src/util/port_none_impl.h      \
               src/util/port_unix_impl.h      \
               src/util/port_win_impl.h       \
               src/util/random.h              \
               src/util/rbt.h                 \
               src/util/slice.h               \
               src/util/snappy.h              \
               src/util/status.h              \
               src/util/strutil.h             \
               src/util/thread_pool.h         \
               src/util/types.h               \
               src/util/vector.h              \
               src/table/block.h              \
               src/table/block_builder.h      \
               src/table/filter_block.h       \
               src/table/format.h             \
               src/table/iterator.h           \
               src/table/iterator_wrapper.h   \
               src/table/merger.h             \
               src/table/table.h              \
               src/table/table_builder.h      \
               src/table/two_level_iterator.h \
               src/builder.h                  \
               src/db_impl.h                  \
               src/db_iter.h                  \
               src/dbformat.h                 \
               src/dumpfile.h                 \
               src/filename.h                 \
               src/log_format.h               \
               src/log_reader.h               \
               src/log_writer.h               \
               src/memtable.h                 \
               src/skiplist.h                 \
               src/snapshot.h                 \
               src/table_cache.h              \
               src/version_edit.h             \
               src/version_set.h              \
               src/write_batch.h

#
# Sources
#

lcdb_sources = src/util/arena.c               \
               src/util/array.c               \
               src/util/atomic.c              \
               src/util/bloom.c               \
               src/util/buffer.c              \
               src/util/cache.c               \
               src/util/comparator.c          \
               src/util/crc32c.c              \
               src/util/env.c                 \
               src/util/hash.c                \
               src/util/internal.c            \
               src/util/logger.c              \
               src/util/options.c             \
               src/util/port.c                \
               src/util/random.c              \
               src/util/rbt.c                 \
               src/util/slice.c               \
               src/util/snappy.c              \
               src/util/status.c              \
               src/util/strutil.c             \
               src/util/thread_pool.c         \
               src/util/vector.c              \
               src/table/block.c              \
               src/table/block_builder.c      \
               src/table/filter_block.c       \
               src/table/format.c             \
               src/table/iterator.c           \
               src/table/merger.c             \
               src/table/table.c              \
               src/table/table_builder.c      \
               src/table/two_level_iterator.c \
               src/builder.c                  \
               src/c.c                        \
               src/db_impl.c                  \
               src/db_iter.c                  \
               src/dbformat.c                 \
               src/dumpfile.c                 \
               src/filename.c                 \
               src/log_reader.c               \
               src/log_writer.c               \
               src/memtable.c                 \
               src/repair.c                   \
               src/skiplist.c                 \
               src/table_cache.c              \
               src/version_edit.c             \
               src/version_set.c              \
               src/write_batch.c

#
# Targets
#

liblcdb_la_SOURCES = $(lcdb_headers) $(lcdb_sources)
liblcdb_la_CFLAGS = $(WARN_FLAGS) -I$(srcdir)/include
liblcdb_la_LDFLAGS = -static

noinst_LTLIBRARIES = liblcdb.la
