/*!
 * filename.c - filename utilities for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util/env.h"
#include "util/slice.h"
#include "util/status.h"
#include "util/strutil.h"

#include "filename.h"

/*
 * Helpers
 */

static int
make_filename(char *buf,
              size_t size,
              const char *prefix,
              uint64_t num,
              const char *ext) {
  char tmp[128];
  char id[32];

  ldb_encode_int(id, num, 6);

  sprintf(tmp, "%s.%s", id, ext);

  return ldb_join(buf, size, prefix, tmp);
}

/*
 * Filename
 */

int
ldb_log_filename(char *buf, size_t size, const char *prefix, uint64_t num) {
  assert(num > 0);
  return make_filename(buf, size, prefix, num, "log");
}

int
ldb_table_filename(char *buf, size_t size, const char *prefix, uint64_t num) {
  assert(num > 0);
  return make_filename(buf, size, prefix, num, "ldb");
}

int
ldb_sstable_filename(char *buf, size_t size, const char *prefix, uint64_t num) {
  assert(num > 0);
  return make_filename(buf, size, prefix, num, "sst");
}

int
ldb_desc_filename(char *buf, size_t size, const char *prefix, uint64_t num) {
  char tmp[128];
  char id[32];

  assert(num > 0);

  ldb_encode_int(id, num, 6);

  sprintf(tmp, "MANIFEST-%s", id);

  return ldb_join(buf, size, prefix, tmp);
}

int
ldb_current_filename(char *buf, size_t size, const char *prefix) {
  return ldb_join(buf, size, prefix, "CURRENT");
}

int
ldb_lock_filename(char *buf, size_t size, const char *prefix) {
  return ldb_join(buf, size, prefix, "LOCK");
}

int
ldb_temp_filename(char *buf, size_t size, const char *prefix, uint64_t num) {
  assert(num > 0);
  return make_filename(buf, size, prefix, num, "dbtmp");
}

int
ldb_info_filename(char *buf, size_t size, const char *prefix) {
  return ldb_join(buf, size, prefix, "LOG");
}

int
ldb_oldinfo_filename(char *buf, size_t size, const char *prefix) {
  return ldb_join(buf, size, prefix, "LOG.old");
}

/* Owned filenames have the form:
 *    dbname/CURRENT
 *    dbname/LOCK
 *    dbname/LOG
 *    dbname/LOG.old
 *    dbname/MANIFEST-[0-9]+
 *    dbname/[0-9]+.(log|sst|ldb)
 */
int
ldb_parse_filename(ldb_filetype_t *type, uint64_t *num, const char *name) {
  uint64_t x;

  if (strcmp(name, "CURRENT") == 0) {
    *type = LDB_FILE_CURRENT;
    *num = 0;
  } else if (strcmp(name, "LOCK") == 0) {
    *type = LDB_FILE_LOCK;
    *num = 0;
  } else if (strcmp(name, "LOG") == 0 || strcmp(name, "LOG.old") == 0) {
    *type = LDB_FILE_INFO;
    *num = 0;
  } else if (ldb_starts_with(name, "MANIFEST-")) {
    name += 9;

    if (!ldb_decode_int(&x, &name))
      return 0;

    if (*name != '\0')
      return 0;

    *type = LDB_FILE_DESC;
    *num = x;
  } else if (ldb_decode_int(&x, &name)) {
    if (strcmp(name, ".log") == 0)
      *type = LDB_FILE_LOG;
    else if (strcmp(name, ".sst") == 0 || strcmp(name, ".ldb") == 0)
      *type = LDB_FILE_TABLE;
    else if (strcmp(name, ".dbtmp") == 0)
      *type = LDB_FILE_TEMP;
    else
      return 0;

    *num = x;
  } else {
    return 0;
  }

  return 1;
}

int
ldb_set_current_file(const char *prefix, uint64_t desc_number) {
  char cur[LDB_PATH_MAX];
  char tmp[LDB_PATH_MAX];
  ldb_slice_t data;
  char man[128];
  char id[32];
  int rc;

  assert(desc_number > 0);

  if (!ldb_temp_filename(tmp, sizeof(tmp), prefix, desc_number))
    return LDB_INVALID;

  if (!ldb_current_filename(cur, sizeof(cur), prefix))
    return LDB_INVALID;

  ldb_encode_int(id, desc_number, 6);

  sprintf(man, "MANIFEST-%s\n", id);

  ldb_slice_set_str(&data, man);

  rc = ldb_write_file(tmp, &data, 1);

  if (rc == LDB_OK)
    rc = ldb_rename_file(tmp, cur);

  if (rc != LDB_OK)
    ldb_remove_file(tmp);

  return rc;
}
