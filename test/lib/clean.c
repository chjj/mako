/*!
 * clean.c - datadir cleaner for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <io/core.h>
#include "tests.h"

static int
btc_rmdir_r(const char *path) {
  char file[BTC_PATH_MAX + 1];
  btc_dirent_t **list;
  size_t i, count;
  int ret = 1;

  if (!btc_fs_scandir(path, &list, &count))
    return 0;

  for (i = 0; i < count; i++) {
    const char *name = list[i]->d_name;

    btc_path_join(file, path, name, 0);

    ret &= btc_fs_unlink(file);

    free(list[i]);
  }

  free(list);

  ret &= btc_fs_rmdir(path);

  return ret;
}

int
btc_clean(const char *prefix) {
  char path[BTC_PATH_MAX + 1];
  int ret = 1;

  btc_path_join(path, prefix, "blocks", 0);

  ret &= btc_rmdir_r(path);

  btc_path_join(path, prefix, "chain", 0);

  ret &= btc_rmdir_r(path);

  btc_path_join(path, prefix, "debug.log", 0);

  ret &= btc_fs_unlink(path);
  ret &= btc_fs_rmdir(prefix);

  return ret;
}
