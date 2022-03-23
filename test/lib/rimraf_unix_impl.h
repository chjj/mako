/*!
 * rimraf_unix_impl.h - rm -rf for c
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include "tests.h"

#if !defined(FD_SETSIZE) && !defined(FD_SET)
#  include <sys/select.h>
#endif

/*
 * Helpers
 */

static int
btc_scandir(const char *path, char ***out) {
  struct dirent *entry;
  char **list = NULL;
  char *name = NULL;
  DIR *dir = NULL;
  size_t size = 8;
  size_t i = 0;
  size_t j, len;

  list = (char **)malloc(size * sizeof(char *));

  if (list == NULL)
    goto fail;

  dir = opendir(path);

  if (dir == NULL)
    goto fail;

  for (;;) {
    errno = 0;
    entry = readdir(dir);

    if (entry == NULL) {
      if (errno != 0)
        goto fail;
      break;
    }

    len = strlen(entry->d_name);
    name = (char *)malloc(len + 1);

    if (name == NULL)
      goto fail;

    memcpy(name, entry->d_name, len + 1);

    if (i == size) {
      size = (size * 3) / 2;
      list = (char **)realloc(list, size * sizeof(char *));

      if (list == NULL)
        goto fail;
    }

    list[i++] = name;
    name = NULL;
  }

  closedir(dir);

  *out = list;

  return i;
fail:
  for (j = 0; j < i; j++)
    free(list[j]);

  if (list != NULL)
    free(list);

  if (name != NULL)
    free(name);

  if (dir != NULL)
    closedir(dir);

  *out = NULL;

  return -1;
}

static void
btc_freedir(char **list, int len) {
  int i;

  for (i = 0; i < len; i++)
    free(list[i]);

  free(list);
}

static void
btc_sleep(int msec) {
  struct timeval tv;

  memset(&tv, 0, sizeof(tv));

  if (msec <= 0) {
    tv.tv_usec = 1;
  } else {
    tv.tv_sec = msec / 1000;
    tv.tv_usec = (msec % 1000) * 1000;
  }

  select(0, NULL, NULL, NULL, &tv);
}

/*
 * Removal
 */

static int
btc_remove(char *path, int plen) {
  struct stat st;
  char **list;
  int i;

  if (lstat(path, &st) < 0) {
    if (errno == ENOENT)
      return 0;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    int len = btc_scandir(path, &list);

    if (len < 0) {
      if (errno == ENOENT)
        return 0;
      return -1;
    }

    for (i = 0; i < len; i++) {
      char *name = list[i];
      char *ptr = path + plen;

      if (strcmp(name, ".") == 0)
        continue;

      if (strcmp(name, "..") == 0)
        continue;

      if (plen + strlen(name) + 2 > 4096) {
        btc_freedir(list, len);
        errno = ERANGE;
        return -1;
      }

      *ptr++ = '/';

      while (*name)
        *ptr++ = *name++;

      *ptr = '\0';

      if (btc_remove(path, ptr - path) < 0) {
        btc_freedir(list, len);
        path[plen] = '\0';
        return -1;
      }

      path[plen] = '\0';
    }

    btc_freedir(list, len);

    if (rmdir(path) < 0) {
      if (errno == ENOENT)
        return 0;
      return -1;
    }

    return 0;
  }

  if (unlink(path) < 0) {
    if (errno == ENOENT)
      return 0;
    return -1;
  }

  return 0;
}

int
btc_rimraf(const char *path) {
  size_t len = strlen(path);
  char tmp[4096];
  int tries = 0;

  if (len + 1 > sizeof(tmp)) {
    errno = ERANGE;
    return -1;
  }

  memcpy(tmp, path, len + 1);

  if (len == 0) {
    tmp[0] = '.';
    tmp[1] = '\0';
    len = 1;
  }

  while (btc_remove(tmp, len) < 0) {
    switch (errno) {
      case EBUSY:
      case ENOTEMPTY:
      case EPERM:
#if ENFILE != EMFILE
      case ENFILE:
#endif
      case EMFILE:
        if (tries++ < 3) {
          btc_sleep(tries * 100);
          continue;
        }
        break;
    }
    return -1;
  }

  return 0;
}
