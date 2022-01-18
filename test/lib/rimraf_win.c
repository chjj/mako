/*!
 * rimraf.c - rm -rf for c
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj
 */

#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "tests.h"

/*
 * Removal
 */

static int
btc_remove(char *path, int plen) {
  DWORD attrs = GetFileAttributesA(path);

  if (attrs == INVALID_FILE_ATTRIBUTES) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
      return 0;
    return -1;
  }

  if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
    HANDLE handle = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAA fdata;

    if (plen + 3 > 4096) {
      SetLastError(ERROR_BUFFER_OVERFLOW);
      return -1;
    }

    if (path[plen - 1] == '\\' || path[plen - 1] == '/') {
      path[plen + 0] = '*';
      path[plen + 1] = '\0';
    } else {
      path[plen + 0] = '\\';
      path[plen + 1] = '*';
      path[plen + 2] = '\0';
    }

    handle = FindFirstFileA(path, &fdata);
    path[plen] = '\0';

    if (handle == INVALID_HANDLE_VALUE) {
      if (GetLastError() == ERROR_FILE_NOT_FOUND)
        return 0;
      return -1;
    }

    do {
      char *name = fdata.cFileName;
      char *ptr = path + plen;
      int tries = 0;

      if (strcmp(name, ".") == 0)
        continue;

      if (strcmp(name, "..") == 0)
        continue;

      if (plen + strlen(name) + 2 > 4096) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        FindClose(handle);
        return -1;
      }

      *ptr++ = '/';

      while (*name)
        *ptr++ = *name++;

      *ptr = '\0';

      if (btc_remove(path, ptr - path) < 0) {
        FindClose(handle);
        path[plen] = '\0';
        return -1;
      }

      path[plen] = '\0';
    } while (FindNextFileA(handle, &fdata));

    if (GetLastError() != ERROR_NO_MORE_FILES) {
      FindClose(handle);
      return -1;
    }

    FindClose(handle);

    while (!RemoveDirectoryA(path)) {
      if (GetLastError() == ERROR_FILE_NOT_FOUND)
        return 0;

      if (GetLastError() == ERROR_DIR_NOT_EMPTY) {
        if (tries++ < 4) {
          Sleep(1);
          continue;
        }
      }

      return -1;
    }

    return 0;
  }

  if (attrs & FILE_ATTRIBUTE_READONLY)
    SetFileAttributesA(name, attrs & ~FILE_ATTRIBUTE_READONLY);

  if (!DeleteFileA(path)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
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
    SetLastError(ERROR_BUFFER_OVERFLOW);
    return -1;
  }

  memcpy(tmp, path, len + 1);

  if (len == 0) {
    tmp[len++] = '.';
    tmp[len] = '\0';
  }

  while (btc_remove(tmp, len) < 0) {
    switch (GetLastError()) {
      case ERROR_PATH_BUSY:
      case ERROR_BUSY:
      case ERROR_DIR_NOT_EMPTY:
      case ERROR_ACCESS_DENIED:
      case ERROR_TOO_MANY_OPEN_FILES:
        if (tries++ < 3) {
          Sleep(tries * 100);
          continue;
        }
        break;
    }
    return -1;
  }

  return 0;
}
