/*!
 * rimraf_win_impl.h - rm -rf for c
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj
 */

#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "tests.h"

/*
 * Removal (Wide)
 */

static WCHAR *
btc_basename_wide(const WCHAR *name) {
  size_t len = lstrlenW(name);

  while (len > 0) {
    if (name[len - 1] == L'/' || name[len - 1] == L'\\')
      break;

    len--;
  }

  return (WCHAR *)name + len;
}

static int
btc_remove_wide(WCHAR *path, int plen) {
  DWORD attrs = GetFileAttributesW(path);

  if (attrs == INVALID_FILE_ATTRIBUTES) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
      return 0;
    return -1;
  }

  if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
    HANDLE handle = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW fdata;
    int tries = 0;

    if (plen + 3 > 4096) {
      SetLastError(ERROR_BUFFER_OVERFLOW);
      return -1;
    }

    if (path[plen - 1] == L'\\' || path[plen - 1] == L'/') {
      path[plen + 0] = L'*';
      path[plen + 1] = L'\0';
    } else {
      path[plen + 0] = L'\\';
      path[plen + 1] = L'*';
      path[plen + 2] = L'\0';
    }

    handle = FindFirstFileW(path, &fdata);
    path[plen] = L'\0';

    if (handle == INVALID_HANDLE_VALUE) {
      if (GetLastError() == ERROR_FILE_NOT_FOUND)
        return 0;
      return -1;
    }

    do {
      WCHAR *name = btc_basename_wide(fdata.cFileName);
      WCHAR *ptr = path + plen;

      if (lstrcmpW(name, L".") == 0)
        continue;

      if (lstrcmpW(name, L"..") == 0)
        continue;

      if (plen + lstrlenW(name) + 2 > 4096) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        FindClose(handle);
        return -1;
      }

      *ptr++ = L'/';

      while (*name)
        *ptr++ = *name++;

      *ptr = L'\0';

      if (btc_remove_wide(path, ptr - path) < 0) {
        FindClose(handle);
        path[plen] = L'\0';
        return -1;
      }

      path[plen] = L'\0';
    } while (FindNextFileW(handle, &fdata));

    if (GetLastError() != ERROR_NO_MORE_FILES) {
      FindClose(handle);
      return -1;
    }

    FindClose(handle);

    while (!RemoveDirectoryW(path)) {
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
    SetFileAttributesW(path, attrs & ~FILE_ATTRIBUTE_READONLY);

  if (!DeleteFileW(path)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
      return 0;
    return -1;
  }

  return 0;
}

static int
btc_rimraf_wide(const char *path) {
  WCHAR *tmp = malloc(4096 * sizeof(WCHAR));
  int tries = 0;
  int len;

  if (tmp == NULL) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return -1;
  }

  len = MultiByteToWideChar(CP_UTF8, 0, path, -1, tmp, 4096);

  if (len <= 0) {
    free(tmp);
    return -1;
  }

  len--;

  if (len == 0) {
    tmp[0] = L'.';
    tmp[1] = L'\0';
    len = 1;
  }

  while (btc_remove_wide(tmp, len) < 0) {
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

    free(tmp);

    return -1;
  }

  free(tmp);

  return 0;
}

/*
 * Removal (ANSI)
 */

static char *
btc_basename_ansi(const char *name) {
  size_t len = strlen(name);

  while (len > 0) {
    if (name[len - 1] == '/' || name[len - 1] == '\\')
      break;

    len--;
  }

  return (char *)name + len;
}

static int
btc_remove_ansi(char *path, int plen) {
  DWORD attrs = GetFileAttributesA(path);

  if (attrs == INVALID_FILE_ATTRIBUTES) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
      return 0;
    return -1;
  }

  if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
    HANDLE handle = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAA fdata;
    int tries = 0;

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
      char *name = btc_basename_ansi(fdata.cFileName);
      char *ptr = path + plen;

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

      if (btc_remove_ansi(path, ptr - path) < 0) {
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
    SetFileAttributesA(path, attrs & ~FILE_ATTRIBUTE_READONLY);

  if (!DeleteFileA(path)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
      return 0;
    return -1;
  }

  return 0;
}

static int
btc_rimraf_ansi(const char *path) {
  size_t len = strlen(path);
  char tmp[4096];
  int tries = 0;

  if (len + 1 > sizeof(tmp)) {
    SetLastError(ERROR_BUFFER_OVERFLOW);
    return -1;
  }

  memcpy(tmp, path, len + 1);

  if (len == 0) {
    tmp[0] = '.';
    tmp[1] = '\0';
    len = 1;
  }

  while (btc_remove_ansi(tmp, len) < 0) {
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

int
btc_rimraf(const char *path) {
  if (GetVersion() < 0x80000000)
    return btc_rimraf_wide(path);

  return btc_rimraf_ansi(path);
}
