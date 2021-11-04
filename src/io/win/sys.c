/*!
 * sys.c - system functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shlobj.h>
#include <userenv.h>
#include <io/core.h>

#ifndef __MINGW32__
#  pragma comment(lib, "shell32.lib")
#  pragma comment(lib, "userenv.lib")
#endif

/*
 * System
 */

int
btc_sys_cpu_count(void) {
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  return info.dwNumberOfProcessors;
}

int
btc_sys_homedir(char *out, size_t size) {
  DWORD len = GetEnvironmentVariableA("USERPROFILE", out, size);
  HANDLE token;

  if (len >= size)
    return 0;

  if (len != 0)
    return 1;

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token) == 0)
    return 0;

  len = size;

  return GetUserProfileDirectoryA(token, out, &len) == TRUE;
}

int
btc_sys_datadir(char *out, size_t size, const char *name) {
  char path[MAX_PATH];

  memset(path, 0, sizeof(path));

#if defined(CSIDL_APPDATA)
  if (!SHGetSpecialFolderPathA(NULL, path, CSIDL_APPDATA, FALSE)) {
    if (!btc_sys_homedir(path, sizeof(path)))
      return 0;
  }
#else
  if (!btc_sys_homedir(path, sizeof(path)))
    return 0;
#endif

  if (strlen(path) + strlen(name) + 2 > size)
    return 0;

  sprintf(out, "%s\\%c%s", path, name[0] & ~32, name + 1);

  return 1;
}
