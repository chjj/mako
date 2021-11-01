/*!
 * sys.c - system functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <windows.h>
#include <userenv.h>
#include <io/core.h>

#ifndef __MINGW32__
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
