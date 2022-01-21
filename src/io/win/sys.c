/*!
 * sys.c - system functions for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shlobj.h>
#include <io/core.h>

#ifndef __MINGW32__
#  pragma comment(lib, "shell32.lib")
#endif

/*
 * System
 */

int
btc_sys_numcpu(void) {
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  return info.dwNumberOfProcessors;
}

int
btc_sys_homedir(char *buf, size_t size) {
  DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, size);
  return len > 0 && len < size;
}

int
btc_sys_datadir(char *buf, size_t size, const char *name) {
  char path[MAX_PATH];

  memset(path, 0, sizeof(path));

  if (!SHGetSpecialFolderPathA(NULL, path, CSIDL_APPDATA, FALSE)) {
    if (!btc_sys_homedir(path, sizeof(path)))
      return 0;
  }

  if (strlen(path) + strlen(name) + 2 > size)
    return 0;

  sprintf(buf, "%s\\%c%s", path, name[0] & ~32, name + 1);

  return 1;
}
