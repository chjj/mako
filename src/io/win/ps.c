/*!
 * ps.c - process functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <windows.h>
#include <io/core.h>

/*
 * Process
 */

int
btc_ps_cwd(char *buf, size_t size) {
  DWORD len;

  if (size < 2)
    return 0;

  len = GetCurrentDirectoryA(size, buf);

  return len >= 1 && len <= size - 1;
}

int
btc_ps_getenv(char *out, size_t size, const char *name) {
  DWORD len = GetEnvironmentVariableA(name, out, size);

  if (len >= size)
    return 0;

  return len != 0;
}
