/*!
 * ps.c - process functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <windows.h>
#include <io/core.h>

/*
 * Globals
 */

static void (*global_handler)(void *) = NULL;
static void *global_arg = NULL;

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

int
btc_ps_daemon(void) {
  return 0;
}

static BOOL WINAPI
real_handler(DWORD type) {
  /* Note: this runs on a separate thread. */
  /* May need to add a mutex for `loop->running`? */
  (void)type;

  if (global_handler != NULL) {
    global_handler(global_arg);
    global_handler = NULL;
  }

  Sleep(INFINITE); /* Prevent ExitProcess from being called. */

  return TRUE;
}

void
btc_ps_onterm(void (*handler)(void *), void *arg) {
  global_handler = handler;
  global_arg = arg;

  SetConsoleCtrlHandler(real_handler, TRUE);
}
