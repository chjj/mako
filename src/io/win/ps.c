/*!
 * ps.c - process functions for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <windows.h>
#include <io/core.h>

/*
 * Globals
 */

static void (*global_handler)(void *) = NULL;
static void *global_arg = NULL;
static int global_bound = 0;

/*
 * Process
 */

int
btc_ps_cwd(char *buf, size_t size) {
  DWORD len = GetCurrentDirectoryA(size, buf);
  return len >= 1 && len < size;
}

int
btc_ps_getenv(char *buf, size_t size, const char *name) {
  DWORD len = GetEnvironmentVariableA(name, buf, size);
  return len >= 1 && len < size;
}

int
btc_ps_daemon(void) {
  return 0;
}

int
btc_ps_fdlimit(int minfd) {
  return minfd < 2048 ? 2048 : minfd;
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

  if (!global_bound) {
    global_bound = 1;

    SetConsoleCtrlHandler(real_handler, TRUE);
  }
}
