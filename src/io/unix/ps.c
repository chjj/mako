/*!
 * ps.c - process functions for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h> /* umask */
#include <sys/time.h>
#include <sys/resource.h> /* getrlimit */
#include <fcntl.h> /* open */
#include <unistd.h>

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
#if defined(__wasi__)
  if (size < 2)
    return 0;

  buf[0] = '/';
  buf[1] = '\0';

  return 1;
#else
  if (size < 2)
    return 0;

  if (getcwd(buf, size) == NULL)
    return 0;

  buf[size - 1] = '\0';

  return 1;
#endif
}

int
btc_ps_getenv(char *buf, size_t size, const char *name) {
  char *value = getenv(name);
  size_t len;

  if (value == NULL)
    return 0;

  len = strlen(value);

  if (len + 1 > size)
    return 0;

  memcpy(buf, value, len + 1);

  return 1;
}

int
btc_ps_daemon(void) {
#if defined(__wasi__) || defined(__EMSCRIPTEN__)
  return 0;
#else
  pid_t pid = fork();

  if (pid < 0)
    return 0;

  if (pid > 0) {
    exit(EXIT_SUCCESS);
    return 0;
  }

  if (setsid() < 0) {
    exit(EXIT_FAILURE);
    return 0;
  }

  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  pid = fork();

  if (pid < 0) {
    exit(EXIT_FAILURE);
    return 0;
  }

  if (pid > 0) {
    exit(EXIT_SUCCESS);
    return 0;
  }

  umask(0);

  chdir("/");

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  open("/dev/null", O_RDONLY);
  open("/dev/null", O_WRONLY);
  open("/dev/null", O_WRONLY);

  return 1;
#endif
}

int
btc_ps_fdlimit(int minfd) {
  /* From Bitcoin Core. */
  struct rlimit lim;

  if (getrlimit(RLIMIT_NOFILE, &lim) < 0)
    return -1;

  if (lim.rlim_cur < (rlim_t)minfd) {
    lim.rlim_cur = minfd;

    if (lim.rlim_cur > lim.rlim_max)
      lim.rlim_cur = lim.rlim_max;

    if (setrlimit(RLIMIT_NOFILE, &lim) < 0)
      return -1;

    if (getrlimit(RLIMIT_NOFILE, &lim) < 0)
      return -1;
  }

  return lim.rlim_cur;
}

static void
btc_signal(int signum, void (*handler)(int)) {
  struct sigaction sa;

  sa.sa_handler = handler;

  sigemptyset(&sa.sa_mask);

  sa.sa_flags = 0;

  sigaction(signum, &sa, NULL);
}

static void
real_handler(int signum) {
  (void)signum;

  if (global_handler != NULL) {
    global_handler(global_arg);
    global_handler = NULL;
  }
}

void
btc_ps_onterm(void (*handler)(void *), void *arg) {
  global_handler = handler;
  global_arg = arg;

  if (!global_bound) {
    global_bound = 1;

    btc_signal(SIGTERM, real_handler);
    btc_signal(SIGINT, real_handler);
  }
}
