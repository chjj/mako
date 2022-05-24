/*!
 * core_unix_impl.h - unix environment for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#if !defined(__Fuchsia__) && !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#  include <sys/resource.h>
#endif

#if !defined(FD_SETSIZE) && !defined(FD_SET)
#  include <sys/select.h>
#endif

#ifdef __APPLE__
#  include <mach/mach.h>
#endif

#ifdef BTC_PTHREAD
#  include <pthread.h>
#endif

#include <io/core.h>

/*
 * Macros
 */

#define BTC_MIN(x, y) ((x) < (y) ? (x) : (y))

/*
 * Compat
 */

#undef HAVE_FCNTL
#undef HAVE_SETLK
#undef HAVE_FLOCK
#undef HAVE_SYSCTL

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#  define HAVE_FCNTL
#endif

#if defined(HAVE_FCNTL) && defined(F_WRLCK) && defined(F_SETLK)
#  define HAVE_SETLK
#endif

#if !defined(HAVE_SETLK) && !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#  ifndef LOCK_EX
#    include <sys/file.h>
#  endif
#  ifdef LOCK_EX
#    define HAVE_FLOCK
#  endif
#endif

#if defined(__APPLE__)     \
 || defined(__FreeBSD__)   \
 || defined(__OpenBSD__)   \
 || defined(__NetBSD__)    \
 || defined(__DragonFly__)
#  include <sys/sysctl.h>
#  if defined(CTL_HW) && (defined(HW_AVAILCPU) || defined(HW_NCPU))
#    define HAVE_SYSCTL
#  endif
#elif defined(__hpux)
#  include <sys/mpctl.h>
#endif

/*
 * Fixes
 */

#ifdef __wasi__
/* lseek(3) is statement expression in wasi-libc. */
#  pragma GCC diagnostic ignored "-Wgnu-statement-expression"
#endif

#if defined(__APPLE__) && defined(__GNUC__)
/* clock_gettime(2) can be a weak symbol on apple. */
#  pragma GCC diagnostic ignored "-Waddress"
#endif

/*
 * Filesystem
 */

static int
btc_try_open(const char *name, int flags, uint32_t mode) {
  int fd;

#ifdef O_CLOEXEC
  if (flags & O_CREAT)
    fd = open(name, flags | O_CLOEXEC, mode);
  else
    fd = open(name, flags | O_CLOEXEC);

  if (fd >= 0 || errno != EINVAL)
    return fd;
#endif

  if (flags & O_CREAT)
    fd = open(name, flags, mode);
  else
    fd = open(name, flags);

#if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
  if (fd >= 0) {
    int r = fcntl(fd, F_GETFD);

    if (r != -1)
      fcntl(fd, F_SETFD, r | FD_CLOEXEC);
  }
#endif

  return fd;
}

static int
btc_open(const char *name, int flags, uint32_t mode) {
  int fd;

  do {
    fd = btc_try_open(name, flags, mode);
  } while (fd < 0 && errno == EINTR);

  return fd;
}

btc_fd_t
btc_fs_open(const char *name) {
  return btc_open(name, O_RDONLY, 0);
}

btc_fd_t
btc_fs_create(const char *name) {
  return btc_open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

btc_fd_t
btc_fs_append(const char *name) {
  return btc_open(name, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

FILE *
btc_fs_fopen(const char *name, const char *mode) {
  FILE *stream;
  int fd = -1;

  if (strcmp(mode, "r") == 0)
    fd = btc_fs_open(name);
  else if (strcmp(mode, "w") == 0)
    fd = btc_fs_create(name);
  else if (strcmp(mode, "a") == 0)
    fd = btc_fs_append(name);

  if (fd < 0)
    return NULL;

  stream = fdopen(fd, mode);

  if (stream == NULL)
    close(fd);

  return stream;
}

int
btc_fs_close(btc_fd_t fd) {
  return close(fd) == 0;
}

int
btc_fs_size(const char *name, uint64_t *size) {
  struct stat st;

  if (stat(name, &st) != 0)
    return 0;

  *size = st.st_size;

  return 1;
}

int
btc_fs_exists(const char *name) {
  return access(name, F_OK) == 0;
}

int
btc_fs_rename(const char *from, const char *to) {
  return rename(from, to) == 0;
}

int
btc_fs_unlink(const char *name) {
  return unlink(name) == 0;
}

int
btc_fs_mkdir(const char *name) {
  return mkdir(name, 0755) == 0;
}

int
btc_fs_mkdirp(const char *name) {
  size_t len = strlen(name);
  char path[BTC_PATH_MAX];
  struct stat st;
  size_t i = 0;

  if (len + 1 > sizeof(path))
    return 0;

  memcpy(path, name, len + 1);

  if (path[0] == '/')
    i += 1;

  for (; i < len + 1; i++) {
    if (path[i] != '/' && path[i] != '\0')
      continue;

    path[i] = '\0';

    if (stat(path, &st) < 0) {
      if (errno != ENOENT)
        return 0;

      if (mkdir(path, 0755) < 0)
        return 0;
    } else {
      if (!S_ISDIR(st.st_mode))
        return 0;
    }

    path[i] = '/';
  }

  return 1;
}

int
btc_fs_rmdir(const char *name) {
  return rmdir(name) == 0;
}

int
btc_fs_fsize(btc_fd_t fd, uint64_t *size) {
  struct stat st;

  if (fstat(fd, &st) != 0)
    return 0;

  *size = st.st_size;

  return 1;
}

int64_t
btc_fs_seek(btc_fd_t fd, int64_t pos) {
  return lseek(fd, pos, SEEK_SET);
}

int64_t
btc_fs_read(btc_fd_t fd, void *dst, size_t len) {
  unsigned char *buf = dst;
  int64_t cnt = 0;

  while (len > 0) {
    size_t max = BTC_MIN(len, 1 << 30);
    int nread;

    do {
      nread = read(fd, buf, max);
    } while (nread < 0 && errno == EINTR);

    if (nread < 0)
      return -1;

    if (nread == 0)
      break;

    buf += nread;
    len -= nread;
    cnt += nread;
  }

  return cnt;
}

int64_t
btc_fs_write(btc_fd_t fd, const void *src, size_t len) {
  const unsigned char *buf = src;
  int64_t cnt = 0;

  while (len > 0) {
    size_t max = BTC_MIN(len, 1 << 30);
    int nwrite;

    do {
      nwrite = write(fd, buf, max);
    } while (nwrite < 0 && errno == EINTR);

    if (nwrite < 0)
      return -1;

    buf += nwrite;
    len -= nwrite;
    cnt += nwrite;
  }

  return cnt;
}

int
btc_fs_fsync(btc_fd_t fd) {
#if defined(__APPLE__) && defined(F_FULLFSYNC)
  if (fcntl(fd, F_FULLFSYNC) == 0)
    return 1;
#endif

  return fsync(fd) == 0;
}

static int
btc_flock(int fd, int lock) {
#if defined(HAVE_SETLK)
  struct flock info;

  memset(&info, 0, sizeof(info));

  info.l_type = lock ? F_WRLCK : F_UNLCK;
  info.l_whence = SEEK_SET;

  return fcntl(fd, F_SETLK, &info) == 0;
#elif defined(HAVE_FLOCK)
  return flock(fd, lock ? LOCK_EX : LOCK_UN) == 0;
#else
  (void)fd;
  (void)lock;
  return 1;
#endif
}

btc_fd_t
btc_fs_lock(const char *name) {
  int fd = btc_open(name, O_RDWR | O_CREAT, 0644);

  if (fd < 0)
    return -1;

  if (!btc_flock(fd, 1)) {
    close(fd);
    return -1;
  }

  return fd;
}

int
btc_fs_unlock(btc_fd_t fd) {
  int ok = btc_flock(fd, 0);
  close(fd);
  return ok;
}

/*
 * Path
 */

int
btc_path_absolute(char *buf, size_t size, const char *name) {
#if defined(__wasi__)
  size_t len = strlen(name);

  if (name[0] != '/')
    return 0;

  if (len + 1 > size)
    return 0;

  memcpy(buf, name, len + 1);

  return 1;
#else
  char cwd[BTC_PATH_MAX];

  if (name[0] == '/') {
    size_t len = strlen(name);

    if (len + 1 > size)
      return 0;

    memcpy(buf, name, len + 1);

    return 1;
  }

  if (getcwd(cwd, sizeof(cwd)) == NULL)
    return 0;

  cwd[sizeof(cwd) - 1] = '\0';

  return btc_path_join(buf, size, cwd, name);
#endif
}

/*
 * Process
 */

static void (*global_handler)(void *) = NULL;
static void *global_arg = NULL;
static int global_bound = 0;

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
#ifdef RLIMIT_NOFILE
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
#else
  (void)minfd;
  return -1;
#endif
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

size_t
btc_ps_rss(void) {
#if defined(__linux__)
  FILE *fp = fopen("/proc/self/statm", "r");
  long size, rss, shm;

  if (fp == NULL)
    return 0;

  if (fscanf(fp, "%ld %ld %ld", &size, &rss, &shm) != 3) {
    fclose(fp);
    return 0;
  }

  fclose(fp);

  return rss * getpagesize();
#elif defined(__APPLE__)
  mach_msg_type_number_t count;
  task_basic_info_data_t info;
  kern_return_t rc;

  count = TASK_BASIC_INFO_COUNT;

  rc = task_info(mach_task_self(),
                 TASK_BASIC_INFO,
                 (task_info_t)&info,
                 &count);

  if (rc != KERN_SUCCESS)
    return 0;

  return info.resident_size;
#else
  return 0;
#endif
}

/*
 * System
 */

#ifdef HAVE_SYSCTL
static int
btc_sysctl(int name) {
  int ret = -1;
  size_t len;
  int mib[2];

  len = sizeof(ret);

  mib[0] = CTL_HW;
  mib[1] = name;

  if (sysctl(mib, 2, &ret, &len, NULL, 0) != 0)
    return -1;

  return ret;
}
#endif

int
btc_sys_numcpu(void) {
  /* https://stackoverflow.com/questions/150355 */
#if defined(__linux__) || defined(__sun) || defined(_AIX)
  /* Linux, Solaris, AIX */
# if defined(_SC_NPROCESSORS_ONLN)
  return (int)sysconf(_SC_NPROCESSORS_ONLN);
# else
  return -1;
# endif
#elif defined(HAVE_SYSCTL)
  /* Apple, FreeBSD, OpenBSD, NetBSD, DragonFly BSD */
  int ret = -1;
# if defined(HW_AVAILCPU)
  ret = btc_sysctl(HW_AVAILCPU);
# endif
# if defined(HW_NCPU)
  if (ret < 1)
    ret = btc_sysctl(HW_NCPU);
# endif
  return ret;
#elif defined(__hpux)
  /* HP-UX */
  return mpctl(MPC_GETNUMSPUS, NULL, NULL);
#elif defined(__sgi)
  /* IRIX */
# if defined(_SC_NPROC_ONLN)
  return (int)sysconf(_SC_NPROC_ONLN);
# else
  return -1;
# endif
#else
  return -1;
#endif
}

int
btc_sys_datadir(char *buf, size_t size, const char *name) {
#if defined(__wasi__)
  if (strlen(name) + 3 > size)
    return 0;

  sprintf(buf, "/.%s", name);

  return 1;
#else /* !__wasi__ */
  char *home = getenv("HOME");

  if (home == NULL || home[0] == '\0')
    return 0;

#if defined(__APPLE__)
  if (strlen(home) + strlen(name) + 30 > size)
    return 0;

  sprintf(buf, "%s/Library", home);
  mkdir(buf, 0755);

  sprintf(buf, "%s/Library/Application Support", home);
  mkdir(buf, 0755);

  sprintf(buf, "%s/Library/Application Support/%c%s",
               home, name[0] & ~32, name + 1);
#else
  if (strlen(home) + strlen(name) + 3 > size)
    return 0;

  sprintf(buf, "%s/.%s", home, name);
#endif

  return 1;
#endif /* !__wasi__ */
}

/*
 * Time
 */

static void
btc_gettimeofday(struct timeval *tv) {
  if (gettimeofday(tv, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

#ifdef BTC_HAVE_CLOCK
static void
btc_clock_gettime(clockid_t id, struct timespec *ts) {
  struct timeval tv;

#ifdef __APPLE__
  if (&clock_gettime != NULL)
#endif
  {
    if (clock_gettime(id, ts) == 0)
      return;
  }

  btc_gettimeofday(&tv);

  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = tv.tv_usec * 1000;
}
#endif

int64_t
btc_time_sec(void) {
#ifdef BTC_HAVE_CLOCK
  struct timespec ts;

#if defined(__linux__) && defined(CLOCK_MONOTONIC_COARSE)
  btc_clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
#else
  btc_clock_gettime(CLOCK_MONOTONIC, &ts);
#endif

  return ts.tv_sec;
#else
  struct timeval tv;

  btc_gettimeofday(&tv);

  return tv.tv_sec;
#endif
}

int64_t
btc_time_msec(void) {
#ifdef BTC_HAVE_CLOCK
  struct timespec ts;

  btc_clock_gettime(CLOCK_MONOTONIC, &ts);

  return ((uint64_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
#else
  struct timeval tv;

  btc_gettimeofday(&tv);

  return ((uint64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
#endif
}

int64_t
btc_time_usec(void) {
#ifdef BTC_HAVE_CLOCK
  struct timespec ts;

  btc_clock_gettime(CLOCK_MONOTONIC, &ts);

  return ((uint64_t)ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
#else
  struct timeval tv;

  btc_gettimeofday(&tv);

  return ((uint64_t)tv.tv_sec * 1000000) + tv.tv_usec;
#endif
}

void
btc_time_sleep(int64_t msec) {
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
 * Threads
 */

#ifdef BTC_PTHREAD

/*
 * Mutex
 */

void
btc_mutex_init(btc_mutex_t *mtx) {
  if (pthread_mutex_init(&mtx->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_mutex_destroy(btc_mutex_t *mtx) {
  if (pthread_mutex_destroy(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_mutex_lock(btc_mutex_t *mtx) {
  if (pthread_mutex_lock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_mutex_unlock(btc_mutex_t *mtx) {
  if (pthread_mutex_unlock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * Conditional
 */

void
btc_cond_init(btc_cond_t *cond) {
  if (pthread_cond_init(&cond->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_cond_destroy(btc_cond_t *cond) {
  if (pthread_cond_destroy(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_cond_signal(btc_cond_t *cond) {
  if (pthread_cond_signal(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_cond_broadcast(btc_cond_t *cond) {
  if (pthread_cond_broadcast(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_cond_wait(btc_cond_t *cond, btc_mutex_t *mtx) {
  if (pthread_cond_wait(&cond->handle, &mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * Thread
 */

typedef struct btc_args_s {
  void (*start)(void *);
  void *arg;
} btc_args_t;

/* Set a sane stack size for thread (from libuv). */
#if defined(__APPLE__) || defined(__linux__)
static size_t
thread_stack_size(void) {
  struct rlimit lim;

  if (getrlimit(RLIMIT_STACK, &lim) != 0)
    abort(); /* LCOV_EXCL_LINE */

  if (lim.rlim_cur != RLIM_INFINITY) {
    lim.rlim_cur -= (lim.rlim_cur % (rlim_t)getpagesize());

#if defined(PTHREAD_STACK_MIN)
    if (lim.rlim_cur >= (rlim_t)PTHREAD_STACK_MIN)
#else
    if (lim.rlim_cur >= (16 << 10))
#endif
      return lim.rlim_cur;
  }

#if !defined(__linux__)
  return 0;
#elif defined(__PPC__) || defined(__ppc__) || defined(__powerpc__)
  return 4 << 20;
#else
  return 2 << 20;
#endif
}
#endif

static void *
btc_thread_run(void *ptr) {
  btc_args_t args = *((btc_args_t *)ptr);

  free(ptr);

  args.start(args.arg);

  return NULL;
}

void
btc_thread_create(btc_thread_t *thread, void (*start)(void *), void *arg) {
  btc_args_t *args = malloc(sizeof(btc_args_t));
  pthread_attr_t *attr = NULL;

#if defined(__APPLE__) || defined(__linux__)
  size_t stack_size = thread_stack_size();
  pthread_attr_t tmp;

  if (stack_size > 0) {
    attr = &tmp;

    if (pthread_attr_init(attr) != 0)
      abort(); /* LCOV_EXCL_LINE */

    if (pthread_attr_setstacksize(attr, stack_size) != 0)
      abort(); /* LCOV_EXCL_LINE */
  }
#endif

  if (args == NULL)
    abort(); /* LCOV_EXCL_LINE */

  args->start = start;
  args->arg = arg;

  if (pthread_create(&thread->handle, attr, btc_thread_run, args) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_thread_detach(btc_thread_t *thread) {
  if (pthread_detach(thread->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_thread_join(btc_thread_t *thread) {
  if (pthread_join(thread->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

#else /* !BTC_PTHREAD */

/*
 * Mutex
 */

void
btc_mutex_init(btc_mutex_t *mtx) {
  (void)mtx;
}

void
btc_mutex_destroy(btc_mutex_t *mtx) {
  (void)mtx;
}

void
btc_mutex_lock(btc_mutex_t *mtx) {
  (void)mtx;
}

void
btc_mutex_unlock(btc_mutex_t *mtx) {
  (void)mtx;
}

/*
 * Conditional
 */

void
btc_cond_init(btc_cond_t *cond) {
  (void)cond;
}

void
btc_cond_destroy(btc_cond_t *cond) {
  (void)cond;
}

void
btc_cond_signal(btc_cond_t *cond) {
  (void)cond;
}

void
btc_cond_broadcast(btc_cond_t *cond) {
  (void)cond;
}

void
btc_cond_wait(btc_cond_t *cond, btc_mutex_t *mtx) {
  (void)cond;
  (void)mtx;
  abort(); /* LCOV_EXCL_LINE */
}

/*
 * Thread
 */

void
btc_thread_create(btc_thread_t *thread, void (*start)(void *), void *arg) {
  (void)thread;
  (void)start;
  (void)arg;
  abort(); /* LCOV_EXCL_LINE */
}

void
btc_thread_detach(btc_thread_t *thread) {
  (void)thread;
}

void
btc_thread_join(btc_thread_t *thread) {
  (void)thread;
}

#endif /* !BTC_PTHREAD */
