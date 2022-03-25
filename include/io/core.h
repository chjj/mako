/*!
 * core.h - core io functions for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_IO_CORE_H
#define BTC_IO_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../mako/common.h"

/*
 * Compat
 */

#if defined(BTC_NEED_WINDOWS_H)
#  include <windows.h>
#  define BTC_HANDLE HANDLE
#  define BTC_CRITICAL_SECTION CRITICAL_SECTION
#elif defined(_WIN32)
typedef void *BTC_HANDLE;
#  pragma pack(push, 8)
typedef struct BTC_RTL_CRITICAL_SECTION {
  void *DebugInfo;
  long LockCount;
  long RecursionCount;
  void *OwningThread;
  void *LockSemaphore;
#ifdef _WIN64
  unsigned __int64 SpinCount;
#else
  unsigned long SpinCount;
#endif
} BTC_CRITICAL_SECTION;
#  pragma pack(pop)
#elif defined(BTC_PTHREAD)
#  include <pthread.h>
#endif

/*
 * Constants
 */

#define BTC_PATH_MAX 1024

#define BTC_INET_ADDRSTRLEN 22
#define BTC_INET6_ADDRSTRLEN 65

#define BTC_AF_UNSPEC 0
#define BTC_AF_INET 4
#define BTC_AF_INET6 6

/*
 * Types
 */

#if defined(_WIN32)
#  define BTC_INVALID_FD ((BTC_HANDLE)-1)
typedef BTC_HANDLE btc_fd_t;
#else
#  define BTC_INVALID_FD (-1)
typedef int btc_fd_t;
#endif

#if defined(_WIN32)

typedef struct btc_mutex_s {
  volatile long state;
  BTC_CRITICAL_SECTION handle;
} btc_mutex_t;

typedef struct btc_cond_s {
  int waiters;
  BTC_HANDLE signal;
  BTC_HANDLE broadcast;
  BTC_CRITICAL_SECTION lock;
} btc_cond_t;

typedef struct btc_thread_s {
  BTC_HANDLE handle;
} btc_thread_t;

#define BTC_MUTEX_INITIALIZER {0, {0, 0, 0, 0, 0, 0}}

#elif defined(BTC_PTHREAD)

typedef struct btc_mutex_s {
  pthread_mutex_t handle;
} btc_mutex_t;

typedef struct btc_cond_s {
  pthread_cond_t handle;
} btc_cond_t;

typedef struct btc_thread_s {
  pthread_t handle;
} btc_thread_t;

#define BTC_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER }

#else /* !BTC_PTHREAD */

typedef struct btc_mutex_s {
  void *handle;
} btc_mutex_t;

typedef struct btc_cond_s {
  void *handle;
} btc_cond_t;

typedef struct btc_thread_s {
  void *handle;
} btc_thread_t;

#define BTC_MUTEX_INITIALIZER {0}

#endif /* !BTC_PTHREAD */

typedef struct btc_sockaddr_s {
  int family;
  uint8_t raw[32];
  int port;
  struct btc_sockaddr_s *next;
} btc_sockaddr_t;

struct sockaddr;

/*
 * Address Info
 */

BTC_EXTERN int
btc_getaddrinfo(btc_sockaddr_t **res, const char *name, int port);

BTC_EXTERN void
btc_freeaddrinfo(btc_sockaddr_t *res);

BTC_EXTERN int
btc_getifaddrs(btc_sockaddr_t **res, int port);

BTC_EXTERN void
btc_freeifaddrs(btc_sockaddr_t *res);

/*
 * Filesystem
 */

BTC_EXTERN btc_fd_t
btc_fs_open(const char *name);

BTC_EXTERN btc_fd_t
btc_fs_create(const char *name);

BTC_EXTERN btc_fd_t
btc_fs_append(const char *name);

BTC_EXTERN FILE *
btc_fs_fopen(const char *name, const char *mode);

BTC_EXTERN int
btc_fs_close(btc_fd_t fd);

BTC_EXTERN int
btc_fs_size(const char *name, uint64_t *size);

BTC_EXTERN int
btc_fs_exists(const char *name);

BTC_EXTERN int
btc_fs_rename(const char *from, const char *to);

BTC_EXTERN int
btc_fs_unlink(const char *name);

BTC_EXTERN int
btc_fs_mkdir(const char *name);

BTC_EXTERN int
btc_fs_mkdirp(const char *name);

BTC_EXTERN int
btc_fs_rmdir(const char *name);

BTC_EXTERN int
btc_fs_fsize(btc_fd_t fd, uint64_t *size);

BTC_EXTERN int64_t
btc_fs_seek(btc_fd_t fd, int64_t pos);

BTC_EXTERN int64_t
btc_fs_read(btc_fd_t fd, void *dst, size_t len);

BTC_EXTERN int64_t
btc_fs_write(btc_fd_t fd, const void *src, size_t len);

BTC_EXTERN int
btc_fs_fsync(btc_fd_t fd);

BTC_EXTERN btc_fd_t
btc_fs_lock(const char *name);

BTC_EXTERN int
btc_fs_unlock(btc_fd_t fd);

BTC_EXTERN int
btc_fs_read_file(const char *name, unsigned char **dst, size_t *len);

BTC_EXTERN int
btc_fs_write_file(const char *name, const void *src, size_t len);

/*
 * Network
 */

BTC_EXTERN void
btc_net_startup(void);

BTC_EXTERN void
btc_net_cleanup(void);

BTC_EXTERN int
btc_net_external(btc_sockaddr_t *addr, int family, int port);

/*
 * Path
 */

BTC_EXTERN int
btc_path_absolute(char *buf, size_t size, const char *name);

BTC_EXTERN int
btc_path_absolutify(char *name, size_t size);

BTC_EXTERN int
btc_path_join(char *zp, size_t zn, const char *xp, const char *yp);

/*
 * Process
 */

BTC_EXTERN int
btc_ps_daemon(void);

BTC_EXTERN int
btc_ps_fdlimit(int minfd);

BTC_EXTERN void
btc_ps_onterm(void (*handler)(void *), void *arg);

BTC_EXTERN size_t
btc_ps_rss(void);

/*
 * Mutex
 */

BTC_EXTERN void
btc_mutex_init(btc_mutex_t *mtx);

BTC_EXTERN void
btc_mutex_destroy(btc_mutex_t *mtx);

BTC_EXTERN void
btc_mutex_lock(btc_mutex_t *mtx);

BTC_EXTERN void
btc_mutex_unlock(btc_mutex_t *mtx);

/*
 * Conditional
 */

BTC_EXTERN void
btc_cond_init(btc_cond_t *cond);

BTC_EXTERN void
btc_cond_destroy(btc_cond_t *cond);

BTC_EXTERN void
btc_cond_signal(btc_cond_t *cond);

BTC_EXTERN void
btc_cond_broadcast(btc_cond_t *cond);

BTC_EXTERN void
btc_cond_wait(btc_cond_t *cond, btc_mutex_t *mtx);

/*
 * Thread
 */

BTC_EXTERN void
btc_thread_create(btc_thread_t *thread, void (*start)(void *), void *arg);

BTC_EXTERN void
btc_thread_detach(btc_thread_t *thread);

BTC_EXTERN void
btc_thread_join(btc_thread_t *thread);

/*
 * Socket Address
 */

BTC_EXTERN void
btc_sockaddr_init(btc_sockaddr_t *addr);

BTC_EXTERN int
btc_sockaddr_set(btc_sockaddr_t *z, const struct sockaddr *x);

BTC_EXTERN int
btc_sockaddr_get(struct sockaddr *z, const btc_sockaddr_t *x);

BTC_EXTERN int
btc_sockaddr_import(btc_sockaddr_t *z, const char *xp, int port);

BTC_EXTERN int
btc_sockaddr_export(char *zp, int *port, const btc_sockaddr_t *x);

/*
 * System
 */

BTC_EXTERN int
btc_sys_numcpu(void);

BTC_EXTERN int
btc_sys_datadir(char *buf, size_t size, const char *name);

/*
 * Time
 */

BTC_EXTERN int64_t
btc_time_sec(void);

BTC_EXTERN int64_t
btc_time_msec(void);

BTC_EXTERN int64_t
btc_time_usec(void);

BTC_EXTERN void
btc_time_sleep(int64_t msec);

#ifdef __cplusplus
}
#endif

#endif /* BTC_IO_CORE_H */
