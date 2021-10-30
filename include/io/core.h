/*!
 * core.h - core io functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_IO_CORE_H
#define BTC_IO_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#ifndef _WIN32
#include <pthread.h>
#endif

#include "../satoshi/common.h"

/*
 * Constants
 */

#define BTC_O_RDONLY     (1 <<  0)
#define BTC_O_WRONLY     (1 <<  1)
#define BTC_O_RDWR       (1 <<  2)
#define BTC_O_APPEND     (1 <<  3)
#define BTC_O_CREAT      (1 <<  4)
#define BTC_O_DSYNC      (1 <<  5)
#define BTC_O_EXCL       (1 <<  6)
#define BTC_O_NOCTTY     (1 <<  7)
#define BTC_O_NONBLOCK   (1 <<  8)
#define BTC_O_RSYNC      (1 <<  9)
#define BTC_O_SYNC       (1 << 10)
#define BTC_O_TRUNC      (1 << 11)
#define BTC_O_EXLOCK     (1 << 12)
#define BTC_O_SEQUENTIAL (1 << 13)
#define BTC_O_RANDOM     (1 << 14)
#define BTC_O_MMAP       (1 << 15)

#define BTC_S_IFMT   00170000
#define BTC_S_IFBLK  0060000
#define BTC_S_IFCHR  0020000
#define BTC_S_IFIFO  0010000
#define BTC_S_IFREG  0100000
#define BTC_S_IFDIR  0040000
#define BTC_S_IFLNK  0120000
#define BTC_S_IFSOCK 0140000

#define BTC_S_IRWXU  00700
#define BTC_S_IRUSR  00400
#define BTC_S_IWUSR  00200
#define BTC_S_IXUSR  00100

#define BTC_S_IRWXG  00070
#define BTC_S_IRGRP  00040
#define BTC_S_IWGRP  00020
#define BTC_S_IXGRP  00010

#define BTC_S_IRWXO  00007
#define BTC_S_IROTH  00004
#define BTC_S_IWOTH  00002
#define BTC_S_IXOTH  00001

#define BTC_S_ISUID  0004000
#define BTC_S_ISGID  0002000
#define BTC_S_ISVTX  0001000

#define BTC_S_ISLNK(m)  (((m) & BTC_S_IFMT) == BTC_S_IFLNK)
#define BTC_S_ISREG(m)  (((m) & BTC_S_IFMT) == BTC_S_IFREG)
#define BTC_S_ISDIR(m)  (((m) & BTC_S_IFMT) == BTC_S_IFDIR)
#define BTC_S_ISCHR(m)  (((m) & BTC_S_IFMT) == BTC_S_IFCHR)
#define BTC_S_ISBLK(m)  (((m) & BTC_S_IFMT) == BTC_S_IFBLK)
#define BTC_S_ISFIFO(m) (((m) & BTC_S_IFMT) == BTC_S_IFIFO)
#define BTC_S_ISSOCK(m) (((m) & BTC_S_IFMT) == BTC_S_IFSOCK)

#define BTC_DT_UNKNOWN 0
#define BTC_DT_FIFO    1
#define BTC_DT_CHR     2
#define BTC_DT_DIR     4
#define BTC_DT_BLK     6
#define BTC_DT_REG     8
#define BTC_DT_LNK     10
#define BTC_DT_SOCK    12

#define BTC_SEEK_SET 0
#define BTC_SEEK_CUR 1
#define BTC_SEEK_END 2

#define BTC_LOCK_SH 0
#define BTC_LOCK_EX 1
#define BTC_LOCK_UN 2

#define BTC_MSEC(ts) \
  (((ts)->tv_sec * 1000) + ((ts)->tv_nsec / 1000000))

#define BTC_USEC(ts) \
  (((ts)->tv_sec * 1000000) + ((ts)->tv_nsec / 1000))

#define BTC_NSEC(ts) \
  (((ts)->tv_sec * 1000000000) + (ts)->tv_nsec)

#define BTC_PATH_MAX 1023

#if defined(_WIN32)
#  define BTC_PATH_SEP '\\'
#else
#  define BTC_PATH_SEP '/'
#endif

#define BTC_INET_ADDRSTRLEN 22
#define BTC_INET6_ADDRSTRLEN 65

#define BTC_AF_UNSPEC 0
#define BTC_AF_INET 4
#define BTC_AF_INET6 6
#define BTC_AF_UNIX 10

#if defined(_WIN32)
#  define BTC_ONCE_INIT {NULL, 0}
#else
#  define BTC_ONCE_INIT PTHREAD_ONCE_INIT
#endif

/*
 * Types
 */

typedef struct btc_timespec_s {
  int64_t /* time_t */ tv_sec;
  uint32_t /* long */ tv_nsec;
} btc_timespec_t;

typedef struct btc_stat_s {
  uint64_t /* dev_t */ st_dev;
  uint64_t /* ino_t */ st_ino;
  uint32_t /* mode_t */ st_mode;
  uint64_t /* nlink_t */ st_nlink;
  uint32_t /* uid_t */ st_uid;
  uint32_t /* gid_t */ st_gid;
  uint64_t /* dev_t */ st_rdev;
  int64_t /* off_t */ st_size;
  btc_timespec_t /* time_t */ st_atim;
  btc_timespec_t /* time_t */ st_mtim;
  btc_timespec_t /* time_t */ st_ctim;
  btc_timespec_t /* time_t */ st_birthtim;
  int64_t /* blksize_t */ st_blksize;
  int64_t /* blkcnt_t */ st_blocks;
} btc_stat_t;

typedef struct btc_dirent_s {
  uint64_t /* ino_t */ d_ino;
  int /* unsigned char */ d_type;
  char d_name[256];
} btc_dirent_t;

typedef struct btc_mutex_s btc_mutex_t;
typedef struct btc_rwlock_s btc_rwlock_t;
typedef struct btc_cond_s btc_cond_t;
typedef struct btc_thread_s btc_thread_t;

#if defined(_WIN32)
typedef struct btc_once_s {
  void *event; /* HANDLE */
  int ran;
} btc_once_t;

typedef struct btc_tls_s {
  unsigned long index; /* DWORD */
} btc_tls_t;
#else
typedef pthread_once_t btc_once_t;
typedef pthread_key_t btc_tls_t;
#endif

typedef struct btc_sockaddr_s {
  int family;
  uint8_t raw[32];
  char path[108];
  int port;
  struct btc_sockaddr_s *next;
} btc_sockaddr_t;

struct sockaddr;

/*
 * Filesystem
 */

BTC_EXTERN int
btc_fs_open(const char *name, int flags, uint32_t mode);

BTC_EXTERN int
btc_fs_stat(const char *name, btc_stat_t *out);

BTC_EXTERN int
btc_fs_lstat(const char *name, btc_stat_t *out);

BTC_EXTERN int
btc_fs_exists(const char *name);

BTC_EXTERN int
btc_fs_chmod(const char *name, uint32_t mode);

BTC_EXTERN int
btc_fs_truncate(const char *name, int64_t size);

BTC_EXTERN int
btc_fs_rename(const char *oldpath, const char *newpath);

BTC_EXTERN int
btc_fs_unlink(const char *name);

BTC_EXTERN int
btc_fs_mkdir(const char *name, uint32_t mode);

BTC_EXTERN int
btc_fs_mkdirp(const char *name, uint32_t mode);

BTC_EXTERN int
btc_fs_rmdir(const char *name);

BTC_EXTERN int
btc_fs_scandir(const char *name, btc_dirent_t ***out, size_t *count);

BTC_EXTERN int
btc_fs_fstat(int fd, btc_stat_t *out);

BTC_EXTERN int64_t
btc_fs_seek(int fd, int64_t pos, int whence);

BTC_EXTERN int64_t
btc_fs_tell(int fd);

BTC_EXTERN int
btc_fs_read(int fd, void *dst, size_t len);

BTC_EXTERN int
btc_fs_write(int fd, const void *src, size_t len);

BTC_EXTERN int
btc_fs_pread(int fd, void *dst, size_t len, int64_t pos);

BTC_EXTERN int
btc_fs_pwrite(int fd, const void *src, size_t len, int64_t pos);

BTC_EXTERN int
btc_fs_ftruncate(int fd, int64_t size);

BTC_EXTERN int
btc_fs_fsync(int fd);

BTC_EXTERN int
btc_fs_fdatasync(int fd);

BTC_EXTERN int
btc_fs_flock(int fd, int operation);

BTC_EXTERN int
btc_fs_close(int fd);

BTC_EXTERN int
btc_fs_read_file(const char *name, void *dst, size_t len);

BTC_EXTERN int
btc_fs_write_file(const char *name,
                  uint32_t mode,
                  const void *src,
                  size_t len);

BTC_EXTERN int
btc_fs_alloc_file(unsigned char **dst, size_t *len, const char *name);

BTC_EXTERN int
btc_fs_open_lock(const char *name, uint32_t mode);

BTC_EXTERN void
btc_fs_close_lock(int fd);

/*
 * Process
 */

BTC_EXTERN int
btc_ps_cwd(char *buf, size_t size);

/*
 * Path
 */

BTC_EXTERN size_t
btc_path_join(char *zp, ...);

BTC_EXTERN size_t
btc_path_resolve(char *out, const char *path);

/*
 * System
 */

BTC_EXTERN int
btc_sys_cpu_count(void);

/*
 * Mutex
 */

BTC_EXTERN btc_mutex_t *
btc_mutex_create(void);

BTC_EXTERN void
btc_mutex_destroy(btc_mutex_t *mtx);

BTC_EXTERN void
btc_mutex_lock(btc_mutex_t *mtx);

BTC_EXTERN void
btc_mutex_unlock(btc_mutex_t *mtx);

BTC_EXTERN int
btc_mutex_trylock(btc_mutex_t *mtx);

/*
 * Read-Write Lock
 */

BTC_EXTERN btc_rwlock_t *
btc_rwlock_create(void);

BTC_EXTERN void
btc_rwlock_destroy(btc_rwlock_t *mtx);

BTC_EXTERN void
btc_rwlock_wrlock(btc_rwlock_t *mtx);

BTC_EXTERN void
btc_rwlock_wrunlock(btc_rwlock_t *mtx);

BTC_EXTERN void
btc_rwlock_rdlock(btc_rwlock_t *mtx);

BTC_EXTERN void
btc_rwlock_rdunlock(btc_rwlock_t *mtx);

BTC_EXTERN int
btc_rwlock_trywrlock(btc_rwlock_t *mtx);

BTC_EXTERN int
btc_rwlock_tryrdlock(btc_rwlock_t *mtx);

/*
 * Conditional
 */

BTC_EXTERN btc_cond_t *
btc_cond_create(void);

BTC_EXTERN void
btc_cond_destroy(btc_cond_t *cond);

BTC_EXTERN void
btc_cond_signal(btc_cond_t *cond);

BTC_EXTERN void
btc_cond_broadcast(btc_cond_t *cond);

BTC_EXTERN void
btc_cond_wait(btc_cond_t *cond, btc_mutex_t *mtx);

BTC_EXTERN int
btc_cond_timedwait(btc_cond_t *cond, btc_mutex_t *mtx, int64_t msec);

/*
 * Thread
 */

BTC_EXTERN btc_thread_t *
btc_thread_alloc(void);

BTC_EXTERN void
btc_thread_free(btc_thread_t *thread);

BTC_EXTERN void
btc_thread_create(btc_thread_t *thread, void (*start)(void *), void *arg);

BTC_EXTERN void
btc_thread_detach(btc_thread_t *thread);

BTC_EXTERN void
btc_thread_join(btc_thread_t *thread);

/*
 * Once
 */

BTC_EXTERN void
btc_once(btc_once_t *guard, void (*callback)(void));

/*
 * TLS
 */

BTC_EXTERN void
btc_tls_init(btc_tls_t *key);

BTC_EXTERN void
btc_tls_clear(btc_tls_t *key);

BTC_EXTERN void *
btc_tls_get(btc_tls_t *key);

BTC_EXTERN void
btc_tls_set(btc_tls_t *key, void *value);

/*
 * Time
 */

BTC_EXTERN void
btc_time_get(btc_timespec_t *ts);

BTC_EXTERN int64_t
btc_time_sec(void);

BTC_EXTERN int64_t
btc_time_msec(void);

BTC_EXTERN int64_t
btc_time_usec(void);

BTC_EXTERN int64_t
btc_time_nsec(void);

BTC_EXTERN void
btc_time_sleep(int64_t msec);

/*
 * Temporary
 */

#define btc_ms btc_time_msec
#define btc_us btc_time_usec

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
 * Address Info
 */

BTC_EXTERN int
btc_getaddrinfo(btc_sockaddr_t **res, const char *name);

BTC_EXTERN void
btc_freeaddrinfo(btc_sockaddr_t *res);

BTC_EXTERN int
btc_getifaddrs(btc_sockaddr_t **res);

BTC_EXTERN void
btc_freeifaddrs(btc_sockaddr_t *res);

#ifdef __cplusplus
}
#endif

#endif /* BTC_IO_CORE_H */
