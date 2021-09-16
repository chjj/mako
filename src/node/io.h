/*!
 * io.h - io for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_IO_H_
#define BTC_IO_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Defines
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

#define BTC_NSEC(ts) \
  ((uint64_t)(ts)->tv_sec * 1000000000 + (uint64_t)(ts)->tv_nsec)

#define BTC_PATH_MAX 1024

#if defined(_WIN32)
#  define BTC_PATH_SEP '\\'
#else
#  define BTC_PATH_SEP '/'
#endif

/*
 * Structs
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

typedef struct btc_file_s {
  int fd;
  uint32_t index;
  uint64_t size;
  void *base;
  int mapped;
  char _storage[32];
} btc_file_t;

struct btc_mutex_s;
struct btc_rwlock_s;

typedef struct btc_mutex_s btc_mutex_t;
typedef struct btc_rwlock_s btc_rwlock_t;

/*
 * Filesystem
 */

int
btc_fs_open(const char *name, int flags, uint32_t mode);

int
btc_fs_stat(const char *name, btc_stat_t *out);

int
btc_fs_lstat(const char *name, btc_stat_t *out);

int
btc_fs_exists(const char *name);

int
btc_fs_chmod(const char *name, uint32_t mode);

int
btc_fs_truncate(const char *name, int64_t size);

int
btc_fs_rename(const char *oldpath, const char *newpath);

int
btc_fs_unlink(const char *name);

int
btc_fs_mkdir(const char *name, uint32_t mode);

int
btc_fs_mkdirp(const char *name, uint32_t mode);

int
btc_fs_rmdir(const char *name);

int
btc_fs_scandir(const char *name, btc_dirent_t ***out, size_t *count);

int
btc_fs_fstat(int fd, btc_stat_t *out);

int64_t
btc_fs_seek(int fd, int64_t pos, int whence);

int64_t
btc_fs_tell(int fd);

int
btc_fs_read(int fd, void *dst, size_t len);

int
btc_fs_write(int fd, const void *src, size_t len);

int
btc_fs_pread(int fd, void *dst, size_t len, int64_t pos);

int
btc_fs_pwrite(int fd, const void *src, size_t len, int64_t pos);

int
btc_fs_ftruncate(int fd, int64_t size);

int
btc_fs_fsync(int fd);

int
btc_fs_fdatasync(int fd);

int
btc_fs_flock(int fd, int operation);

int
btc_fs_close(int fd);

/*
 * File
 */

btc_file_t *
btc_file_open(const char *name, int flags, uint32_t mode);

int
btc_file_pread(const btc_file_t *file, void *dst, size_t len, uint64_t pos);

int
btc_file_write(btc_file_t *file, const void *src, size_t len);

int
btc_file_sync(const btc_file_t *file);

int
btc_file_datasync(const btc_file_t *file);

int
btc_file_close(btc_file_t *file);

/*
 * Process
 */

int
btc_ps_cwd(char *buf, size_t size);

/*
 * Path
 */

size_t
btc_path_resolve(char *out, const char *path);

/*
 * System
 */

int
btc_sys_random(void *dst, size_t size);

/*
 * Mutex
 */

btc_mutex_t *
btc_mutex_create(void);

void
btc_mutex_destroy(btc_mutex_t *mtx);

void
btc_mutex_lock(btc_mutex_t *mtx);

void
btc_mutex_unlock(btc_mutex_t *mtx);

/*
 * Read-Write Lock
 */

btc_rwlock_t *
btc_rwlock_create(void);

void
btc_rwlock_destroy(btc_rwlock_t *mtx);

void
btc_rwlock_wrlock(btc_rwlock_t *mtx);

void
btc_rwlock_wrunlock(btc_rwlock_t *mtx);

void
btc_rwlock_rdlock(btc_rwlock_t *mtx);

void
btc_rwlock_rdunlock(btc_rwlock_t *mtx);

/*
 * Time
 */

void
btc_time_get(btc_timespec_t *ts);

/*
 * High-level Calls
 */

int
btc_fs_read_file(const char *name, void *dst, size_t len);

int
btc_fs_write_file(const char *name,
                  uint32_t mode,
                  const void *dst,
                  size_t len);

int
btc_fs_open_lock(const char *name, uint32_t mode);

void
btc_fs_close_lock(int fd);

size_t
btc_path_join(char *zp, ...);

#endif /* BTC_IO_H_ */
