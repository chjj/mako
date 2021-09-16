/*!
 * io_posix.c - posix io for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#undef HAVE_FCNTL
#undef HAVE_MMAP
#undef HAVE_PTHREAD

#if !defined(__EMSCRIPTEN__) && !defined(__wasi__)
#  define HAVE_FCNTL
#  define HAVE_MMAP
#  define HAVE_PTHREAD
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#include <dirent.h>
#include <fcntl.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif
#include <unistd.h>

#ifndef MAP_FAILED
#  define MAP_FAILED ((void *)-1)
#endif

#ifndef SSIZE_MAX
#  define SSIZE_MAX ((ssize_t)((size_t)-1 / 2))
#endif

#ifdef __wasi__
/* lseek(3) is statement expression in wasi-libc. */
#  pragma GCC diagnostic ignored "-Wgnu-statement-expression"
/* We need direct access to some WASI calls. */
#  include <wasi/api.h>
#endif

#ifdef __EMSCRIPTEN__
/* Necessary for our RNG. See btc_sys_random. */
#  include <uuid/uuid.h> /* uuid_generate */
#endif

#include "io.h"

/*
 * Prototypes
 */

static size_t
btc_path_normalize(char *path);

/*
 * Structs
 */

typedef struct btc_mutex_s {
#if defined(HAVE_PTHREAD)
  pthread_mutex_t handle;
#else
  void *unused;
#endif
} btc__mutex_t;

typedef struct btc_rwlock_s {
#if defined(HAVE_PTHREAD)
  pthread_rwlock_t handle;
#else
  void *unused;
#endif
} btc__rwlock_t;

/*
 * Filesystem
 */

static int
btc_fs__flags_api_to_os(int flags) {
  int out = 0;

#ifdef O_RDONLY
  if (flags & BTC_O_RDONLY)
    out |= O_RDONLY;
#endif

#ifdef O_WRONLY
  if (flags & BTC_O_WRONLY)
    out |= O_WRONLY;
#endif

#ifdef O_RDWR
  if (flags & BTC_O_RDWR)
    out |= O_RDWR;
#endif

#ifdef O_APPEND
  if (flags & BTC_O_APPEND)
    out |= O_APPEND;
#endif

#ifdef O_CREAT
  if (flags & BTC_O_CREAT)
    out |= O_CREAT;
#endif

#ifdef O_DSYNC
  if (flags & BTC_O_DSYNC)
    out |= O_DSYNC;
#endif

#ifdef O_EXCL
  if (flags & BTC_O_EXCL)
    out |= O_EXCL;
#endif

#ifdef O_NOCTTY
  if (flags & BTC_O_NOCTTY)
    out |= O_NOCTTY;
#endif

#ifdef O_NONBLOCK
  if (flags & BTC_O_NONBLOCK)
    out |= O_NONBLOCK;
#endif

#ifdef O_RSYNC
  if (flags & BTC_O_RSYNC)
    out |= O_RSYNC;
#endif

#ifdef O_SYNC
  if (flags & BTC_O_SYNC)
    out |= O_SYNC;
#endif

#ifdef O_TRUNC
  if (flags & BTC_O_TRUNC)
    out |= O_TRUNC;
#endif

  return out;
}

static uint32_t
btc_fs__mode_api_to_os(uint32_t mode) {
  uint32_t out = 0;

#ifdef S_IFBLK
  if (mode & BTC_S_IFBLK)
    out |= S_IFBLK;
#endif

#ifdef S_IFCHR
  if (mode & BTC_S_IFCHR)
    out |= S_IFCHR;
#endif

#ifdef S_IFIFO
  if (mode & BTC_S_IFIFO)
    out |= S_IFIFO;
#endif

#ifdef S_IFREG
  if (mode & BTC_S_IFREG)
    out |= S_IFREG;
#endif

#ifdef S_IFDIR
  if (mode & BTC_S_IFDIR)
    out |= S_IFDIR;
#endif

#ifdef S_IFLNK
  if (mode & BTC_S_IFLNK)
    out |= S_IFLNK;
#endif

#ifdef S_IFSOCK
  if (mode & BTC_S_IFSOCK)
    out |= S_IFSOCK;
#endif

#ifdef S_IRUSR
  if (mode & BTC_S_IRUSR)
    out |= S_IRUSR;
#endif

#ifdef S_IWUSR
  if (mode & BTC_S_IWUSR)
    out |= S_IWUSR;
#endif

#ifdef S_IXUSR
  if (mode & BTC_S_IXUSR)
    out |= S_IXUSR;
#endif

#ifdef S_IRGRP
  if (mode & BTC_S_IRGRP)
    out |= S_IRGRP;
#endif

#ifdef S_IWGRP
  if (mode & BTC_S_IWGRP)
    out |= S_IWGRP;
#endif

#ifdef S_IXGRP
  if (mode & BTC_S_IXGRP)
    out |= S_IXGRP;
#endif

#ifdef S_IROTH
  if (mode & BTC_S_IROTH)
    out |= S_IROTH;
#endif

#ifdef S_IWOTH
  if (mode & BTC_S_IWOTH)
    out |= S_IWOTH;
#endif

#ifdef S_IXOTH
  if (mode & BTC_S_IXOTH)
    out |= S_IXOTH;
#endif

#ifdef S_ISUID
  if (mode & BTC_S_ISUID)
    out |= S_ISUID;
#endif

#ifdef S_ISGID
  if (mode & BTC_S_ISGID)
    out |= S_ISGID;
#endif

#ifdef S_ISVTX
  if (mode & BTC_S_ISVTX)
    out |= S_ISVTX;
#endif

  return out;
}

static uint32_t
btc_fs__mode_os_to_api(uint32_t mode) {
  uint32_t out = 0;

#ifdef S_IFBLK
  if (mode & S_IFBLK)
    out |= BTC_S_IFBLK;
#endif

#ifdef S_IFCHR
  if (mode & S_IFCHR)
    out |= BTC_S_IFCHR;
#endif

#ifdef S_IFIFO
  if (mode & S_IFIFO)
    out |= BTC_S_IFIFO;
#endif

#ifdef S_IFREG
  if (mode & S_IFREG)
    out |= BTC_S_IFREG;
#endif

#ifdef S_IFDIR
  if (mode & S_IFDIR)
    out |= BTC_S_IFDIR;
#endif

#ifdef S_IFLNK
  if (mode & S_IFLNK)
    out |= BTC_S_IFLNK;
#endif

#ifdef S_IFSOCK
  if (mode & S_IFSOCK)
    out |= BTC_S_IFSOCK;
#endif

#ifdef S_IRUSR
  if (mode & S_IRUSR)
    out |= BTC_S_IRUSR;
#endif

#ifdef S_IWUSR
  if (mode & S_IWUSR)
    out |= BTC_S_IWUSR;
#endif

#ifdef S_IXUSR
  if (mode & S_IXUSR)
    out |= BTC_S_IXUSR;
#endif

#ifdef S_IRGRP
  if (mode & S_IRGRP)
    out |= BTC_S_IRGRP;
#endif

#ifdef S_IWGRP
  if (mode & S_IWGRP)
    out |= BTC_S_IWGRP;
#endif

#ifdef S_IXGRP
  if (mode & S_IXGRP)
    out |= BTC_S_IXGRP;
#endif

#ifdef S_IROTH
  if (mode & S_IROTH)
    out |= BTC_S_IROTH;
#endif

#ifdef S_IWOTH
  if (mode & S_IWOTH)
    out |= BTC_S_IWOTH;
#endif

#ifdef S_IXOTH
  if (mode & S_IXOTH)
    out |= BTC_S_IXOTH;
#endif

#ifdef S_ISUID
  if (mode & S_ISUID)
    out |= BTC_S_ISUID;
#endif

#ifdef S_ISGID
  if (mode & S_ISGID)
    out |= BTC_S_ISGID;
#endif

#ifdef S_ISVTX
  if (mode & S_ISVTX)
    out |= BTC_S_ISVTX;
#endif

  return out;
}

static void
btc_fs__convert_stat(btc_stat_t *dst, const struct stat *src) {
  dst->st_dev = src->st_dev;
  dst->st_ino = src->st_ino;
  dst->st_mode = btc_fs__mode_os_to_api(src->st_mode);
  dst->st_nlink = src->st_nlink;
  dst->st_uid = src->st_uid;
  dst->st_gid = src->st_gid;
  dst->st_rdev = src->st_rdev;
  dst->st_size = src->st_size;
  /* From libuv. */
#if defined(__APPLE__)
  dst->st_atim.tv_sec = src->st_atimespec.tv_sec;
  dst->st_atim.tv_nsec = src->st_atimespec.tv_nsec;
  dst->st_mtim.tv_sec = src->st_mtimespec.tv_sec;
  dst->st_mtim.tv_nsec = src->st_mtimespec.tv_nsec;
  dst->st_ctim.tv_sec = src->st_ctimespec.tv_sec;
  dst->st_ctim.tv_nsec = src->st_ctimespec.tv_nsec;
  dst->st_birthtim.tv_sec = src->st_birthtimespec.tv_sec;
  dst->st_birthtim.tv_nsec = src->st_birthtimespec.tv_nsec;
#elif defined(__ANDROID__)
  dst->st_atim.tv_sec = src->st_atime;
  dst->st_atim.tv_nsec = src->st_atimensec;
  dst->st_mtim.tv_sec = src->st_mtime;
  dst->st_mtim.tv_nsec = src->st_mtimensec;
  dst->st_ctim.tv_sec = src->st_ctime;
  dst->st_ctim.tv_nsec = src->st_ctimensec;
  dst->st_birthtim.tv_sec = src->st_ctime;
  dst->st_birthtim.tv_nsec = src->st_ctimensec;
#elif !defined(_AIX) && (defined(__DragonFly__)    \
                      || defined(__FreeBSD__)      \
                      || defined(__OpenBSD__)      \
                      || defined(__NetBSD__)       \
                      || defined(_GNU_SOURCE)      \
                      || defined(_BSD_SOURCE)      \
                      || defined(_SVID_SOURCE)     \
                      || defined(_XOPEN_SOURCE)    \
                      || defined(_DEFAULT_SOURCE))
  dst->st_atim.tv_sec = src->st_atim.tv_sec;
  dst->st_atim.tv_nsec = src->st_atim.tv_nsec;
  dst->st_mtim.tv_sec = src->st_mtim.tv_sec;
  dst->st_mtim.tv_nsec = src->st_mtim.tv_nsec;
  dst->st_ctim.tv_sec = src->st_ctim.tv_sec;
  dst->st_ctim.tv_nsec = src->st_ctim.tv_nsec;
#if defined(__FreeBSD__) || defined(__NetBSD__)
  dst->st_birthtim.tv_sec = src->st_birthtim.tv_sec;
  dst->st_birthtim.tv_nsec = src->st_birthtim.tv_nsec;
#else
  dst->st_birthtim.tv_sec = src->st_ctim.tv_sec;
  dst->st_birthtim.tv_nsec = src->st_ctim.tv_nsec;
#endif
#else
  dst->st_atim.tv_sec = src->st_atime;
  dst->st_atim.tv_nsec = 0;
  dst->st_mtim.tv_sec = src->st_mtime;
  dst->st_mtim.tv_nsec = 0;
  dst->st_ctim.tv_sec = src->st_ctime;
  dst->st_ctim.tv_nsec = 0;
  dst->st_birthtim.tv_sec = src->st_ctime;
  dst->st_birthtim.tv_nsec = 0;
#endif
  dst->st_blksize = src->st_blksize;
  dst->st_blocks = src->st_blocks;
}

static int
btc_fs__open(const char *name, int flags_, uint32_t mode_) {
  int flags = btc_fs__flags_api_to_os(flags_);
  uint32_t mode = btc_fs__mode_api_to_os(mode_);
  int fd;

#ifdef O_CLOEXEC
  if (flags & O_CREAT)
    fd = open(name, flags | O_CLOEXEC, mode);
  else
    fd = open(name, flags | O_CLOEXEC);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  if (flags & O_CREAT)
    fd = open(name, flags, mode);
  else
    fd = open(name, flags);

#if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
  if (fd != -1) {
    int r = fcntl(fd, F_GETFD);

    if (r != -1)
      fcntl(fd, F_SETFD, r | FD_CLOEXEC);
  }
#endif

  return fd;
}

int
btc_fs_open(const char *name, int flags, uint32_t mode) {
  int fd;

  do {
    fd = btc_fs__open(name, flags, mode);
  } while (fd == -1 && errno == EINTR);

  return fd;
}

int
btc_fs_stat(const char *name, btc_stat_t *out) {
  struct stat st;

  if (stat(name, &st) == 0) {
    btc_fs__convert_stat(out, &st);
    return 1;
  }

  return 0;
}

int
btc_fs_lstat(const char *name, btc_stat_t *out) {
  struct stat st;

  if (lstat(name, &st) == 0) {
    btc_fs__convert_stat(out, &st);
    return 1;
  }

  return 0;
}

int
btc_fs_exists(const char *name) {
  struct stat st;
  return lstat(name, &st) == 0;
}

int
btc_fs_chmod(const char *name, uint32_t mode) {
#if defined(__wasi__)
  (void)name;
  (void)mode;
  return 1;
#else
  return chmod(name, btc_fs__mode_api_to_os(mode)) == 0;
#endif
}

int
btc_fs_truncate(const char *name, int64_t size) {
  return truncate(name, size) == 0;
}

int
btc_fs_rename(const char *oldpath, const char *newpath) {
  return rename(oldpath, newpath) == 0;
}

int
btc_fs_unlink(const char *name) {
  return unlink(name) == 0;
}

int
btc_fs_mkdir(const char *name, uint32_t mode) {
  return mkdir(name, btc_fs__mode_api_to_os(mode)) == 0;
}

int
btc_fs_mkdirp(const char *name, uint32_t mode) {
  char path[BTC_PATH_MAX + 1];
  size_t len = strlen(name);
  struct stat st;
  size_t i = 0;

  if (len > BTC_PATH_MAX)
    return 0;

  memcpy(path, name, len + 1);

  len = btc_path_normalize(path);
  mode = btc_fs__mode_api_to_os(mode);

  if (path[0] == '/')
    i += 1;

  for (; i < len + 1; i++) {
    if (path[i] != '/' && path[i] != '\0')
      continue;

    path[i] = '\0';

    if (stat(path, &st) < 0) {
      if (errno != ENOENT)
        return 0;

      if (mkdir(path, mode) < 0)
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

static int
btc__dirent_compare(const void *x, const void *y) {
  const btc_dirent_t *a = *((const btc_dirent_t **)x);
  const btc_dirent_t *b = *((const btc_dirent_t **)y);

  return strcmp(a->d_name, b->d_name);
}

int
btc_fs_scandir(const char *name, btc_dirent_t ***out, size_t *count) {
#if defined(__wasi__)
  /* This absolutely insane hack is to workaround the fact that
  * uvwasi is broken in node.js[1][2]. uvwasi mistakenly copies
  * a pointer to the dirent name string instead of the string
  * itself. Not only does this cause the node.js process to enter
  * an unpredictable state and leak potentially sensitive data,
  * it also means that it's impossible to actually get the dirent
  * names.
  *
  * To get around this we ask uvwasi for the dirents only and we
  * infer the filenames in our database directory based on their
  * lengths. This avoids any kind of segfault and gives us a way
  * to use libbtc in WASI right now.
  *
  * [1] https://github.com/cjihrig/uvwasi/blob/d3fe61d/src/uvwasi.c#L1392
  * [2] https://github.com/cjihrig/uvwasi/issues/148
  */
  btc_dirent_t **list = NULL;
  btc_dirent_t *item = NULL;
  __wasi_dirent_t entry;
  __wasi_fd_t fd = -1;
  unsigned char *buf = (unsigned char *)&entry;
  __wasi_size_t buflen = sizeof(entry);
  __wasi_dircookie_t cookie = 0;
  __wasi_size_t bufused = 0;
  uint32_t name_index = 1;
  size_t size = 8;
  int has_meta = 0;
  int has_lock = 0;
  size_t i = 0;
  size_t j;

  list = (btc_dirent_t **)malloc(size * sizeof(btc_dirent_t *));

  if (list == NULL)
    goto fail;

  fd = open(name, O_RDONLY);

  if (fd == -1)
    goto fail;

  for (;;) {
    if (__wasi_fd_readdir(fd, buf, buflen, cookie, &bufused) != 0)
      goto fail;

    if (bufused != sizeof(entry))
      break;

    item = (btc_dirent_t *)malloc(sizeof(btc_dirent_t));

    if (item == NULL)
      goto fail;

    if (i == size) {
      size = (size * 3) / 2;
      list = (btc_dirent_t **)realloc(list, size * sizeof(btc_dirent_t *));

      if (list == NULL)
        goto fail;
    }

    item->d_ino = entry.d_ino;
    item->d_type = BTC_DT_REG;

    switch (entry.d_namlen) {
      case 4: {
        if (!has_meta) {
          memcpy(item->d_name, "meta", 5);
          has_meta = 1;
        } else if (!has_lock) {
          memcpy(item->d_name, "lock", 5);
          has_lock = 1;
        } else {
          free(item);
          goto next;
        }

        break;
      }

      case 10: {
        uint32_t num = name_index++;
        size_t k = 10;

        item->d_name[k] = '\0';

        while (k--) {
          item->d_name[k] = '0' + (num % 10);
          num /= 10;
        }

        break;
      }

      default: {
        free(item);
        goto next;
      }
    }

    list[i++] = item;
next:
    item = NULL;
    cookie = entry.d_next;
  }

  close(fd);

  qsort(list, i, sizeof(btc_dirent_t *), btc__dirent_compare);

  *out = list;
  *count = i;

  return 1;
fail:
  for (j = 0; j < i; j++)
    free(list[j]);

  if (list != NULL)
    free(list);

  if (item != NULL)
    free(item);

  if (fd != -1)
    close(fd);

  *out = NULL;
  *count = 0;

  return 0;
#else /* !__wasi__ */
  btc_dirent_t **list = NULL;
  btc_dirent_t *item = NULL;
  struct dirent *entry;
  size_t size = 8;
  DIR *dir = NULL;
  size_t i = 0;
  size_t j, len;

  list = (btc_dirent_t **)malloc(size * sizeof(btc_dirent_t *));

  if (list == NULL)
    goto fail;

  dir = opendir(name);

  if (dir == NULL)
    goto fail;

  for (;;) {
    errno = 0;
    entry = readdir(dir);

    if (entry == NULL) {
      if (errno != 0)
        goto fail;
      break;
    }

    if (strcmp(entry->d_name, ".") == 0
        || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    item = (btc_dirent_t *)malloc(sizeof(btc_dirent_t));

    if (item == NULL)
      goto fail;

    len = strlen(entry->d_name);

    if (len + 1 > sizeof(item->d_name))
      goto fail;

    if (i == size) {
      size = (size * 3) / 2;
      list = (btc_dirent_t **)realloc(list, size * sizeof(btc_dirent_t *));

      if (list == NULL)
        goto fail;
    }

    item->d_ino = entry->d_ino;
    item->d_type = BTC_DT_UNKNOWN;

#ifdef DT_UNKNOWN
    switch (entry->d_type) {
#ifdef DT_FIFO
      case DT_FIFO:
        item->d_type = BTC_DT_FIFO;
        break;
#endif
#ifdef DT_CHR
      case DT_CHR:
        item->d_type = BTC_DT_CHR;
        break;
#endif
#ifdef DT_DIR
      case DT_DIR:
        item->d_type = BTC_DT_DIR;
        break;
#endif
#ifdef DT_BLK
      case DT_BLK:
        item->d_type = BTC_DT_BLK;
        break;
#endif
#ifdef DT_REG
      case DT_REG:
        item->d_type = BTC_DT_REG;
        break;
#endif
#ifdef DT_LNK
      case DT_LNK:
        item->d_type = BTC_DT_LNK;
        break;
#endif
#ifdef DT_SOCK
      case DT_SOCK:
        item->d_type = BTC_DT_SOCK;
        break;
#endif
    }
#endif /* !DT_UNKNOWN */

    memcpy(item->d_name, entry->d_name, len + 1);

    list[i++] = item;
    item = NULL;
  }

  closedir(dir);

  qsort(list, i, sizeof(btc_dirent_t *), btc__dirent_compare);

  *out = list;
  *count = i;

  return 1;
fail:
  for (j = 0; j < i; j++)
    free(list[j]);

  if (list != NULL)
    free(list);

  if (item != NULL)
    free(item);

  if (dir != NULL)
    closedir(dir);

  *out = NULL;
  *count = 0;

  return 0;
#endif /* !__wasi__ */
}

int
btc_fs_fstat(int fd, btc_stat_t *out) {
  struct stat st;

  if (fstat(fd, &st) == 0) {
    btc_fs__convert_stat(out, &st);
    return 1;
  }

  return 0;
}

int64_t
btc_fs_seek(int fd, int64_t pos, int whence) {
  int w = 0;

  switch (whence) {
    case BTC_SEEK_SET:
      w = SEEK_SET;
      break;
    case BTC_SEEK_CUR:
      w = SEEK_CUR;
      break;
    case BTC_SEEK_END:
      w = SEEK_END;
      break;
    default:
      return -1;
  }

  return lseek(fd, pos, w);
}

int64_t
btc_fs_tell(int fd) {
  return lseek(fd, 0, SEEK_CUR);
}

int
btc_fs_read(int fd, void *dst, size_t len) {
  unsigned char *buf = (unsigned char *)dst;
  size_t max = SSIZE_MAX;
  ssize_t nread;

  while (len > 0) {
    if (max > len)
      max = len;

    do {
      nread = read(fd, buf, max);
    } while (nread < 0 && (errno == EINTR || errno == EAGAIN));

    if (nread <= 0)
      break;

    if ((size_t)nread > max)
      abort();

    buf += nread;
    len -= nread;
  }

  return len == 0;
}

int
btc_fs_write(int fd, const void *src, size_t len) {
  const unsigned char *buf = (const unsigned char *)src;
  size_t max = SSIZE_MAX;
  ssize_t nwrite;

  while (len > 0) {
    if (max > len)
      max = len;

    do {
      nwrite = write(fd, buf, max);
    } while (nwrite < 0 && (errno == EINTR || errno == EAGAIN));

    if (nwrite <= 0)
      break;

    if ((size_t)nwrite > max)
      abort();

    buf += nwrite;
    len -= nwrite;
  }

  return len == 0;
}

int
btc_fs_pread(int fd, void *dst, size_t len, int64_t pos) {
  unsigned char *buf = (unsigned char *)dst;
  size_t max = SSIZE_MAX;
  ssize_t nread;

  while (len > 0) {
    if (max > len)
      max = len;

    do {
      nread = pread(fd, buf, max, pos);
    } while (nread < 0 && (errno == EINTR || errno == EAGAIN));

    if (nread <= 0)
      break;

    if ((size_t)nread > max)
      abort();

    buf += nread;
    len -= nread;
    pos += nread;
  }

  return len == 0;
}

int
btc_fs_pwrite(int fd, const void *src, size_t len, int64_t pos) {
  const unsigned char *buf = (const unsigned char *)src;
  size_t max = SSIZE_MAX;
  ssize_t nwrite;

#ifdef __APPLE__
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

  if (pthread_mutex_lock(&lock) != 0)
    abort();
#endif

  while (len > 0) {
    if (max > len)
      max = len;

    do {
      nwrite = pwrite(fd, buf, max, pos);
    } while (nwrite < 0 && (errno == EINTR || errno == EAGAIN));

    if (nwrite <= 0)
      break;

    if ((size_t)nwrite > max)
      abort();

    buf += nwrite;
    len -= nwrite;
    pos += nwrite;
  }

#ifdef __APPLE__
  if (pthread_mutex_unlock(&lock) != 0)
    abort();
#endif

  return len == 0;
}

int
btc_fs_ftruncate(int fd, int64_t size) {
  return ftruncate(fd, size) == 0;
}

int
btc_fs_fsync(int fd) {
  /* From libuv. */
#if defined(__APPLE__)
  int r = fcntl(fd, F_FULLFSYNC);

  if (r != 0)
    r = fcntl(fd, 85 /* F_BARRIERFSYNC */);

  if (r != 0)
    r = fsync(fd);

  return r == 0;
#else
  return fsync(fd) == 0;
#endif
}

int
btc_fs_fdatasync(int fd) {
  /* From libuv. */
#if defined(__linux__) || defined(__sun) || defined(__NetBSD__)
  return fdatasync(fd) == 0;
#elif defined(__APPLE__)
  return btc_fs_fsync(fd);
#else
  return fsync(fd) == 0;
#endif
}

int
btc_fs_flock(int fd, int operation) {
#if defined(HAVE_FCNTL) && defined(F_SETLK)
  struct flock fl;
  int type;

  switch (operation) {
    case BTC_LOCK_SH:
      type = F_RDLCK;
      break;
    case BTC_LOCK_EX:
      type = F_WRLCK;
      break;
    case BTC_LOCK_UN:
      type = F_UNLCK;
      break;
    default:
      return 0;
  }

  memset(&fl, 0, sizeof(fl));

  fl.l_type = type;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  return fcntl(fd, F_SETLK, &fl) == 0;
#else
  (void)fd;
  (void)operation;
  return 1;
#endif
}

int
btc_fs_close(int fd) {
  return close(fd) == 0;
}

/*
 * File
 */

btc_file_t *
btc_file_open(const char *name, int flags, uint32_t mode) {
  btc_file_t *file;
  struct stat st;
  int fd;

  fd = btc_fs_open(name, flags, mode);

  if (fd == -1)
    return NULL;

  if (fstat(fd, &st) != 0) {
    close(fd);
    return NULL;
  }

  file = (btc_file_t *)malloc(sizeof(btc_file_t));

  if (file == NULL) {
    close(fd);
    return NULL;
  }

  file->fd = fd;
  file->index = 0;
  file->size = st.st_size;
  file->base = NULL;
  file->mapped = 0;

#ifdef HAVE_MMAP
  if ((flags & BTC_O_MMAP) && sizeof(void *) >= 8) {
    if (file->size > 0) {
      void *base = mmap(NULL, file->size, PROT_READ, MAP_SHARED, fd, 0);

      if (base == MAP_FAILED) {
        btc_file_close(file);
        return NULL;
      }

      file->base = base;

      if (flags & BTC_O_RDONLY) {
        close(file->fd);
        file->fd = -1;
      }
    }

    file->mapped = 1;
  }
#endif

  return file;
}

int
btc_file_pread(const btc_file_t *file,
                 void *dst, size_t len, uint64_t pos) {
  if (len == 0)
    return 1;

  if (pos + len < pos)
    return 0;

  if (pos + len > file->size)
    return 0;

#ifdef HAVE_MMAP
  if (file->base != NULL) {
    memcpy(dst, (const unsigned char *)file->base + pos, len);
    return 1;
  }
#endif

  return btc_fs_pread(file->fd, dst, len, pos);
}

int
btc_file_write(btc_file_t *file, const void *src, size_t len) {
  if (len == 0)
    return 1;

#ifdef HAVE_MMAP
  if (file->base != NULL) {
    if (munmap(file->base, file->size) != 0)
      return 0;

    file->base = NULL;
  }
#endif

  if (!btc_fs_write(file->fd, src, len))
    return 0;

  file->size += len;

#ifdef HAVE_MMAP
  if (file->mapped) {
    void *base = mmap(NULL, file->size, PROT_READ, MAP_SHARED, file->fd, 0);

    if (base == MAP_FAILED)
      return 0;

    file->base = base;
  }
#endif

  return 1;
}

int
btc_file_sync(const btc_file_t *file) {
  return btc_fs_fsync(file->fd);
}

int
btc_file_datasync(const btc_file_t *file) {
  return btc_fs_fdatasync(file->fd);
}

int
btc_file_close(btc_file_t *file) {
  int ret = 1;

#ifdef HAVE_MMAP
  if (file->base != NULL)
    ret &= (munmap(file->base, file->size) == 0);
#endif

  if (file->fd != -1)
    ret &= (close(file->fd) == 0);

  free(file);

  return ret;
}

/*
 * Process
 */

int
btc_ps_cwd(char *buf, size_t size) {
  if (size < 2)
    return 0;

#if defined(__wasi__)
  buf[0] = '/';
  buf[1] = '\0';
#else
  if (getcwd(buf, size) == NULL)
    return 0;

  buf[size - 1] = '\0';
#endif

  return 1;
}

/*
 * Path
 */

static size_t
btc_path_normalize(char *path) {
  /* Logic from Apache[1], modified to handle filesystem
   * paths. This function is necessary on platforms like
   * WASI (where uvwasi does not normalize file paths
   * before checking against preopens).
   *
   * [1] https://github.com/apache/httpd/blob/85ab7bc/server/util.c#L500
   */
  size_t l = 1;
  size_t w = 1;

  if (path[0] != '/') {
    if (path[0] == '\0')
      return 0;

    l = 0;
    w = 0;
  }

  while (path[l] != '\0') {
    if (w == 0 || path[w - 1] == '/') {
      /* Collapse ///// sequences to / */
      if (path[l] == '/') {
        do {
          l += 1;
        } while (path[l] == '/');

        continue;
      }

      if (path[l] == '.') {
        /* Remove /./ segments */
        if (path[l + 1] == '/' || path[l + 1] == '\0') {
          l += 1;

          if (path[l] != '\0')
            l += 1;

          continue;
        }

        /* Remove /xx/../ segments */
        if (path[l + 1] == '.' && (path[l + 2] == '/' || path[l + 2] == '\0')) {
          /* Wind w back to remove the previous segment */
          if (w > 1) {
            do {
              w -= 1;
            } while (w > 0 && path[w - 1] != '/');
          }

          /* Move l forward to the next segment */
          l += 2;

          if (path[l] != '\0')
            l += 1;

          continue;
        }
      }
    }

    path[w++] = path[l++];
  }

  while (w > 1 && path[w - 1] == '/')
    w -= 1;

  path[w] = '\0';

  return w;
}

size_t
btc_path_resolve(char *out, const char *path) {
  char buf[2 * BTC_PATH_MAX + 1];
  size_t plen = path != NULL ? strlen(path) : 0;
  size_t olen;

  if (plen > 0 && path[0] == '/') {
    if (plen > 2 * BTC_PATH_MAX)
      return 0;

    memcpy(buf, path, plen + 1);
  } else {
    if (!btc_ps_cwd(buf, sizeof(buf)))
      return 0;

    olen = strlen(buf);

    if (olen + 1 + plen > 2 * BTC_PATH_MAX)
      return 0;

    if (plen != 0) {
      buf[olen++] = '/';
      memcpy(buf + olen, path, plen + 1);
    }
  }

  olen = btc_path_normalize(buf);

  if (olen > BTC_PATH_MAX)
    return 0;

  memcpy(out, buf, olen + 1);

  return olen;
}

/*
 * System
 */

int
btc_sys_random(void *dst, size_t size) {
#if defined(__wasi__)
  return __wasi_random_get((uint8_t *)dst, size) == 0;
#elif defined(__EMSCRIPTEN__)
  /* Abuse emscripten's UUID generator[1] to get
   * direct access to the node.js RNG. This is
   * avoids us having to access a device which
   * may not exist. Furthermore, this actually
   * works on windows.
   *
   * [1] https://github.com/emscripten-core/emscripten/commit/385a660
   */
  unsigned char *data = (unsigned char *)dst;
  unsigned char uuid[16];
  size_t max = 14;

  while (size > 0) {
    if (max > size)
      max = size;

    uuid_generate(uuid);

    uuid[6] = uuid[14];
    uuid[8] = uuid[15];

    memcpy(dst, uuid, max);

    data += max;
    size -= max;
  }

  return 1;
#else
  int ret;
#if defined(__redox__)
  int fd = btc_fs_open("rand:", BTC_O_RDONLY, 0);
#else
  int fd = btc_fs_open("/dev/urandom", BTC_O_RDONLY, 0);

  if (fd == -1)
    fd = btc_fs_open("/dev/random", BTC_O_RDONLY, 0);
#endif

  if (fd == -1)
    return 0;

  ret = btc_fs_read(fd, dst, size);

  btc_fs_close(fd);

  return ret;
#endif
}

/*
 * Mutex
 */

btc__mutex_t *
btc_mutex_create(void) {
  btc__mutex_t *mtx = (btc__mutex_t *)malloc(sizeof(btc__mutex_t));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

#ifdef HAVE_PTHREAD
  if (pthread_mutex_init(&mtx->handle, NULL) != 0)
    abort();
#endif

  return mtx;
}

void
btc_mutex_destroy(btc__mutex_t *mtx) {
#ifdef HAVE_PTHREAD
  if (pthread_mutex_destroy(&mtx->handle) != 0)
    abort();
#endif

  free(mtx);
}

void
btc_mutex_lock(btc__mutex_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_mutex_lock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_mutex_unlock(btc__mutex_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_mutex_unlock(&mtx->handle) != 0)
    abort();
#endif
}

/*
 * Read-Write Lock
 */

btc__rwlock_t *
btc_rwlock_create(void) {
  btc__rwlock_t *mtx = (btc__rwlock_t *)malloc(sizeof(btc__rwlock_t));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

#ifdef HAVE_PTHREAD
  if (pthread_rwlock_init(&mtx->handle, NULL) != 0)
    abort();
#endif

  return mtx;
}

void
btc_rwlock_destroy(btc__rwlock_t *mtx) {
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_destroy(&mtx->handle) != 0)
    abort();
#endif

  free(mtx);
}

void
btc_rwlock_wrlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_wrlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_wrunlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_rdlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_rdlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_rdunlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort();
#endif
}

/*
 * Time
 */

void
btc_time_get(btc_timespec_t *ts) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort();

  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = (uint32_t)tv.tv_usec * 1000;
}
