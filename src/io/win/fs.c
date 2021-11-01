/*!
 * fs.c - windows filesystem functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 *
 * Parts of this software are based on libuv/libuv:
 *   Copyright (c) 2015-2020, libuv project contributors (MIT License).
 *   https://github.com/libuv/libuv
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <io.h>
#include <io/core.h>

/*
 * Helpers
 */

static void
btc_timespec_set_filetime(btc_timespec_t *ts, const FILETIME *ft) {
  static const uint64_t epoch = UINT64_C(116444736000000000);
  ULARGE_INTEGER ul;

  ul.LowPart = ft->dwLowDateTime;
  ul.HighPart = ft->dwHighDateTime;

  ts->tv_sec = (ul.QuadPart - epoch) / 10000000;
  ts->tv_nsec = ((ul.QuadPart - epoch) % 10000000) * 100;
}

/*
 * Filesystem
 */

int
btc_fs_open(const char *name, int flags, uint32_t mode) {
  DWORD access;
  DWORD share;
  DWORD disposition;
  DWORD attributes;
  HANDLE handle;
  int fd;

  if (flags & BTC_O_MMAP) {
    if (flags & BTC_O_WRONLY)
      flags = (flags & ~BTC_O_WRONLY) | BTC_O_RDWR;
  }

  switch (flags & (BTC_O_RDONLY | BTC_O_WRONLY | BTC_O_RDWR)) {
    case BTC_O_RDONLY:
      access = FILE_GENERIC_READ;
      break;
    case BTC_O_WRONLY:
      access = FILE_GENERIC_WRITE;
      break;
    case BTC_O_RDWR:
      access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
      break;
    default:
      return -1;
  }

  if (flags & BTC_O_APPEND) {
    access &= ~FILE_WRITE_DATA;
    access |= FILE_APPEND_DATA;
  }

  if (!(flags & BTC_O_EXLOCK))
    share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
  else
    share = 0;

  switch (flags & (BTC_O_CREAT | BTC_O_EXCL | BTC_O_TRUNC)) {
    case 0:
    case BTC_O_EXCL:
      disposition = OPEN_EXISTING;
      break;
    case BTC_O_CREAT:
      disposition = OPEN_ALWAYS;
      break;
    case BTC_O_CREAT | BTC_O_EXCL:
    case BTC_O_CREAT | BTC_O_TRUNC | BTC_O_EXCL:
      disposition = CREATE_NEW;
      break;
    case BTC_O_TRUNC:
    case BTC_O_TRUNC | BTC_O_EXCL:
      disposition = TRUNCATE_EXISTING;
      break;
    case BTC_O_CREAT | BTC_O_TRUNC:
      disposition = CREATE_ALWAYS;
      break;
    default:
      return -1;
  }

  attributes = FILE_ATTRIBUTE_NORMAL;

  if (flags & BTC_O_CREAT) {
    if (!(mode & BTC_S_IWUSR))
      attributes |= FILE_ATTRIBUTE_READONLY;
  }

  switch (flags & (BTC_O_SEQUENTIAL | BTC_O_RANDOM)) {
    case 0:
      break;
    case BTC_O_SEQUENTIAL:
      attributes |= FILE_FLAG_SEQUENTIAL_SCAN;
      break;
    case BTC_O_RANDOM:
      attributes |= FILE_FLAG_RANDOM_ACCESS;
      break;
    default:
      return -1;
  }

  switch (flags & (BTC_O_DSYNC | BTC_O_SYNC)) {
    case 0:
      break;
    case BTC_O_DSYNC:
    case BTC_O_SYNC:
      attributes |= FILE_FLAG_WRITE_THROUGH;
      break;
    default:
      return -1;
  }

  attributes |= FILE_FLAG_BACKUP_SEMANTICS;

  handle = CreateFileA(name, access, share, NULL,
                       disposition, attributes, NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  fd = _open_osfhandle((intptr_t)handle, 0);

  if (fd < 0) {
    CloseHandle(handle);
    return -1;
  }

  return fd;
}

static int
btc_fs__stat_handle(HANDLE handle, btc_stat_t *st) {
  BY_HANDLE_FILE_INFORMATION info;
  ULARGE_INTEGER ul_ino, ul_size;

  if (!GetFileInformationByHandle(handle, &info))
    return 0;

  ul_ino.LowPart = info.nFileIndexLow;
  ul_ino.HighPart = info.nFileIndexHigh;

  ul_size.LowPart = info.nFileSizeLow;
  ul_size.HighPart = info.nFileSizeHigh;

  st->st_dev = info.dwVolumeSerialNumber;
  st->st_ino = ul_ino.QuadPart;
  st->st_mode = 0;
  st->st_nlink = info.nNumberOfLinks;
  st->st_uid = 0;
  st->st_gid = 0;
  st->st_rdev = 0;
  st->st_size = ul_size.QuadPart;

  btc_timespec_set_filetime(&st->st_atim, &info.ftLastAccessTime);
  btc_timespec_set_filetime(&st->st_ctim, &info.ftCreationTime);
  btc_timespec_set_filetime(&st->st_mtim, &info.ftLastWriteTime);
  btc_timespec_set_filetime(&st->st_birthtim, &info.ftCreationTime);

  st->st_blksize = 4096;
  st->st_blocks = (st->st_size + 4095) / 4096;

  if (info.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) {
    st->st_mode |= BTC_S_IFCHR;
  } else if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    st->st_mode |= BTC_S_IFLNK;
  } else if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    st->st_mode |= BTC_S_IFDIR;
    st->st_size = 0;
  } else {
    st->st_mode |= BTC_S_IFREG;
  }

  if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
    st->st_mode |= BTC_S_IRUSR;
  else
    st->st_mode |= BTC_S_IRUSR | BTC_S_IWUSR;

  return 1;
}

static int
btc_fs__stat_path(const char *name, btc_stat_t *st, int soft) {
  DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;
  HANDLE handle;
  int ret = 0;

  if (soft)
    flags |= FILE_FLAG_OPEN_REPARSE_POINT;

  handle = CreateFileA(name,
                       FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL,
                       OPEN_EXISTING,
                       flags,
                       NULL);

  if (handle == INVALID_HANDLE_VALUE)
    goto fail;

  if (!btc_fs__stat_handle(handle, st))
    goto fail;

  ret = 1;
fail:
  CloseHandle(handle);
  return ret;
}

int
btc_fs_stat(const char *name, btc_stat_t *out) {
  return btc_fs__stat_path(name, out, 0);
}

int
btc_fs_lstat(const char *name, btc_stat_t *out) {
  if (btc_fs__stat_path(name, out, 1))
    return 1;

  return btc_fs__stat_path(name, out, 0);
}

int
btc_fs_exists(const char *name) {
  return GetFileAttributesA(name) != INVALID_FILE_ATTRIBUTES;
}

int
btc_fs_chmod(const char *name, uint32_t mode) {
  DWORD attributes = GetFileAttributesA(name);

  if (attributes == INVALID_FILE_ATTRIBUTES)
    return 0;

  if (attributes & (FILE_ATTRIBUTE_DEVICE
                  | FILE_ATTRIBUTE_REPARSE_POINT
                  | FILE_ATTRIBUTE_DIRECTORY)) {
    return 1;
  }

  if (mode & BTC_S_IWUSR)
    attributes &= ~FILE_ATTRIBUTE_READONLY;
  else
    attributes |= FILE_ATTRIBUTE_READONLY;

  return SetFileAttributesA(name, attributes) != 0;
}

int
btc_fs_truncate(const char *name, int64_t size) {
  int fd = btc_fs_open(name, BTC_O_WRONLY, 0);
  int ret;

  if (fd == -1)
    return 0;

  ret = btc_fs_ftruncate(fd, size);

  btc_fs_close(fd);

  return ret;
}

int
btc_fs_rename(const char *oldpath, const char *newpath) {
  if (MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING))
    return 1;

  if (ReplaceFileA(newpath, oldpath, NULL,
                   REPLACEFILE_IGNORE_MERGE_ERRORS,
                   NULL, NULL)) {
    return 1;
  }

  return 0;
}

int
btc_fs_unlink(const char *name) {
  DWORD attributes = GetFileAttributesA(name);

  if (attributes != INVALID_FILE_ATTRIBUTES) {
    if (attributes & FILE_ATTRIBUTE_READONLY) {
      attributes &= ~FILE_ATTRIBUTE_READONLY;
      SetFileAttributesA(name, attributes);
    }
  }

  return DeleteFileA(name) != 0;
}

int
btc_fs_mkdir(const char *name, uint32_t mode) {
  (void)mode;
  return CreateDirectoryA(name, NULL) != 0;
}

int
btc_fs_mkdirp(const char *name, uint32_t mode) {
  char path[BTC_PATH_MAX + 1];
  size_t len = strlen(name);
  size_t i;

  (void)mode;

  if (len > BTC_PATH_MAX)
    return 0;

  for (i = 0; i < len + 1; i++) {
    if (name[i] == '/')
      path[i] = '\\';
    else
      path[i] = name[i];
  }

  i = 0;

  if (path[0] >= 'A' && path[0] <= 'Z') {
    if (path[1] == ':' && path[2] == '\0')
      return 1;

    if (path[1] == ':' && path[2] == '\\')
      i += 3;
  }

  while (path[i] == '\\')
    i += 1;

  for (; i < len + 1; i++) {
    if (path[i] != '\\' && path[i] != '\0')
      continue;

    if (i > 0 && path[i - 1] == '\\')
      continue;

    path[i] = '\0';

    if (!CreateDirectoryA(path, NULL)) {
      if (GetLastError() != ERROR_ALREADY_EXISTS)
        return 0;
    }

    path[i] = '\\';
  }

  return 1;
}

int
btc_fs_rmdir(const char *name) {
  return RemoveDirectoryA(name) != 0;
}

static int
btc__dirent_compare(const void *x, const void *y) {
  const btc_dirent_t *a = *((const btc_dirent_t **)x);
  const btc_dirent_t *b = *((const btc_dirent_t **)y);

  return strcmp(a->d_name, b->d_name);
}

int
btc_fs_scandir(const char *name, btc_dirent_t ***out, size_t *count) {
  HANDLE handle = INVALID_HANDLE_VALUE;
  char buf[BTC_PATH_MAX + 1];
  btc_dirent_t **list = NULL;
  btc_dirent_t *item = NULL;
  size_t len = strlen(name);
  WIN32_FIND_DATAA fdata;
  size_t size = 8;
  size_t i = 0;
  size_t j;

  if (len + 3 > BTC_PATH_MAX)
    goto fail;

  if (!(GetFileAttributesA(name) & FILE_ATTRIBUTE_DIRECTORY))
    goto fail;

  list = (btc_dirent_t **)malloc(size * sizeof(btc_dirent_t *));

  if (list == NULL)
    goto fail;

  memcpy(buf, name, len);

  if (len == 0) {
    buf[len++] = '.';
    buf[len++] = '/';
    buf[len++] = '*';
    buf[len++] = '\0';
  } else if (name[len - 1] == '\\' || name[len - 1] == '/') {
    buf[len++] = '*';
    buf[len++] = '\0';
  } else {
    buf[len++] = '\\';
    buf[len++] = '*';
    buf[len++] = '\0';
  }

  handle = FindFirstFileA(buf, &fdata);

  if (handle == INVALID_HANDLE_VALUE) {
    if (GetLastError() != ERROR_FILE_NOT_FOUND)
      goto fail;

    goto succeed;
  }

  do {
    if (strcmp(fdata.cFileName, ".") == 0
        || strcmp(fdata.cFileName, "..") == 0) {
      continue;
    }

    item = (btc_dirent_t *)malloc(sizeof(btc_dirent_t));

    if (item == NULL)
      goto fail;

    len = strlen(fdata.cFileName);

    if (len + 1 > sizeof(item->d_name))
      goto fail;

    if (i == size) {
      size = (size * 3) / 2;
      list = (btc_dirent_t **)realloc(list, size * sizeof(btc_dirent_t *));

      if (list == NULL)
        goto fail;
    }

    item->d_ino = 0;

    if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DEVICE)
      item->d_type = BTC_DT_CHR;
    else if (fdata.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      item->d_type = BTC_DT_LNK;
    else if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      item->d_type = BTC_DT_DIR;
    else
      item->d_type = BTC_DT_REG;

    memcpy(item->d_name, fdata.cFileName, len + 1);

    list[i++] = item;
    item = NULL;
  } while (FindNextFileA(handle, &fdata));

  if (GetLastError() != ERROR_NO_MORE_FILES)
    goto fail;

  FindClose(handle);

  qsort(list, i, sizeof(btc_dirent_t *), btc__dirent_compare);

succeed:
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

  if (handle != INVALID_HANDLE_VALUE)
    FindClose(handle);

  *out = NULL;
  *count = 0;

  return 0;
}

int
btc_fs_fstat(int fd, btc_stat_t *out) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  return btc_fs__stat_handle(handle, out);
}

int64_t
btc_fs_seek(int fd, int64_t pos, int whence) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  LARGE_INTEGER pos_, ptr;
  DWORD method = 0;

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  switch (whence) {
    case BTC_SEEK_SET:
      method = FILE_BEGIN;
      break;
    case BTC_SEEK_CUR:
      method = FILE_CURRENT;
      break;
    case BTC_SEEK_END:
      method = FILE_END;
      break;
    default:
      return -1;
  }

  pos_.QuadPart = pos;

  if (!SetFilePointerEx(handle, pos_, &ptr, method))
    return -1;

  return ptr.QuadPart;
}

int64_t
btc_fs_tell(int fd) {
  return btc_fs_seek(fd, 0, BTC_SEEK_CUR);
}

int
btc_fs_read(int fd, void *dst, size_t len) {
  unsigned char *raw = (unsigned char *)dst;
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  DWORD nread;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  while (len > 0) {
    if (!ReadFile(handle, raw, len, &nread, NULL))
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
  }

  return len == 0;
}

int
btc_fs_write(int fd, const void *src, size_t len) {
  const unsigned char *raw = (const unsigned char *)src;
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  DWORD nread;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  while (len > 0) {
    if (!WriteFile(handle, raw, len, &nread, NULL))
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
  }

  return len == 0;
}

int
btc_fs_pread(int fd, void *dst, size_t len, int64_t pos) {
  unsigned char *raw = (unsigned char *)dst;
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  LARGE_INTEGER zero, old, pos_;
  int restore = 0;
  OVERLAPPED ol;
  DWORD nread;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  zero.QuadPart = 0;

  memset(&ol, 0, sizeof(ol));

  if (SetFilePointerEx(handle, zero, &old, FILE_CURRENT))
    restore = 1;

  while (len > 0) {
    pos_.QuadPart = pos;

    ol.Offset = pos_.LowPart;
    ol.OffsetHigh = pos_.HighPart;

    if (!ReadFile(handle, raw, len, &nread, &ol))
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
    pos += nread;
  }

  if (restore)
    SetFilePointerEx(handle, old, NULL, FILE_BEGIN);

  return len == 0;
}

int
btc_fs_pwrite(int fd, const void *src, size_t len, int64_t pos) {
  const unsigned char *raw = (const unsigned char *)src;
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  LARGE_INTEGER zero, old, pos_;
  int restore = 0;
  OVERLAPPED ol;
  DWORD nread;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  zero.QuadPart = 0;

  memset(&ol, 0, sizeof(ol));

  if (SetFilePointerEx(handle, zero, &old, FILE_CURRENT))
    restore = 1;

  while (len > 0) {
    pos_.QuadPart = pos;

    ol.Offset = pos_.LowPart;
    ol.OffsetHigh = pos_.HighPart;

    if (!WriteFile(handle, raw, len, &nread, &ol))
      break;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
    pos += nread;
  }

  if (restore)
    SetFilePointerEx(handle, old, NULL, FILE_BEGIN);

  return len == 0;
}

int
btc_fs_ftruncate(int fd, int64_t size) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  LARGE_INTEGER pos;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  pos.QuadPart = size;

  if (!SetFilePointerEx(handle, pos, NULL, FILE_BEGIN))
    return 0;

  if (!SetEndOfFile(handle))
    return 0;

  return 1;
}

int
btc_fs_fsync(int fd) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  return FlushFileBuffers(handle) != 0;
}

int
btc_fs_fdatasync(int fd) {
  return btc_fs_fsync(fd);
}

int
btc_fs_flock(int fd, int operation) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  DWORD flags = LOCKFILE_FAIL_IMMEDIATELY;
  OVERLAPPED ol;

  if (handle == INVALID_HANDLE_VALUE)
    return 0;

  memset(&ol, 0, sizeof(ol));

  switch (operation) {
    case BTC_LOCK_EX:
      flags |= LOCKFILE_EXCLUSIVE_LOCK;
    case BTC_LOCK_SH:
      return LockFileEx(handle, flags, 0, MAXDWORD, MAXDWORD, &ol) != 0;
    case BTC_LOCK_UN:
      return UnlockFileEx(handle, 0, MAXDWORD, MAXDWORD, &ol) != 0;
  }

  return 0;
}

int
btc_fs_close(int fd) {
  return _close(fd) == 0;
}

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

/*
 * Path
 */

size_t
btc_path_resolve(char *out, const char *path) {
  char buf[MAX_PATH + 1];
  DWORD len = GetFullPathNameA(path, sizeof(buf), buf, NULL);

  if (len < 1 || len > MAX_PATH)
    return 0;

  if (len > BTC_PATH_MAX)
    return 0;

  memcpy(out, buf, len + 1);

  return len;
}
