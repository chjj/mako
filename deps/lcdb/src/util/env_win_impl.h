/*!
 * env_win_impl.h - win32 environment for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "env.h"
#include "internal.h"
#include "slice.h"
#include "status.h"
#include "strutil.h"

/*
 * Constants
 */

#define LDB_WRITE_BUFFER 65536
#define LDB_MMAP_LIMIT (sizeof(void *) >= 8 ? 1000 : 0)
#define LDB_WIN32_ERROR ldb_convert_error

/*
 * Types
 */

typedef struct ldb_limiter_s {
  volatile long acquires_allowed;
  int max_acquires;
} ldb_limiter_t;

struct ldb_filelock_s {
  HANDLE handle;
};

/*
 * Globals
 */

static ldb_limiter_t ldb_mmap_limiter = {LDB_MMAP_LIMIT, LDB_MMAP_LIMIT};

/*
 * Compat
 */

static BOOL (WINAPI *LDBMoveFileExA)(LPCSTR, LPCSTR, DWORD) = NULL;
static BOOL (WINAPI *LDBGetFileAttributesExA)(LPCSTR,
                                              GET_FILEEX_INFO_LEVELS,
                                              LPVOID) = NULL;

static void
ldb_load_functions(void) {
  static volatile long state = 0;
  HMODULE handle;
  long value;

  /* Logic from libsodium/core.c */
  while ((value = InterlockedCompareExchange(&state, 1, 0)) == 1)
    Sleep(0);

  if (value == 0) {
    handle = GetModuleHandleA("kernel32.dll");

    if (handle == NULL)
      abort(); /* LCOV_EXCL_LINE */

    /* Available only on Windows NT (not 9x). */
    *((FARPROC *)&LDBMoveFileExA) = GetProcAddress(handle, "MoveFileExA");

    /* Available only on Windows 98 and above. */
    *((FARPROC *)&LDBGetFileAttributesExA) = GetProcAddress(handle,
                                               "GetFileAttributesExA");

    if (InterlockedExchange(&state, 2) != 1)
      abort(); /* LCOV_EXCL_LINE */
  } else {
    assert(value == 2);
  }
}

static BOOL
LDBSetFilePointerEx(HANDLE file,
                    LARGE_INTEGER pos,
                    LARGE_INTEGER *rpos,
                    DWORD method) {
  pos.LowPart = SetFilePointer(file, pos.LowPart, &pos.HighPart, method);

  if (pos.LowPart == (DWORD)-1) { /* INVALID_SET_FILE_POINTER */
    if (GetLastError() != NO_ERROR)
      return FALSE;
  }

  if (rpos != NULL)
    *rpos = pos;

  return TRUE;
}

static BOOL
LDBGetFileSizeEx(HANDLE file, LARGE_INTEGER *size) {
  DWORD HighPart = 0;

  size->LowPart = GetFileSize(file, &HighPart);
  size->HighPart = HighPart;

  if (size->LowPart == (DWORD)-1) { /* INVALID_FILE_SIZE */
    if (GetLastError() != NO_ERROR)
      return FALSE;
  }

  return TRUE;
}

/*
 * Limiter
 */

static int
ldb_limiter_acquire(ldb_limiter_t *lim) {
  int old;

  old = InterlockedExchangeAdd(&lim->acquires_allowed, -1);

  if (old > 0)
    return 1;

  old = InterlockedExchangeAdd(&lim->acquires_allowed, 1);

  assert(old < lim->max_acquires);

  (void)old;

  return 0;
}

static void
ldb_limiter_release(ldb_limiter_t *lim) {
  int old = InterlockedExchangeAdd(&lim->acquires_allowed, 1);

  assert(old < lim->max_acquires);

  (void)old;
}

/*
 * File Helpers
 */

static int
ldb_convert_error(DWORD code) {
  if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
    return LDB_NOTFOUND;

  return LDB_IOERR;
}

static int
ldb_lock_or_unlock(HANDLE handle, int lock) {
  if (lock)
    return LockFile(handle, 0, 0, MAXDWORD, MAXDWORD);

  return UnlockFile(handle, 0, 0, MAXDWORD, MAXDWORD);
}

/*
 * Filesystem
 */

int
ldb_path_absolute(char *buf, size_t size, const char *name) {
  DWORD len = GetFullPathNameA(name, size, buf, NULL);
  DWORD i;

  if (len < 1 || len >= size)
    return 0;

  for (i = 0; i < len; i++) {
    if (buf[i] == '/')
      buf[i] = '\\';
  }

  return 1;
}

int
ldb_file_exists(const char *filename) {
  return GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;
}

int
ldb_get_children(const char *path, char ***out) {
  HANDLE handle = INVALID_HANDLE_VALUE;
  size_t len = strlen(path);
  WIN32_FIND_DATAA fdata;
  char buf[LDB_PATH_MAX];
  char **list = NULL;
  char *name = NULL;
  const char *base;
  size_t size = 8;
  size_t i = 0;
  size_t j;

  if (len + 4 > sizeof(buf))
    goto fail;

  if (!(GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY))
    goto fail;

  list = (char **)malloc(size * sizeof(char *));

  if (list == NULL)
    goto fail;

  memcpy(buf, path, len);

  if (len == 0) {
    buf[len++] = '.';
    buf[len++] = '\\';
    buf[len++] = '*';
    buf[len++] = '\0';
  } else if (path[len - 1] == '\\' || path[len - 1] == '/') {
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
    base = ldb_basename(fdata.cFileName);

    if (strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
      continue;

    len = strlen(base);
    name = (char *)malloc(len + 1);

    if (name == NULL)
      goto fail;

    memcpy(name, base, len + 1);

    if (i == size) {
      size = (size * 3) / 2;
      list = (char **)realloc(list, size * sizeof(char *));

      if (list == NULL)
        goto fail;
    }

    list[i++] = name;
    name = NULL;
  } while (FindNextFileA(handle, &fdata));

  if (GetLastError() != ERROR_NO_MORE_FILES)
    goto fail;

  FindClose(handle);

succeed:
  *out = list;

  return i;
fail:
  for (j = 0; j < i; j++)
    ldb_free(list[j]);

  if (list != NULL)
    ldb_free(list);

  if (name != NULL)
    ldb_free(name);

  if (handle != INVALID_HANDLE_VALUE)
    FindClose(handle);

  *out = NULL;

  return -1;
}

void
ldb_free_children(char **list, int len) {
  int i;

  for (i = 0; i < len; i++)
    ldb_free(list[i]);

  ldb_free(list);
}

int
ldb_remove_file(const char *filename) {
  if (!DeleteFileA(filename))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_create_dir(const char *dirname) {
  if (!CreateDirectoryA(dirname, NULL))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_remove_dir(const char *dirname) {
  if (!RemoveDirectoryA(dirname))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_get_file_size(const char *filename, uint64_t *size) {
  LARGE_INTEGER result;
  HANDLE handle;

  ldb_load_functions();

  /* Windows 98 and above only. */
  if (LDBGetFileAttributesExA != NULL) {
    WIN32_FILE_ATTRIBUTE_DATA attrs;

    if (!LDBGetFileAttributesExA(filename, GetFileExInfoStandard, &attrs))
      return LDB_WIN32_ERROR(GetLastError());

    result.HighPart = attrs.nFileSizeHigh;
    result.LowPart = attrs.nFileSizeLow;

    *size = result.QuadPart;

    return LDB_OK;
  }

  /* Windows 95 fallback. */
  handle = CreateFileA(filename,
                       0,
                       0,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  if (!LDBGetFileSizeEx(handle, &result)) {
    DWORD code = GetLastError();
    CloseHandle(handle);
    return LDB_WIN32_ERROR(code);
  }

  CloseHandle(handle);

  *size = result.QuadPart;

  return LDB_OK;
}

int
ldb_rename_file(const char *from, const char *to) {
  ldb_load_functions();

  /* Windows NT only. */
  if (LDBMoveFileExA != NULL) {
    if (!LDBMoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING))
      return LDB_WIN32_ERROR(GetLastError());

    return LDB_OK;
  }

  /* Windows 9x fallback (non-atomic). */
  if (!MoveFileA(from, to)) {
    DWORD code = GetLastError();

    if (!DeleteFileA(to))
      return LDB_WIN32_ERROR(code);

    if (!MoveFileA(from, to))
      return LDB_WIN32_ERROR(code);
  }

  return LDB_OK;
}

int
ldb_lock_file(const char *filename, ldb_filelock_t **lock) {
  HANDLE handle = CreateFileA(filename,
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  if (!ldb_lock_or_unlock(handle, 1)) {
    CloseHandle(handle);
    return LDB_IOERR;
  }

  *lock = ldb_malloc(sizeof(ldb_filelock_t));

  (*lock)->handle = handle;

  return LDB_OK;
}

int
ldb_unlock_file(ldb_filelock_t *lock) {
  int ok = ldb_lock_or_unlock(lock->handle, 0);

  CloseHandle(lock->handle);

  ldb_free(lock);

  return ok ? LDB_OK : LDB_IOERR;
}

int
ldb_test_directory(char *result, size_t size) {
  char path[MAX_PATH];
  DWORD len, tid;

  len = GetEnvironmentVariableA("TEST_TMPDIR", result, size);

  if (len >= 1 && len < size)
    return 1;

  if (!GetTempPathA(sizeof(path), path))
    return 0;

  if (strlen(path) + 12 + 20 + 1 > size)
    return 0;

  tid = GetCurrentThreadId();

  sprintf(result, "%sleveldbtest-%lu", path, (unsigned long)tid);

  CreateDirectoryA(result, NULL);

  return 1;
}

/*
 * Readable File
 */

struct ldb_rfile_s {
  char filename[LDB_PATH_MAX];
  HANDLE handle;
  ldb_limiter_t *limiter;
  int mapped;
  unsigned char *base;
  size_t length;
};

static void
ldb_rfile_init(ldb_rfile_t *file, const char *filename, HANDLE handle) {
  strcpy(file->filename, filename);

  file->handle = handle;
  file->limiter = NULL;
  file->mapped = 0;
  file->base = NULL;
  file->length = 0;
}

static void
ldb_mapfile_init(ldb_rfile_t *file,
                 const char *filename,
                 unsigned char *base,
                 size_t length,
                 ldb_limiter_t *limiter) {
  strcpy(file->filename, filename);

  file->handle = INVALID_HANDLE_VALUE;
  file->limiter = limiter;
  file->mapped = 1;
  file->base = base;
  file->length = length;
}

int
ldb_rfile_mapped(ldb_rfile_t *file) {
  return file->mapped;
}

int
ldb_rfile_read(ldb_rfile_t *file,
               ldb_slice_t *result,
               void *buf,
               size_t count) {
  DWORD nread = 0;

  if (!ReadFile(file->handle, buf, count, &nread, NULL))
    return LDB_IOERR;

  ldb_slice_set(result, buf, nread);

  return LDB_OK;
}

int
ldb_rfile_skip(ldb_rfile_t *file, uint64_t offset) {
  LARGE_INTEGER dist;

  dist.QuadPart = offset;

  if (!LDBSetFilePointerEx(file->handle, dist, NULL, FILE_CURRENT))
    return LDB_IOERR;

  return LDB_OK;
}

int
ldb_rfile_pread(ldb_rfile_t *file,
                ldb_slice_t *result,
                void *buf,
                size_t count,
                uint64_t offset) {
  DWORD nread = 0;
  OVERLAPPED ol;

  if (file->mapped) {
    if (offset + count > file->length)
      return LDB_INVALID;

    ldb_slice_set(result, file->base + offset, count);

    return LDB_OK;
  }

  memset(&ol, 0, sizeof(ol));

  ol.OffsetHigh = (DWORD)(offset >> 32);
  ol.Offset = (DWORD)offset;

  if (!ReadFile(file->handle, buf, (DWORD)count, &nread, &ol))
    return LDB_IOERR;

  ldb_slice_set(result, buf, nread);

  return LDB_OK;
}

static int
ldb_rfile_close(ldb_rfile_t *file) {
  int rc = LDB_OK;

  if (file->handle != INVALID_HANDLE_VALUE) {
    if (!CloseHandle(file->handle))
      rc = LDB_IOERR;
  }

  if (file->limiter != NULL)
    ldb_limiter_release(file->limiter);

  if (file->mapped)
    UnmapViewOfFile((void *)file->base);

  file->handle = INVALID_HANDLE_VALUE;
  file->limiter = NULL;
  file->mapped = 0;
  file->base = NULL;
  file->length = 0;

  return rc;
}

/*
 * Readable File Instantiation
 */

int
ldb_seqfile_create(const char *filename, ldb_rfile_t **file) {
  HANDLE handle;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  handle = CreateFileA(filename,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  *file = ldb_malloc(sizeof(ldb_rfile_t));

  ldb_rfile_init(*file, filename, handle);

  return LDB_OK;
}

int
ldb_randfile_create(const char *filename, ldb_rfile_t **file, int use_mmap) {
  HANDLE mapping = NULL;
  LARGE_INTEGER size;
  int rc = LDB_OK;
  HANDLE handle;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  handle = CreateFileA(filename,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_READONLY,
                       NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  if (!use_mmap || !ldb_limiter_acquire(&ldb_mmap_limiter)) {
    *file = ldb_malloc(sizeof(ldb_rfile_t));

    ldb_rfile_init(*file, filename, handle);

    return LDB_OK;
  }

  if (!LDBGetFileSizeEx(handle, &size))
    rc = LDB_WIN32_ERROR(GetLastError());

  if (rc == LDB_OK && (uint64_t)size.QuadPart > (((size_t)-1) / 2))
    rc = LDB_IOERR;

  if (rc == LDB_OK) {
    mapping = CreateFileMappingA(handle, NULL, PAGE_READONLY, 0, 0, NULL);

    if (mapping != NULL) {
      void *base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

      if (base != NULL) {
        *file = ldb_malloc(sizeof(ldb_rfile_t));

        ldb_mapfile_init(*file,
                         filename,
                         base,
                         size.QuadPart,
                         &ldb_mmap_limiter);
      } else {
        rc = LDB_IOERR;
      }
    }
  }

  if (mapping != NULL)
    CloseHandle(mapping);

  CloseHandle(handle);

  if (rc != LDB_OK)
    ldb_limiter_release(&ldb_mmap_limiter);

  return rc;
}

void
ldb_rfile_destroy(ldb_rfile_t *file) {
  ldb_rfile_close(file);
  ldb_free(file);
}

/*
 * Writable File
 */

struct ldb_wfile_s {
  char filename[LDB_PATH_MAX];
  HANDLE handle;
  unsigned char buf[LDB_WRITE_BUFFER];
  size_t pos;
};

static void
ldb_wfile_init(ldb_wfile_t *file, const char *filename, HANDLE handle) {
  strcpy(file->filename, filename);

  file->handle = handle;
  file->pos = 0;
}

int
ldb_wfile_close(ldb_wfile_t *file) {
  int rc = ldb_wfile_flush(file);

  if (!CloseHandle(file->handle) && rc == LDB_OK)
    rc = LDB_IOERR;

  file->handle = INVALID_HANDLE_VALUE;

  return rc;
}

static int
ldb_wfile_write(ldb_wfile_t *file, const unsigned char *data, size_t size) {
  DWORD nwrite = 0;

  if (!WriteFile(file->handle, data, (DWORD)size, &nwrite, NULL))
    return LDB_IOERR;

  return LDB_OK;
}

int
ldb_wfile_append(ldb_wfile_t *file, const ldb_slice_t *data) {
  const unsigned char *write_data = data->data;
  size_t write_size = data->size;
  size_t copy_size;
  int rc;

  copy_size = LDB_MIN(write_size, LDB_WRITE_BUFFER - file->pos);

  memcpy(file->buf + file->pos, write_data, copy_size);

  write_data += copy_size;
  write_size -= copy_size;
  file->pos += copy_size;

  if (write_size == 0)
    return LDB_OK;

  if ((rc = ldb_wfile_flush(file)))
    return rc;

  if (write_size < LDB_WRITE_BUFFER) {
    memcpy(file->buf, write_data, write_size);
    file->pos = write_size;
    return LDB_OK;
  }

  return ldb_wfile_write(file, write_data, write_size);
}

int
ldb_wfile_flush(ldb_wfile_t *file) {
  int rc = ldb_wfile_write(file, file->buf, file->pos);
  file->pos = 0;
  return rc;
}

int
ldb_wfile_sync(ldb_wfile_t *file) {
  int rc;

  if ((rc = ldb_wfile_flush(file)))
    return rc;

  if (!FlushFileBuffers(file->handle))
    return LDB_IOERR;

  return LDB_OK;
}

/*
 * Writable File Instantiation
 */

int
ldb_truncfile_create(const char *filename, ldb_wfile_t **file) {
  HANDLE handle;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  handle = CreateFileA(filename,
                       GENERIC_WRITE,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, filename, handle);

  return LDB_OK;
}

int
ldb_appendfile_create(const char *filename, ldb_wfile_t **file) {
  HANDLE handle;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  handle = CreateFileA(filename,
                       GENERIC_WRITE,
                       0,
                       NULL,
                       OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  if (SetFilePointer(handle, 0, NULL, FILE_END) == (DWORD)-1) {
    DWORD code = GetLastError();
    if (code != NO_ERROR) {
      CloseHandle(handle);
      return LDB_WIN32_ERROR(code);
    }
  }

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, filename, handle);

  return LDB_OK;
}

void
ldb_wfile_destroy(ldb_wfile_t *file) {
  if (file->handle != INVALID_HANDLE_VALUE)
    CloseHandle(file->handle);

  ldb_free(file);
}

/*
 * Logging
 */

ldb_logger_t *
ldb_logger_create(FILE *stream);

int
ldb_logger_open(const char *filename, ldb_logger_t **result) {
  FILE *stream = fopen(filename, "w"); /* "wN" */

  if (stream == NULL)
    return LDB_WIN32_ERROR(GetLastError());

  *result = ldb_logger_create(stream);

  return LDB_OK;
}

/*
 * Time
 */

int64_t
ldb_now_usec(void) {
  uint64_t ticks;
  FILETIME ft;

  GetSystemTimeAsFileTime(&ft);

  ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

  return ticks / 10;
}

void
ldb_sleep_usec(int64_t usec) {
  if (usec < 0)
    usec = 0;

  Sleep(usec / 1000);
}
