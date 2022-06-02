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

#ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

/*
 * Constants
 */

#define LDB_WRITE_BUFFER 65536
#define LDB_MMAP_LIMIT (sizeof(void *) >= 8 ? 1000 : 0)
#define LDB_WIN32_ERROR ldb_convert_error

/*
 * Types
 */

typedef struct ldb_wide_s {
  WCHAR scratch[256];
  WCHAR *data;
} ldb_wide_t;

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
 * Encoding
 */

static size_t
ldb_utf8_size(const WCHAR *xp) {
  return WideCharToMultiByte(CP_UTF8, 0, xp, -1, NULL, 0, NULL, NULL);
}

static int
ldb_utf8_write(char *zp, size_t zn, const WCHAR *xp) {
  return WideCharToMultiByte(CP_UTF8, 0, xp, -1, zp, zn, NULL, NULL) != 0;
}

static size_t
ldb_utf16_size(const char *xp) {
  return MultiByteToWideChar(CP_UTF8, 0, xp, -1, NULL, 0);
}

static int
ldb_utf16_write(WCHAR *zp, size_t zn, const char *xp) {
  return MultiByteToWideChar(CP_UTF8, 0, xp, -1, zp, zn) != 0;
}

/*
 * Wide String
 */

static void
ldb_wide_init(ldb_wide_t *z, size_t zn) {
  if (zn > lengthof(z->scratch))
    z->data = ldb_malloc(zn * sizeof(WCHAR));
  else
    z->data = z->scratch;
}

static void
ldb_wide_clear(ldb_wide_t *z) {
  if (z->data != z->scratch)
    ldb_free(z->data);
}

static int
ldb_wide_import(ldb_wide_t *z, const char *xp) {
  size_t zn = ldb_utf16_size(xp);

  if (zn == 0)
    return 0;

  ldb_wide_init(z, zn);

  if (!ldb_utf16_write(z->data, zn, xp)) {
    ldb_wide_clear(z);
    return 0;
  }

  return 1;
}

static int
ldb_wide_export(char *zp, size_t zn, const ldb_wide_t *x) {
  return ldb_utf8_write(zp, zn, x->data);
}

/*
 * Compat
 */

static int
LDBIsWindowsNT(void) {
  static volatile long state = 0;
  static DWORD version = 0;
  long value;

  while ((value = InterlockedCompareExchange(&state, 1, 0)) == 1)
    Sleep(0);

  if (value == 0) {
    version = GetVersion();

    if (InterlockedExchange(&state, 2) != 1)
      abort(); /* LCOV_EXCL_LINE */
  } else {
    assert(value == 2);
  }

  return version < 0x80000000;
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

static HANDLE
LDBCreateFile(LPCSTR filename,
              DWORD access,
              DWORD share,
              LPSECURITY_ATTRIBUTES attrs,
              DWORD disposition,
              DWORD flags,
              HANDLE temp) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    HANDLE handle;

    if (!ldb_wide_import(&path, filename))
      return INVALID_HANDLE_VALUE;

    handle = CreateFileW(path.data,
                         access,
                         share,
                         attrs,
                         disposition,
                         flags,
                         temp);

    ldb_wide_clear(&path);

    return handle;
  }

  return CreateFileA(filename,
                     access,
                     share,
                     attrs,
                     disposition,
                     flags,
                     temp);
}

static int
LDBGetFullPathNameW(const ldb_wide_t *path, ldb_wide_t *result) {
  DWORD size, len;
  WCHAR ch;

  size = GetFullPathNameW(path->data, 1, &ch, NULL);

  if (size <= 1)
    return 0;

  ldb_wide_init(result, size);

  len = GetFullPathNameW(path->data, size, result->data, NULL);

  if (len == 0 || len >= size) {
    ldb_wide_clear(result);
    return 0;
  }

  return 1;
}

static int
LDBGetEnvironmentVariableW(const WCHAR *name, ldb_wide_t *result) {
  DWORD size, len;
  WCHAR ch;

  size = GetEnvironmentVariableW(name, &ch, 1);

  if (size <= 1)
    return 0;

  ldb_wide_init(result, size);

  len = GetEnvironmentVariableW(name, result->data, size);

  if (len == 0 || len >= size) {
    ldb_wide_clear(result);
    return 0;
  }

  return 1;
}

static int
LDBGetTempPathW(ldb_wide_t *result) {
  DWORD size, len;
  WCHAR ch;

  size = GetTempPathW(1, &ch);

  if (size <= 1)
    return 0;

  ldb_wide_init(result, size);

  len = GetTempPathW(size, result->data);

  if (len == 0 || len >= size) {
    ldb_wide_clear(result);
    return 0;
  }

  return 1;
}

static BOOL
LDBCreateHardLinkW(LPCWSTR to, LPCWSTR from, LPSECURITY_ATTRIBUTES attr) {
  typedef BOOL (WINAPI *P)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
  static volatile long state = 0;
  static P HardLinkW = NULL;
  long value;

  while ((value = InterlockedCompareExchange(&state, 1, 0)) == 1)
    Sleep(0);

  if (value == 0) {
    HMODULE h = GetModuleHandleA("kernel32.dll");

    if (h == NULL)
      abort(); /* LCOV_EXCL_LINE */

    HardLinkW = (P)GetProcAddress(h, "CreateHardLinkW");

    if (InterlockedExchange(&state, 2) != 1)
      abort(); /* LCOV_EXCL_LINE */
  } else {
    assert(value == 2);
  }

  if (HardLinkW == NULL) {
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
  }

  return HardLinkW(to, from, attr);
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
 * Helpers
 */

static int
ldb_convert_error(DWORD code) {
  if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
    return LDB_NOTFOUND;

  return LDB_IOERR;
}

static WCHAR *
ldb_basename_w(const WCHAR *fname) {
  size_t len = lstrlenW(fname);

  while (len > 0) {
    if (fname[len - 1] == L'/' || fname[len - 1] == L'\\')
      break;

    len--;
  }

  return (WCHAR *)fname + len;
}

static int64_t
ldb_read(HANDLE handle, void *dst, size_t len) {
  unsigned char *buf = dst;
  int64_t cnt = 0;

  while (len > 0) {
    DWORD max = LDB_MIN(len, 1 << 30);
    DWORD nread;

    if (!ReadFile(handle, buf, max, &nread, NULL))
      return -1;

    if (nread == 0)
      break;

    buf += nread;
    len -= nread;
    cnt += nread;
  }

  return cnt;
}

static int64_t
ldb_pread(HANDLE handle, void *dst, size_t len, uint64_t off) {
  unsigned char *buf = dst;
  ULARGE_INTEGER ul;
  int64_t cnt = 0;
  OVERLAPPED ol;

  while (len > 0) {
    DWORD max = LDB_MIN(len, 1 << 30);
    DWORD nread;

    memset(&ol, 0, sizeof(ol));

    ul.QuadPart = off;
    ol.OffsetHigh = ul.HighPart;
    ol.Offset = ul.LowPart;

    if (!ReadFile(handle, buf, max, &nread, &ol))
      return -1;

    if (nread == 0)
      break;

    buf += nread;
    len -= nread;
    off += nread;
    cnt += nread;
  }

  return cnt;
}

static int64_t
ldb_write(HANDLE handle, const void *src, size_t len) {
  const unsigned char *buf = src;
  int64_t cnt = 0;

  while (len > 0) {
    DWORD max = LDB_MIN(len, 1 << 30);
    DWORD nwrite;

    if (!WriteFile(handle, buf, max, &nwrite, NULL))
      return -1;

    buf += nwrite;
    len -= nwrite;
    cnt += nwrite;
  }

  return cnt;
}

/*
 * Filesystem
 */

int
ldb_path_absolute(char *buf, size_t size, const char *name) {
  DWORD len;

  if (LDBIsWindowsNT()) {
    ldb_wide_t path, result;
    int ret = 0;

    if (!ldb_wide_import(&path, name))
      return 0;

    if (LDBGetFullPathNameW(&path, &result)) {
      ret = ldb_wide_export(buf, size, &result);
      ldb_wide_clear(&result);
    }

    ldb_wide_clear(&path);

    return ret;
  }

  len = GetFullPathNameA(name, size, buf, NULL);

  return len > 0 && len < size;
}

int
ldb_file_exists(const char *filename) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    DWORD attrs;

    if (!ldb_wide_import(&path, filename))
      return 0;

    attrs = GetFileAttributesW(path.data);

    ldb_wide_clear(&path);

    return attrs != INVALID_FILE_ATTRIBUTES;
  }

  return GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;
}

static int
ldb_get_children_wide(const char *path, char ***out) {
  HANDLE handle = INVALID_HANDLE_VALUE;
  size_t len = ldb_utf16_size(path);
  WIN32_FIND_DATAW fdata;
  char **list = NULL;
  char *name = NULL;
  const WCHAR *base;
  size_t size = 8;
  ldb_wide_t buf;
  size_t i = 0;
  DWORD attrs;
  size_t j;

  if (len == 0) {
    *out = NULL;
    return -1;
  }

  ldb_wide_init(&buf, len + 3);

  if (!ldb_utf16_write(buf.data, len, path))
    goto fail;

  attrs = GetFileAttributesW(buf.data);

  if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY))
    goto fail;

  list = (char **)malloc(size * sizeof(char *));

  if (list == NULL)
    goto fail;

  len--;

  if (len == 0) {
    buf.data[len++] = L'.';
    buf.data[len++] = L'\\';
    buf.data[len++] = L'*';
    buf.data[len++] = L'\0';
  } else if (buf.data[len - 1] == L'\\' || buf.data[len - 1] == L'/') {
    buf.data[len++] = L'*';
    buf.data[len++] = L'\0';
  } else {
    buf.data[len++] = L'\\';
    buf.data[len++] = L'*';
    buf.data[len++] = L'\0';
  }

  handle = FindFirstFileW(buf.data, &fdata);

  if (handle == INVALID_HANDLE_VALUE) {
    if (GetLastError() != ERROR_FILE_NOT_FOUND)
      goto fail;

    goto succeed;
  }

  do {
    base = ldb_basename_w(fdata.cFileName);

    if (lstrcmpW(base, L".") == 0 || lstrcmpW(base, L"..") == 0)
      continue;

    len = ldb_utf8_size(base);

    if (len == 0)
      continue;

    name = (char *)malloc(len);

    if (name == NULL)
      goto fail;

    if (!ldb_utf8_write(name, len, base))
      goto fail;

    if (i == size) {
      size = (size * 3) / 2;
      list = (char **)realloc(list, size * sizeof(char *));

      if (list == NULL)
        goto fail;
    }

    list[i++] = name;
    name = NULL;
  } while (FindNextFileW(handle, &fdata));

  if (GetLastError() != ERROR_NO_MORE_FILES)
    goto fail;

  FindClose(handle);

succeed:
  *out = list;

  ldb_wide_clear(&buf);

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

  ldb_wide_clear(&buf);

  *out = NULL;

  return -1;
}

static int
ldb_get_children_ansi(const char *path, char ***out) {
  HANDLE handle = INVALID_HANDLE_VALUE;
  size_t len = strlen(path);
  WIN32_FIND_DATAA fdata;
  char buf[MAX_PATH];
  char **list = NULL;
  char *name = NULL;
  const char *base;
  size_t size = 8;
  size_t i = 0;
  DWORD attrs;
  size_t j;

  if (len + 4 > sizeof(buf))
    goto fail;

  attrs = GetFileAttributesA(path);

  if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY))
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

int
ldb_get_children(const char *path, char ***out) {
  if (LDBIsWindowsNT())
    return ldb_get_children_wide(path, out);

  return ldb_get_children_ansi(path, out);
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
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    int rc = LDB_OK;

    if (!ldb_wide_import(&path, filename))
      return LDB_INVALID;

    if (!DeleteFileW(path.data))
      rc = LDB_WIN32_ERROR(GetLastError());

    ldb_wide_clear(&path);

    return rc;
  }

  if (!DeleteFileA(filename))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_create_dir(const char *dirname) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    int rc = LDB_OK;

    if (!ldb_wide_import(&path, dirname))
      return LDB_INVALID;

    if (!CreateDirectoryW(path.data, NULL))
      rc = LDB_WIN32_ERROR(GetLastError());

    ldb_wide_clear(&path);

    return rc;
  }

  if (!CreateDirectoryA(dirname, NULL))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_remove_dir(const char *dirname) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    int rc = LDB_OK;

    if (!ldb_wide_import(&path, dirname))
      return LDB_INVALID;

    if (!RemoveDirectoryW(path.data))
      rc = LDB_WIN32_ERROR(GetLastError());

    ldb_wide_clear(&path);

    return rc;
  }

  if (!RemoveDirectoryA(dirname))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_sync_dir(const char *dirname) {
  (void)dirname;
  return LDB_OK;
}

int
ldb_file_size(const char *filename, uint64_t *size) {
  LARGE_INTEGER result;
  HANDLE handle;

  handle = LDBCreateFile(filename,
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
  if (LDBIsWindowsNT()) {
    ldb_wide_t src, dst;
    int rc = LDB_OK;

    if (!ldb_wide_import(&src, from))
      return LDB_INVALID;

    if (!ldb_wide_import(&dst, to)) {
      ldb_wide_clear(&src);
      return LDB_INVALID;
    }

    /* Windows NT only. */
    if (!MoveFileExW(src.data, dst.data, MOVEFILE_REPLACE_EXISTING))
      rc = LDB_WIN32_ERROR(GetLastError());

    ldb_wide_clear(&src);
    ldb_wide_clear(&dst);

    return rc;
  }

  /* Windows 9x fallback (non-atomic). */
  if (!MoveFileA(from, to)) {
    DWORD code = GetLastError();

    if (code != ERROR_ALREADY_EXISTS)
      return LDB_WIN32_ERROR(code);

    if (!DeleteFileA(to))
      return LDB_WIN32_ERROR(GetLastError());

    if (!MoveFileA(from, to))
      return LDB_WIN32_ERROR(GetLastError());
  }

  return LDB_OK;
}

int
ldb_copy_file(const char *from, const char *to) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t src, dst;
    int rc = LDB_OK;

    if (!ldb_wide_import(&src, from))
      return LDB_INVALID;

    if (!ldb_wide_import(&dst, to)) {
      ldb_wide_clear(&src);
      return LDB_INVALID;
    }

    if (!CopyFileW(src.data, dst.data, TRUE))
      rc = LDB_WIN32_ERROR(GetLastError());

    ldb_wide_clear(&src);
    ldb_wide_clear(&dst);

    return rc;
  }

  if (!CopyFileA(from, to, TRUE))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_link_file(const char *from, const char *to) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t src, dst;
    int rc = LDB_OK;

    if (!ldb_wide_import(&src, from))
      return LDB_INVALID;

    if (!ldb_wide_import(&dst, to)) {
      ldb_wide_clear(&src);
      return LDB_INVALID;
    }

    /* Windows 2000 and above (NTFS only). */
    if (!LDBCreateHardLinkW(dst.data, src.data, NULL)) {
      int code = GetLastError();

      if (code == ERROR_INVALID_FUNCTION || /* Not NTFS. */
          code == ERROR_NOT_SAME_DEVICE ||
          code == ERROR_CALL_NOT_IMPLEMENTED) {
        if (!CopyFileW(src.data, dst.data, TRUE))
          rc = LDB_WIN32_ERROR(GetLastError());
      } else {
        rc = LDB_WIN32_ERROR(code);
      }
    }

    ldb_wide_clear(&src);
    ldb_wide_clear(&dst);

    return rc;
  }

  if (!CopyFileA(from, to, TRUE))
    return LDB_WIN32_ERROR(GetLastError());

  return LDB_OK;
}

int
ldb_lock_file(const char *filename, ldb_filelock_t **lock) {
  HANDLE handle = LDBCreateFile(filename,
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ,
                                NULL,
                                OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  if (!LockFile(handle, 0, 0, 4096, 0)) {
    CloseHandle(handle);
    return LDB_IOERR;
  }

  *lock = ldb_malloc(sizeof(ldb_filelock_t));

  (*lock)->handle = handle;

  return LDB_OK;
}

int
ldb_unlock_file(ldb_filelock_t *lock) {
  BOOL result = UnlockFile(lock->handle, 0, 0, 4096, 0);

  CloseHandle(lock->handle);

  ldb_free(lock);

  return result ? LDB_OK : LDB_IOERR;
}

static int
ldb_test_directory_wide(char *result, size_t size) {
  ldb_wide_t path, tmp;
  int ret = 0;

  if (LDBGetEnvironmentVariableW(L"TEST_TMPDIR", &path)) {
    ret = ldb_wide_export(result, size, &path);
    ldb_wide_clear(&path);
  } else if (LDBGetTempPathW(&tmp)) {
    DWORD n = lstrlenW(tmp.data) + 12 + 20 + 1;

    ldb_wide_init(&path, n);

    _snwprintf(path.data, n, L"%sleveldbtest-%lu",
               tmp.data, GetCurrentThreadId());

    CreateDirectoryW(path.data, NULL);

    ret = ldb_wide_export(result, size, &path);

    ldb_wide_clear(&path);
    ldb_wide_clear(&tmp);
  }

  return ret;
}

static int
ldb_test_directory_ansi(char *result, size_t size) {
  char tmp[MAX_PATH];
  DWORD len;

  len = GetEnvironmentVariableA("TEST_TMPDIR", result, size);

  if (len > 0 && len < size)
    return 1;

  if (!GetTempPathA(sizeof(tmp), tmp))
    return 0;

  if (strlen(tmp) + 12 + 20 + 1 > size)
    return 0;

  sprintf(result, "%sleveldbtest-%lu",
          tmp, GetCurrentThreadId());

  CreateDirectoryA(result, NULL);

  return 1;
}

int
ldb_test_directory(char *result, size_t size) {
  if (LDBIsWindowsNT())
    return ldb_test_directory_wide(result, size);

  return ldb_test_directory_ansi(result, size);
}

/*
 * Readable File
 */

struct ldb_rfile_s {
  HANDLE handle;
  ldb_limiter_t *limiter;
  int mapped;
  unsigned char *base;
  size_t length;
  CRITICAL_SECTION mutex;
  int has_mutex;
};

static void
ldb_seqfile_init(ldb_rfile_t *file, HANDLE handle) {
  file->handle = handle;
  file->limiter = NULL;
  file->mapped = 0;
  file->base = NULL;
  file->length = 0;
  file->has_mutex = 0;
}

static void
ldb_randfile_init(ldb_rfile_t *file, HANDLE handle) {
  file->handle = handle;
  file->limiter = NULL;
  file->mapped = 0;
  file->base = NULL;
  file->length = 0;
  file->has_mutex = 0;

  if (!LDBIsWindowsNT()) {
    InitializeCriticalSection(&file->mutex);
    file->has_mutex = 1;
  }
}

static void
ldb_mapfile_init(ldb_rfile_t *file,
                 unsigned char *base,
                 size_t length,
                 ldb_limiter_t *limiter) {
  file->handle = INVALID_HANDLE_VALUE;
  file->limiter = limiter;
  file->mapped = 1;
  file->base = base;
  file->length = length;
  file->has_mutex = 0;
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
  int64_t nread = ldb_read(file->handle, buf, count);

  if (nread < 0)
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
  int64_t nread;

  if (file->mapped) {
    if (offset + count > file->length)
      return LDB_INVALID;

    ldb_slice_set(result, file->base + offset, count);

    return LDB_OK;
  }

  if (file->has_mutex) {
    /* Windows 9x. */
    LARGE_INTEGER dist;

    dist.QuadPart = offset;

    EnterCriticalSection(&file->mutex);

    if (LDBSetFilePointerEx(file->handle, dist, NULL, FILE_BEGIN))
      nread = ldb_read(file->handle, buf, count);
    else
      nread = -1;

    LeaveCriticalSection(&file->mutex);
  } else {
    /* Windows NT. */
    nread = ldb_pread(file->handle, buf, count, offset);
  }

  if (nread >= 0)
    ldb_slice_set(result, buf, nread);

  return nread < 0 ? LDB_IOERR : LDB_OK;
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

  if (file->has_mutex) {
    DeleteCriticalSection(&file->mutex);
    file->has_mutex = 0;
  }

  return rc;
}

/*
 * Readable File Instantiation
 */

int
ldb_seqfile_create(const char *filename, ldb_rfile_t **file) {
  HANDLE handle = LDBCreateFile(filename,
                                GENERIC_READ,
                                FILE_SHARE_READ,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  *file = ldb_malloc(sizeof(ldb_rfile_t));

  ldb_seqfile_init(*file, handle);

  return LDB_OK;
}

int
ldb_randfile_create(const char *filename, ldb_rfile_t **file, int use_mmap) {
  HANDLE mapping = NULL;
  LARGE_INTEGER size;
  int rc = LDB_OK;
  HANDLE handle;

  handle = LDBCreateFile(filename,
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

    ldb_randfile_init(*file, handle);

    return LDB_OK;
  }

  if (!LDBGetFileSizeEx(handle, &size))
    rc = LDB_WIN32_ERROR(GetLastError());

  if (rc == LDB_OK) {
    mapping = CreateFileMappingA(handle, NULL, PAGE_READONLY, 0, 0, NULL);

    if (mapping != NULL) {
      void *base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

      if (base != NULL) {
        *file = ldb_malloc(sizeof(ldb_rfile_t));

        ldb_mapfile_init(*file, base, size.QuadPart, &ldb_mmap_limiter);
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
  HANDLE handle;
  unsigned char buf[LDB_WRITE_BUFFER];
  size_t pos;
};

static void
ldb_wfile_init(ldb_wfile_t *file, HANDLE handle) {
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
  if (ldb_write(file->handle, data, size) < 0)
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
  HANDLE handle = LDBCreateFile(filename,
                                GENERIC_WRITE,
                                0,
                                NULL,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return LDB_WIN32_ERROR(GetLastError());

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, handle);

  return LDB_OK;
}

int
ldb_appendfile_create(const char *filename, ldb_wfile_t **file) {
  HANDLE handle = LDBCreateFile(filename,
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

  ldb_wfile_init(*file, handle);

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

int
ldb_logger_open(const char *filename, ldb_logger_t **result) {
  FILE *stream;

  if (LDBIsWindowsNT()) {
    ldb_wide_t path;

    if (!ldb_wide_import(&path, filename))
      return LDB_INVALID;

    stream = _wfopen(path.data, L"w"); /* L"wN" */

    ldb_wide_clear(&path);
  } else {
    stream = fopen(filename, "w"); /* "wN" */
  }

  if (stream == NULL)
    return LDB_WIN32_ERROR(GetLastError());

  *result = ldb_logger_fopen(stream);

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
