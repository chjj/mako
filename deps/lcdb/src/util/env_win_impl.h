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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "atomic.h"
#include "buffer.h"
#include "env.h"
#include "internal.h"
#include "slice.h"
#include "status.h"
#include "strutil.h"

/*
 * Fixes
 */

#ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

#ifndef INVALID_FILE_ATTRIBUTES
#  define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif

/*
 * Constants
 */

#define LDB_WRITE_BUFFER 65536
#define LDB_MMAP_LIMIT (sizeof(void *) >= 8 ? 1000 : 0)

/*
 * Types
 */

typedef struct ldb_wide_s {
  WCHAR scratch[256];
  WCHAR *data;
} ldb_wide_t;

typedef struct ldb_limiter_s {
  ldb_atomic(int) acquires_allowed;
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
  static ldb_atomic(int) state = 0;
  static DWORD version = 0;
  int value;

  while ((value = ldb_atomic_compare_exchange(&state, 0, 1)) == 1)
    Sleep(0);

  if (value == 0) {
    version = GetVersion();

    if (ldb_atomic_exchange(&state, 2) != 1)
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
    if (GetLastError() != ERROR_SUCCESS)
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
    if (GetLastError() != ERROR_SUCCESS)
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
  static ldb_atomic(int) state = 0;
  static P HardLinkW = NULL;
  int value;

  while ((value = ldb_atomic_compare_exchange(&state, 0, 1)) == 1)
    Sleep(0);

  if (value == 0) {
    HMODULE h = GetModuleHandleA("kernel32.dll");

    if (h == NULL)
      abort(); /* LCOV_EXCL_LINE */

    HardLinkW = (P)GetProcAddress(h, "CreateHardLinkW");

    if (ldb_atomic_exchange(&state, 2) != 1)
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

  old = ldb_atomic_fetch_sub(&lim->acquires_allowed, 1, ldb_order_relaxed);

  if (old > 0)
    return 1;

  old = ldb_atomic_fetch_add(&lim->acquires_allowed, 1, ldb_order_relaxed);

  assert(old < lim->max_acquires);

  (void)old;

  return 0;
}

static void
ldb_limiter_release(ldb_limiter_t *lim) {
  int old = ldb_atomic_fetch_add(&lim->acquires_allowed, 1, ldb_order_relaxed);

  assert(old < lim->max_acquires);

  (void)old;
}

/*
 * Errors
 */

static DWORD
tls_index_get(void) {
  static ldb_atomic(int) state = 0;
  static DWORD tls_index = 0;
  int value;

  while ((value = ldb_atomic_compare_exchange(&state, 0, 1)) == 1)
    Sleep(0);

  if (value == 0) {
    tls_index = TlsAlloc();

    if (tls_index == TLS_OUT_OF_INDEXES)
      abort(); /* LCOV_EXCL_LINE */

    if (ldb_atomic_exchange(&state, 2) != 1)
      abort(); /* LCOV_EXCL_LINE */
  } else {
    assert(value == 2);
  }

  return tls_index;
}

static char *
tls_buffer_get(size_t size) {
  DWORD tls_index = tls_index_get();
  void *ptr;

  ptr = TlsGetValue(tls_index);

  if (ptr == NULL) {
    if (GetLastError() != ERROR_SUCCESS)
      abort(); /* LCOV_EXCL_LINE */

    ptr = ldb_malloc(size);

    if (!TlsSetValue(tls_index, ptr))
      abort(); /* LCOV_EXCL_LINE */
  }

  return ptr;
}

static int
ldb_convert_error(DWORD code) {
  if (code == ERROR_SUCCESS || code > INT_MAX)
    return LDB_IOERR;

  if (code == ERROR_PATH_NOT_FOUND)
    return ERROR_FILE_NOT_FOUND;

  return code;
}

int
ldb_system_error(void) {
  return ldb_convert_error(GetLastError());
}

const char *
ldb_error_string(int code) {
  char *errbuf = tls_buffer_get(1024);
  DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS;
  DWORD result;

  if (LDBIsWindowsNT()) {
    WCHAR tmpbuf[512];

    result = FormatMessageW(flags, NULL, code, 0, tmpbuf, 512, NULL);

    if (result)
      result = ldb_utf8_write(errbuf, 1024, tmpbuf);
  } else {
    result = FormatMessageA(flags, NULL, code, 0, errbuf, 1024, NULL);
  }

  if (!result)
    sprintf(errbuf, "Unknown error %d", code);

  return errbuf;
}

/*
 * Helpers
 */

static int
ldb_is_manifest(const char *filename) {
  const char *base = ldb_basename(filename);
  return ldb_starts_with(base, "MANIFEST");
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
    DWORD nread = 0;

    memset(&ol, 0, sizeof(ol));

    ul.QuadPart = off;
    ol.OffsetHigh = ul.HighPart;
    ol.Offset = ul.LowPart;

    if (!ReadFile(handle, buf, max, &nread, &ol)) {
      if (GetLastError() != ERROR_HANDLE_EOF)
        return -1;
    }

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
  void *ptr;
  size_t j;

  if (len == 0) {
    *out = NULL;
    return -1;
  }

  ldb_wide_init(&buf, len + 3);

  if (!ldb_utf16_write(buf.data, len, path))
    goto fail;

  attrs = GetFileAttributesW(buf.data);

  if (attrs == INVALID_FILE_ATTRIBUTES)
    goto fail;

  if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    SetLastError(ERROR_DIRECTORY);
    goto fail;
  }

  list = (char **)malloc(size * sizeof(char *));

  if (list == NULL) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    goto fail;
  }

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

    if (name == NULL) {
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      goto fail;
    }

    if (!ldb_utf8_write(name, len, base))
      goto fail;

    if (i == size) {
      size = (size * 3) / 2;
      ptr = realloc(list, size * sizeof(char *));

      if (ptr == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto fail;
      }

      list = (char **)ptr;
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
    free(list[j]);

  if (list != NULL)
    free(list);

  if (name != NULL)
    free(name);

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
  void *ptr;
  size_t j;

  if (len + 4 > sizeof(buf)) {
    SetLastError(ERROR_BUFFER_OVERFLOW);
    goto fail;
  }

  attrs = GetFileAttributesA(path);

  if (attrs == INVALID_FILE_ATTRIBUTES)
    goto fail;

  if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    SetLastError(ERROR_DIRECTORY);
    goto fail;
  }

  list = (char **)malloc(size * sizeof(char *));

  if (list == NULL) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    goto fail;
  }

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

    if (name == NULL) {
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      goto fail;
    }

    memcpy(name, base, len + 1);

    if (i == size) {
      size = (size * 3) / 2;
      ptr = realloc(list, size * sizeof(char *));

      if (ptr == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto fail;
      }

      list = (char **)ptr;
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
    free(list[j]);

  if (list != NULL)
    free(list);

  if (name != NULL)
    free(name);

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
    free(list[i]);

  if (list != NULL)
    free(list);
}

int
ldb_remove_file(const char *filename) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    int rc = LDB_OK;

    if (!ldb_wide_import(&path, filename))
      return ldb_system_error();

    if (!DeleteFileW(path.data))
      rc = ldb_system_error();

    ldb_wide_clear(&path);

    return rc;
  }

  if (!DeleteFileA(filename))
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_create_dir(const char *dirname) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    int rc = LDB_OK;

    if (!ldb_wide_import(&path, dirname))
      return ldb_system_error();

    if (!CreateDirectoryW(path.data, NULL))
      rc = ldb_system_error();

    ldb_wide_clear(&path);

    return rc;
  }

  if (!CreateDirectoryA(dirname, NULL))
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_remove_dir(const char *dirname) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t path;
    int rc = LDB_OK;

    if (!ldb_wide_import(&path, dirname))
      return ldb_system_error();

    if (!RemoveDirectoryW(path.data))
      rc = ldb_system_error();

    ldb_wide_clear(&path);

    return rc;
  }

  if (!RemoveDirectoryA(dirname))
    return ldb_system_error();

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
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return ldb_system_error();

  if (!LDBGetFileSizeEx(handle, &result)) {
    int rc = ldb_system_error();
    CloseHandle(handle);
    return rc;
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
      return ldb_system_error();

    if (!ldb_wide_import(&dst, to)) {
      ldb_wide_clear(&src);
      return ldb_system_error();
    }

    /* Windows NT only. */
    if (!MoveFileExW(src.data, dst.data, MOVEFILE_REPLACE_EXISTING))
      rc = ldb_system_error();

    ldb_wide_clear(&src);
    ldb_wide_clear(&dst);

    return rc;
  }

  /* Windows 9x fallback (non-atomic). */
  if (!MoveFileA(from, to)) {
    DWORD code = GetLastError();

    if (code != ERROR_ALREADY_EXISTS)
      return ldb_convert_error(code);

    if (!DeleteFileA(to))
      return ldb_system_error();

    if (!MoveFileA(from, to))
      return ldb_system_error();
  }

  return LDB_OK;
}

int
ldb_copy_file(const char *from, const char *to) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t src, dst;
    int rc = LDB_OK;

    if (!ldb_wide_import(&src, from))
      return ldb_system_error();

    if (!ldb_wide_import(&dst, to)) {
      ldb_wide_clear(&src);
      return ldb_system_error();
    }

    if (!CopyFileW(src.data, dst.data, TRUE))
      rc = ldb_system_error();

    ldb_wide_clear(&src);
    ldb_wide_clear(&dst);

    return rc;
  }

  if (!CopyFileA(from, to, TRUE))
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_link_file(const char *from, const char *to) {
  if (LDBIsWindowsNT()) {
    ldb_wide_t src, dst;
    int rc = LDB_OK;

    if (!ldb_wide_import(&src, from))
      return ldb_system_error();

    if (!ldb_wide_import(&dst, to)) {
      ldb_wide_clear(&src);
      return ldb_system_error();
    }

    /* Windows 2000 and above (NTFS only). */
    if (!LDBCreateHardLinkW(dst.data, src.data, NULL)) {
      DWORD code = GetLastError();

      if (code == ERROR_INVALID_FUNCTION || /* Not NTFS. */
          code == ERROR_NOT_SAME_DEVICE ||
          code == ERROR_CALL_NOT_IMPLEMENTED) {
        if (!CopyFileW(src.data, dst.data, TRUE))
          rc = ldb_system_error();
      } else {
        rc = ldb_convert_error(code);
      }
    }

    ldb_wide_clear(&src);
    ldb_wide_clear(&dst);

    return rc;
  }

  if (!CopyFileA(from, to, TRUE))
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_lock_file(const char *filename, ldb_filelock_t **lock) {
  HANDLE handle = LDBCreateFile(filename,
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return ldb_system_error();

  if (!LockFile(handle, 0, 0, 1, 0)) {
    int rc = ldb_system_error();
    CloseHandle(handle);
    return rc;
  }

  *lock = ldb_malloc(sizeof(ldb_filelock_t));

  (*lock)->handle = handle;

  return LDB_OK;
}

int
ldb_unlock_file(ldb_filelock_t *lock) {
  int rc = LDB_OK;

  if (!UnlockFile(lock->handle, 0, 0, 1, 0))
    rc = ldb_system_error();

  CloseHandle(lock->handle);

  ldb_free(lock);

  return rc;
}

static int
ldb_test_directory_wide(char *result, size_t size) {
  ldb_wide_t path, tmp;
  int ret = 0;

  if (LDBGetEnvironmentVariableW(L"TEST_TMPDIR", &path)) {
    ret = ldb_wide_export(result, size, &path);
    ldb_wide_clear(&path);
  } else if (LDBGetTempPathW(&tmp)) {
    DWORD n = lstrlenW(tmp.data) + 11 + 1;

    ldb_wide_init(&path, n);

    _snwprintf(path.data, n, L"%sleveldbtest", tmp.data);

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

  if (strlen(tmp) + 11 + 1 > size)
    return 0;

  sprintf(result, "%sleveldbtest", tmp);

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
 * ReadableFile (backend)
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
    return ldb_system_error();

  ldb_slice_set(result, buf, nread);

  return LDB_OK;
}

int
ldb_rfile_skip(ldb_rfile_t *file, uint64_t offset) {
  LARGE_INTEGER dist;

  if (offset > _I64_MAX)
    return ERROR_INVALID_PARAMETER;

  dist.QuadPart = offset;

  if (!LDBSetFilePointerEx(file->handle, dist, NULL, FILE_CURRENT))
    return ldb_system_error();

  return LDB_OK;
}

static LDB_INLINE int
ldb_rfile_pread0(ldb_rfile_t *file,
                 ldb_slice_t *result,
                 void *buf,
                 size_t count,
                 uint64_t offset) {
  int64_t nread = -1;

  if (file->mapped) {
    if (offset + count < count)
      return ERROR_INVALID_PARAMETER;

    if (offset + count > file->length)
      return ERROR_INVALID_PARAMETER;

    ldb_slice_set(result, file->base + offset, count);

    return LDB_OK;
  }

  if (file->has_mutex) {
    /* Windows 9x. */
    LARGE_INTEGER dist;

    if (offset > _I64_MAX)
      return ERROR_INVALID_PARAMETER;

    dist.QuadPart = offset;

    EnterCriticalSection(&file->mutex);

    if (LDBSetFilePointerEx(file->handle, dist, NULL, FILE_BEGIN))
      nread = ldb_read(file->handle, buf, count);

    LeaveCriticalSection(&file->mutex);
  } else {
    /* Windows NT. */
    nread = ldb_pread(file->handle, buf, count, offset);
  }

  if (nread < 0)
    return ldb_system_error();

  ldb_slice_set(result, buf, nread);

  return LDB_OK;
}

static int
ldb_rfile_close(ldb_rfile_t *file) {
  int rc = LDB_OK;

  if (file->handle != INVALID_HANDLE_VALUE) {
    if (!CloseHandle(file->handle))
      rc = ldb_system_error();
  }

  if (file->mapped)
    UnmapViewOfFile((void *)file->base);

  if (file->limiter != NULL)
    ldb_limiter_release(file->limiter);

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

void
ldb_rfile_destroy(ldb_rfile_t *file) {
  ldb_rfile_close(file);
  ldb_free(file);
}

/*
 * SequentialFile
 */

int
ldb_seqfile_create(const char *filename, ldb_rfile_t **file) {
  HANDLE handle = LDBCreateFile(filename,
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL |
                                FILE_FLAG_SEQUENTIAL_SCAN,
                                NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return ldb_system_error();

  *file = ldb_malloc(sizeof(ldb_rfile_t));

  ldb_seqfile_init(*file, handle);

  return LDB_OK;
}

/*
 * RandomAccessFile
 */

int
ldb_randfile_create(const char *filename, ldb_rfile_t **file, int use_mmap) {
  HANDLE mapping = NULL;
  LARGE_INTEGER size;
  void *base = NULL;
  int rc = LDB_OK;
  HANDLE handle;

  handle = LDBCreateFile(filename,
                         GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
                         NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return ldb_system_error();

  if (!use_mmap || !ldb_limiter_acquire(&ldb_mmap_limiter)) {
    *file = ldb_malloc(sizeof(ldb_rfile_t));

    ldb_randfile_init(*file, handle);

    return LDB_OK;
  }

  if (!LDBGetFileSizeEx(handle, &size))
    rc = ldb_system_error();

  if (rc == LDB_OK) {
    mapping = CreateFileMappingA(handle,
                                 NULL,
                                 PAGE_READONLY,
                                 size.HighPart,
                                 size.LowPart,
                                 NULL);

    if (mapping == NULL)
      rc = ldb_system_error();
  }

  if (rc == LDB_OK) {
    base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

    if (base == NULL)
      rc = ldb_system_error();
  }

  if (rc == LDB_OK) {
    *file = ldb_malloc(sizeof(ldb_rfile_t));

    ldb_mapfile_init(*file, base, size.QuadPart, &ldb_mmap_limiter);
  }

  if (mapping != NULL)
    CloseHandle(mapping);

  CloseHandle(handle);

  if (rc != LDB_OK)
    ldb_limiter_release(&ldb_mmap_limiter);

  return rc;
}

/*
 * WritableFile (backend)
 */

struct ldb_wfile_s {
  HANDLE handle;
  int manifest;
  unsigned char buf[LDB_WRITE_BUFFER];
  size_t pos;
};

static void
ldb_wfile_init(ldb_wfile_t *file, const char *filename, HANDLE handle) {
  file->handle = handle;
  file->manifest = ldb_is_manifest(filename);
  file->pos = 0;
}

static int
ldb_wfile_write(ldb_wfile_t *file, const unsigned char *data, size_t size) {
  if (ldb_write(file->handle, data, size) < 0)
    return ldb_system_error();

  return LDB_OK;
}

static LDB_INLINE int
ldb_wfile_append0(ldb_wfile_t *file, const ldb_slice_t *data) {
  const unsigned char *write_data = data->data;
  size_t write_size = data->size;
  size_t copy_size;
  int rc;

  copy_size = LDB_MIN(write_size, LDB_WRITE_BUFFER - file->pos);

  if (copy_size > 0) {
    memcpy(file->buf + file->pos, write_data, copy_size);

    write_data += copy_size;
    write_size -= copy_size;
    file->pos += copy_size;
  }

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

static LDB_INLINE int
ldb_wfile_sync0(ldb_wfile_t *file) {
  int rc;

  if ((rc = ldb_wfile_flush(file)))
    return rc;

  if (!FlushFileBuffers(file->handle))
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_wfile_close(ldb_wfile_t *file) {
  int rc = ldb_wfile_flush(file);

  if (!CloseHandle(file->handle) && rc == LDB_OK)
    rc = ldb_system_error();

  file->handle = INVALID_HANDLE_VALUE;

  return rc;
}

void
ldb_wfile_destroy(ldb_wfile_t *file) {
  if (file->handle != INVALID_HANDLE_VALUE)
    CloseHandle(file->handle);

  ldb_free(file);
}

/*
 * WritableFile
 */

static LDB_INLINE int
ldb_truncfile_create0(const char *filename, ldb_wfile_t **file) {
  HANDLE handle = LDBCreateFile(filename,
                                GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return ldb_system_error();

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, filename, handle);

  return LDB_OK;
}

/*
 * AppendableFile
 */

static LDB_INLINE int
ldb_appendfile_create0(const char *filename, ldb_wfile_t **file) {
  HANDLE handle = LDBCreateFile(filename,
                                GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return ldb_system_error();

  if (SetFilePointer(handle, 0, NULL, FILE_END) == (DWORD)-1) {
    DWORD code = GetLastError();

    if (code != ERROR_SUCCESS) {
      CloseHandle(handle);
      return ldb_convert_error(code);
    }
  }

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, filename, handle);

  return LDB_OK;
}

/*
 * Logging
 */

int
ldb_logger_open(const char *filename, ldb_logger_t **result) {
  FILE *stream;

  SetLastError(ERROR_SUCCESS);

  if (LDBIsWindowsNT()) {
    ldb_wide_t path;

    if (!ldb_wide_import(&path, filename))
      return ldb_system_error();

    stream = _wfopen(path.data, L"w");

    ldb_wide_clear(&path);
  } else {
    stream = fopen(filename, "w");
  }

  if (stream == NULL) {
    DWORD code = GetLastError();

    if (code == ERROR_SUCCESS)
      code = ERROR_TOO_MANY_OPEN_FILES;

    return ldb_convert_error(code);
  }

  *result = ldb_logger_fopen(stream);

  return LDB_OK;
}

/*
 * Time
 */

int64_t
ldb_now_usec(void) {
  static const uint64_t epoch = UINT64_C(116444736000000000);
  ULARGE_INTEGER ticks;
  FILETIME ft;

  GetSystemTimeAsFileTime(&ft);

  ticks.LowPart = ft.dwLowDateTime;
  ticks.HighPart = ft.dwHighDateTime;

  return (ticks.QuadPart - epoch) / 10;
}

void
ldb_sleep_usec(int64_t usec) {
  if (usec < 0)
    usec = 0;

  Sleep(usec / 1000);
}
