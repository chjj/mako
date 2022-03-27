/*!
 * rand_win_impl.h - win32 entropy gathering for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include <mako/crypto/hash.h>

#include "rand.h"

#ifndef __MINGW32__
/* RegQueryValueExA, RegCloseKey */
/* GetCurrentHwProfileA, GetUserNameA */
#  pragma comment(lib, "advapi32.lib")
#endif

/*
 * Helpers
 */

static void
sha256_write(btc_sha256_t *hash, const void *data, size_t size) {
  btc_sha256_update(hash, data, size);
}

static void
sha256_write_data(btc_sha256_t *hash, const void *data, size_t size) {
  sha256_write(hash, &size, sizeof(size));
  sha256_write(hash, data, size);
}

static void
sha256_write_string(btc_sha256_t *hash, const char *str) {
  sha256_write_data(hash, str, str == NULL ? 0 : strlen(str));
}

static void
sha256_write_int(btc_sha256_t *hash, unsigned __int64 num) {
  sha256_write(hash, &num, sizeof(num));
}

static void
sha256_write_ptr(btc_sha256_t *hash, const void *ptr) {
  sha256_write(hash, &ptr, sizeof(ptr));
}

/*
 * Timestamp Counter
 */

static unsigned __int64
btc_rdtsc(void) {
#if defined(_MSC_VER) && !defined(__clang__)        \
                      && !defined(__llvm__)         \
                      && !defined(__INTEL_COMPILER) \
                      && !defined(__ICL)
  _asm rdtsc
#elif (defined(__GNUC__) || defined(__clang__)) \
   && (defined(__i386__) || defined(_M_IX86))
  unsigned long long ts;

  __asm__ __volatile__ (
    "rdtsc\n"
    : "=A" (ts)
  );

  return ts;
#elif (defined(__GNUC__) || defined(__clang__)) \
   && (defined(__x86_64__) || defined(_M_X64))
  unsigned long long lo, hi;

  __asm__ __volatile__ (
    "rdtsc\n"
    : "=a" (lo),
      "=d" (hi)
  );

  return (hi << 32) | lo;
#else
  return 0;
#endif
}

/*
 * Performance Data
 */

static void
sha256_write_perfdata(btc_sha256_t *hash) {
  static const DWORD max = 1000000;
  DWORD size = 25000; /* (max / 40) */
  BYTE *data = (BYTE *)malloc(size);
  DWORD nread;
  LSTATUS ret;

  if (data == NULL)
    return;

  memset(data, 0, size);

  for (;;) {
    nread = size;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA,
                           "Global", NULL, NULL,
                           data, &nread);

    if (ret != ERROR_MORE_DATA || size >= max)
      break;

    size = (size * 3) / 2;

    if (size > max)
      size = max;

    data = (BYTE *)realloc(data, size);

    if (data == NULL)
      break;

    memset(data, 0, size);

    sha256_write_int(hash, btc_rdtsc());
  }

  RegCloseKey(HKEY_PERFORMANCE_DATA);

  if (ret == ERROR_SUCCESS)
    sha256_write_data(hash, data, nread);

  if (data != NULL)
    free(data);
}

/*
 * Environment Entropy
 */

int
btc_envrand(void *dst, size_t size) {
  unsigned char *seed = (unsigned char *)dst;
  btc_sha256_t hash;

  if (size != 32)
    abort(); /* LCOV_EXCL_LINE */

  btc_sha256_init(&hash);

  sha256_write_int(&hash, btc_rdtsc());

  /* Some compile-time static properties. */
#if defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
  sha256_write_int(&hash, __GNUC__);
  sha256_write_int(&hash, __GNUC_MINOR__);
  sha256_write_int(&hash, __GNUC_PATCHLEVEL__);
#endif

#ifdef _MSC_VER
  sha256_write_int(&hash, _MSC_VER);
#endif

#ifdef PACKAGE_STRING
  sha256_write_string(&hash, PACKAGE_STRING);
#endif

  /* Memory locations. */
  sha256_write_ptr(&hash, dst);
  sha256_write_ptr(&hash, &hash);
  sha256_write_ptr(&hash, &errno);
  sha256_write_ptr(&hash, GetModuleHandleA("kernel32.dll"));

  sha256_write_int(&hash, btc_rdtsc());

  /* Timing information. */
  {
    LARGE_INTEGER ctr;

    if (QueryPerformanceCounter(&ctr))
      sha256_write_int(&hash, ctr.QuadPart);
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* OS information. */
  {
    OSVERSIONINFOA info;

    memset(&info, 0, sizeof(info));

    info.dwOSVersionInfoSize = sizeof(info);

    if (GetVersionExA(&info))
      sha256_write(&hash, &info, sizeof(info));

    sha256_write_int(&hash, GetVersion());
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* System information. */
  {
    SYSTEM_INFO info;

    memset(&info, 0, sizeof(info));

    GetSystemInfo(&info);

    sha256_write(&hash, &info, sizeof(info));
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Performance frequency. */
  {
    LARGE_INTEGER freq;

    if (QueryPerformanceFrequency(&freq))
      sha256_write_int(&hash, freq.QuadPart);
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Disk information. */
  {
    char vname[MAX_PATH + 1];
    char fsname[MAX_PATH + 1];
    DWORD serial, maxcmp, flags;

    if (GetVolumeInformationA(NULL, vname, sizeof(vname),
                              &serial, &maxcmp, &flags,
                              fsname, sizeof(fsname))) {
      sha256_write_string(&hash, vname);
      sha256_write_int(&hash, serial);
      sha256_write_int(&hash, maxcmp);
      sha256_write_int(&hash, flags);
      sha256_write_string(&hash, fsname);
    }

    sha256_write_int(&hash, GetLogicalDrives());
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Hostname. */
  {
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = sizeof(name);

    if (GetComputerNameA(name, &len))
      sha256_write_string(&hash, name);
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Current directory. */
  {
    char cwd[MAX_PATH + 1];
    DWORD len;

    len = GetCurrentDirectoryA(sizeof(cwd), cwd);

    if (len >= 1 && len <= MAX_PATH)
      sha256_write_string(&hash, cwd);
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Console title. */
  {
    char title[1024 + 1];

    if (GetConsoleTitleA(title, sizeof(title)))
      sha256_write_string(&hash, title);
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Command line. */
  {
    char *cmd = GetCommandLineA();

    if (cmd != NULL) {
      sha256_write_ptr(&hash, cmd);
      sha256_write_string(&hash, cmd);
    }
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Environment variables. */
  {
    char *env = GetEnvironmentStringsA();

    if (env != NULL) {
      char *penv = env;

      sha256_write_ptr(&hash, env);

      while (*penv != '\0') {
        sha256_write_string(&hash, penv);
        penv += strlen(penv) + 1;
      }

      FreeEnvironmentStringsA(env);
    }
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Username. */
  {
    char name[256 + 1]; /* UNLEN + 1 */
    DWORD len = sizeof(name);

    if (GetUserNameA(name, &len))
      sha256_write_string(&hash, name);
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Process/Thread ID. */
  sha256_write_int(&hash, GetCurrentProcessId());
  sha256_write_int(&hash, GetCurrentThreadId());

  sha256_write_int(&hash, btc_rdtsc());

  /* System time. */
  {
    FILETIME ftime;

    memset(&ftime, 0, sizeof(ftime));

    GetSystemTimeAsFileTime(&ftime);

    sha256_write(&hash, &ftime, sizeof(ftime));
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Various clocks. */
  {
    SYSTEMTIME stime, ltime;
    LARGE_INTEGER ctr;

    memset(&stime, 0, sizeof(stime));
    memset(&ltime, 0, sizeof(ltime));

    GetSystemTime(&stime);
    GetLocalTime(&ltime);

    sha256_write(&hash, &stime, sizeof(stime));
    sha256_write(&hash, &ltime, sizeof(ltime));

    sha256_write_int(&hash, GetTickCount());

    if (QueryPerformanceCounter(&ctr))
      sha256_write_int(&hash, ctr.QuadPart);
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Memory usage. */
  {
    MEMORYSTATUS status;

    memset(&status, 0, sizeof(status));

    status.dwLength = sizeof(status);

    GlobalMemoryStatus(&status);

    sha256_write(&hash, &status, sizeof(status));
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Disk usage. */
  {
    DWORD spc, bps, nfc, tnc;

    if (GetDiskFreeSpaceA(NULL, &spc, &bps, &nfc, &tnc)) {
      sha256_write_int(&hash, spc);
      sha256_write_int(&hash, bps);
      sha256_write_int(&hash, nfc);
      sha256_write_int(&hash, tnc);
    }
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Disk usage (requires Windows 95 OSR2 or later). */
  {
    ULARGE_INTEGER caller, total, avail;

    if (GetDiskFreeSpaceExA(NULL, &caller, &total, &avail)) {
      sha256_write_int(&hash, caller.QuadPart);
      sha256_write_int(&hash, total.QuadPart);
      sha256_write_int(&hash, avail.QuadPart);
    }
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Performance data (NT only). */
  if (GetVersion() < 0x80000000)
    sha256_write_perfdata(&hash);

  sha256_write_int(&hash, btc_rdtsc());

  /* Stack and heap location. */
  {
    void *addr = malloc(4097);

    sha256_write_ptr(&hash, &addr);

    if (addr != NULL) {
      sha256_write_ptr(&hash, addr);
      free(addr);
    }
  }

  sha256_write_int(&hash, btc_rdtsc());

  /* Timing information. */
  {
    LARGE_INTEGER ctr;

    if (QueryPerformanceCounter(&ctr))
      sha256_write_int(&hash, ctr.QuadPart);
  }

  sha256_write_int(&hash, btc_rdtsc());

  btc_sha256_final(&hash, seed);

  return 1;
}
