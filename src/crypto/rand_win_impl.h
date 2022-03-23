/*!
 * rand_win_impl.h - win32 entropy gathering for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include <mako/crypto/hash.h>

#include "rand.h"

#ifndef __MINGW32__
#  pragma comment(lib, "advapi32.lib") /* GetUserNameA */
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
 * Environment Entropy
 */

int
btc_envrand(void *dst, size_t size) {
  unsigned char *seed = (unsigned char *)dst;
  btc_sha256_t hash;

  if (size != 32)
    abort(); /* LCOV_EXCL_LINE */

  /* Try RtlGenRandom first. */
  {
    BOOLEAN (NTAPI *RtlGenRandom)(PVOID, ULONG);
    HMODULE handle;

    /* Should be loaded (GetUserNameA requires advapi32). */
    handle = GetModuleHandleA("advapi32.dll");

    if (handle == NULL)
      abort(); /* LCOV_EXCL_LINE */

    /* Available only on Windows XP. */
    *((FARPROC *)&RtlGenRandom) = GetProcAddress(handle, "SystemFunction036");

    if (RtlGenRandom != NULL) {
      if (RtlGenRandom(seed, 32))
        return 1;
    }
  }

  /* Fall back to environmental randomness. */
  btc_sha256_init(&hash);

  /* Timing information. */
  {
    LARGE_INTEGER ctr;

    if (QueryPerformanceCounter(&ctr))
      sha256_write_int(&hash, ctr.QuadPart);
  }

  /* System information. */
  {
    SYSTEM_INFO info;

    memset(&info, 0, sizeof(info));

    GetSystemInfo(&info);

    sha256_write(&hash, &info, sizeof(info));
  }

  /* Performance frequency. */
  {
    LARGE_INTEGER freq;

    if (QueryPerformanceFrequency(&freq))
      sha256_write_int(&hash, freq.QuadPart);
  }

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

  /* Hostname. */
  {
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = sizeof(name);

    if (GetComputerNameA(name, &len))
      sha256_write_string(&hash, name);
  }

  /* Current directory. */
  {
    char cwd[MAX_PATH + 1];
    DWORD len;

    len = GetCurrentDirectoryA(sizeof(cwd), cwd);

    if (len >= 1 && len <= MAX_PATH)
      sha256_write_string(&hash, cwd);
  }

  /* Console title. */
  {
    char title[1024 + 1];

    if (GetConsoleTitleA(title, sizeof(title)))
      sha256_write_string(&hash, title);
  }

  /* Command line. */
  {
    char *cmd = GetCommandLineA();

    if (cmd != NULL) {
      sha256_write_ptr(&hash, cmd);
      sha256_write_string(&hash, cmd);
    }
  }

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

  /* Username. */
  {
    char name[256 + 1]; /* UNLEN + 1 */
    DWORD len = sizeof(name);

    if (GetUserNameA(name, &len))
      sha256_write_string(&hash, name);
  }

  /* Process/Thread ID. */
  sha256_write_int(&hash, GetCurrentProcessId());
  sha256_write_int(&hash, GetCurrentThreadId());

  /* System time. */
  {
    FILETIME ftime;

    memset(&ftime, 0, sizeof(ftime));

    GetSystemTimeAsFileTime(&ftime);

    sha256_write(&hash, &ftime, sizeof(ftime));
  }

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

  /* Memory usage. */
  {
    MEMORYSTATUS status;

    memset(&status, 0, sizeof(status));

    status.dwLength = sizeof(status);

    GlobalMemoryStatus(&status);

    sha256_write(&hash, &status, sizeof(status));
  }

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

  /* Disk usage (requires Windows 95 OSR2 or later). */
  {
    ULARGE_INTEGER caller, total, avail;

    if (GetDiskFreeSpaceExA(NULL, &caller, &total, &avail)) {
      sha256_write_int(&hash, caller.QuadPart);
      sha256_write_int(&hash, total.QuadPart);
      sha256_write_int(&hash, avail.QuadPart);
    }
  }

  /* Stack and heap location. */
  {
    void *addr = malloc(4097);

    sha256_write_ptr(&hash, &addr);

    if (addr != NULL) {
      sha256_write_ptr(&hash, addr);
      free(addr);
    }
  }

  /* Timing information. */
  {
    LARGE_INTEGER ctr;

    if (QueryPerformanceCounter(&ctr))
      sha256_write_int(&hash, ctr.QuadPart);
  }

  btc_sha256_final(&hash, seed);

  return 1;
}
