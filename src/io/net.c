/*!
 * net.c - network functions for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifdef _WIN32
#  include <stdio.h>
#  include <stdlib.h>
#  ifdef BTC_WSOCK32 /* Windows 95 & NT 3.51 (1995) */
#    include <winsock.h>
#    ifndef __MINGW32__
#      pragma comment(lib, "wsock32.lib")
#    endif
#  else /* NT 4.0 (1996) */
#    include <winsock2.h>
#    ifndef __MINGW32__
#      pragma comment(lib, "ws2_32.lib")
#    endif
#  endif
#else
#  include <signal.h>
#endif

#include <io/core.h>

/*
 * Net
 */

void
btc_net_startup(void) {
#if defined(_WIN32)
  WSADATA wsa_data;
  int rc;

#if defined(BTC_WSOCK32) /* Windows 95 & NT 3.51 (1995) */
  rc = WSAStartup(MAKEWORD(1, 1), &wsa_data);
#elif defined(BTC_HAVE_INET6) /* Windows 2000 */
  rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else /* NT 4.0 (1996) */
  /* Note that NT 4.0 SP4 had Winsock 2.2. */
  rc = WSAStartup(MAKEWORD(2, 1), &wsa_data);
#endif

  if (rc != 0) {
    printf("Could not initialize winsock (%d).\n", rc);
    abort();
  }
#else
  signal(SIGPIPE, SIG_IGN);
#endif
}

void
btc_net_cleanup(void) {
#ifdef _WIN32
  WSACleanup();
#endif
}
