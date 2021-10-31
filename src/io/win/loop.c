/*!
 * loop.c - event loop for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef FD_SETSIZE
#  define FD_SETSIZE 1024
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <io/core.h>
#include <io/loop.h>

#ifndef __MINGW32__
#  pragma comment(lib, "ws2_32.lib")
#endif

/*
 * Macros
 */

#define CHECK(x) do { if (!(x)) abort(); } while (0)
#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

#define btc_list_init(q) do { \
  (q)->head = NULL;           \
  (q)->tail = NULL;           \
  (q)->length = 0;            \
} while (0)

#define btc_list_insert(q, r, x, node_t) do {   \
  node_t *rr = (r), *xx = (x);                  \
                                                \
  xx->prev = rr;                                \
  xx->next = rr != NULL ? rr->next : (q)->head; \
                                                \
  if (xx->prev != NULL)                         \
    xx->prev->next = xx;                        \
                                                \
  if (xx->next != NULL)                         \
    xx->next->prev = xx;                        \
                                                \
  if (rr == NULL)                               \
    (q)->head = xx;                             \
                                                \
  if (rr == (q)->tail)                          \
    (q)->tail = xx;                             \
                                                \
  (q)->length++;                                \
} while (0)

#define btc_list_remove(q, x, node_t) do { \
  node_t *xx = (x);                        \
                                           \
  if (xx->prev != NULL)                    \
    xx->prev->next = xx->next;             \
                                           \
  if (xx->next != NULL)                    \
    xx->next->prev = xx->prev;             \
                                           \
  if (xx == (q)->head)                     \
    (q)->head = xx->next;                  \
                                           \
  if (xx == (q)->tail)                     \
    (q)->tail = xx->prev;                  \
                                           \
  xx->prev = NULL;                         \
  xx->next = NULL;                         \
                                           \
  (q)->length--;                           \
} while (0)

#define btc_list_push(q, x, node_t) btc_list_insert(q, (q)->tail, x, node_t)

#define btc_queue_push(q, x) do { \
  if ((q)->head == NULL)          \
    (q)->head = (x);              \
                                  \
  if ((q)->tail != NULL)          \
    (q)->tail->next = (x);        \
                                  \
  (q)->tail = (x);                \
  (q)->length++;                  \
} while (0)

/*
 * Constants
 */

#define BTC_TICK_RATE 40

enum btc_socket_state {
  BTC_SOCKET_DISCONNECTED,
  BTC_SOCKET_CONNECTING,
  BTC_SOCKET_CONNECTED,
  BTC_SOCKET_LISTENING,
  BTC_SOCKET_BOUND
};

/*
 * Types
 */

typedef struct chunk_s {
  struct sockaddr *addr;
  void *ptr;
  unsigned char *raw;
  size_t len;
  struct chunk_s *next;
} chunk_t;

struct btc_socket_s {
  struct btc_loop_s *loop;
  struct sockaddr_storage storage;
  struct sockaddr *addr;
  SOCKET fd;
  int state;
  chunk_t *head;
  chunk_t *tail;
  size_t total;
  int draining;
  btc_socket_socket_cb *on_socket;
  btc_socket_connect_cb *on_connect;
  btc_socket_close_cb *on_close;
  btc_socket_error_cb *on_error;
  btc_socket_data_cb *on_data;
  btc_socket_drain_cb *on_drain;
  btc_socket_message_cb *on_message;
  void *data;
  struct btc_socket_s *prev;
  struct btc_socket_s *next;
};

typedef struct btc_tick_s {
  btc_loop_tick_cb *handler;
  void *data;
  struct btc_tick_s *prev;
  struct btc_tick_s *next;
} btc_tick_t;

struct btc_loop_s {
  fd_set rfds, rfdi;
  fd_set wfds, wfdi, efdi;
  SOCKET nfds;
  btc_socket_t *sockets[FD_SETSIZE];
  unsigned char buffer[65536];
  char errmsg[256];
  struct btc_closed_queue {
    btc_socket_t *head;
    btc_socket_t *tail;
    size_t length;
  } closed;
  struct btc_ticks {
    btc_tick_t *head;
    btc_tick_t *tail;
    size_t length;
  } ticks;
  int error;
  int running;
};

/*
 * Helpers
 */

static void *
safe_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

/*
 * Sockaddr Helpers
 */

static int
sa_domain(const struct sockaddr *addr) {
  switch (addr->sa_family) {
    case AF_INET:
      return PF_INET;
    case AF_INET6:
      return PF_INET6;
    default:
      return PF_UNSPEC;
  }
}

static int
sa_addrlen(const struct sockaddr *addr) {
  switch (addr->sa_family) {
    case AF_INET:
      return sizeof(struct sockaddr_in);
    case AF_INET6:
      return sizeof(struct sockaddr_in6);
    default:
      return 0;
  }
}

/*
 * Socket Helpers
 */

static int
set_nonblocking(SOCKET fd) {
  u_long yes = 1;
  return ioctlsocket(fd, FIONBIO, &yes);
}

static SOCKET
safe_socket(int domain, int type, int protocol) {
  return socket(domain, type, protocol);
}

static SOCKET
safe_listener(int domain, int type, int protocol) {
  SOCKET fd = safe_socket(domain, type, protocol);
  char yes = 1;
  char no = 0;

  if (fd == INVALID_SOCKET)
    return INVALID_SOCKET;

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  /* https://stackoverflow.com/questions/1618240 */
  /* https://datatracker.ietf.org/doc/html/rfc3493#section-5.3 */
#ifdef IPV6_V6ONLY
  if (domain == PF_INET6)
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
#endif

  return fd;
}

/*
 * Time Helpers
 */

static void
time_sleep(signed __int64 msec) {
  if (msec > 0)
    Sleep((DWORD)msec);
}

static signed __int64
time_msec(void) {
#if defined(__MINGW32__)
  static const unsigned __int64 epoch = 116444736000000000ULL;
#else
  static const unsigned __int64 epoch = 116444736000000000ui64;
#endif
  ULARGE_INTEGER ul;
  FILETIME ft;

  GetSystemTimeAsFileTime(&ft);

  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;

  return (ul.QuadPart - epoch) / 10000;
}

/*
 * Socket
 */

static btc_socket_t *
btc_socket_create(btc_loop_t *loop) {
  btc_socket_t *socket = (btc_socket_t *)safe_malloc(sizeof(btc_socket_t));

  memset(socket, 0, sizeof(*socket));

  socket->loop = loop;
  socket->addr = (struct sockaddr *)&socket->storage;
  socket->fd = INVALID_SOCKET;
  socket->state = BTC_SOCKET_DISCONNECTED;

  return socket;
}

static void
btc_socket_destroy(btc_socket_t *socket) {
  chunk_t *chunk, *next;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    if (chunk->addr != NULL)
      free(chunk->addr);

    free(chunk->ptr);
    free(chunk);
  }

  free(socket);
}

btc_loop_t *
btc_socket_loop(btc_socket_t *socket) {
  return socket->loop;
}

void
btc_socket_address(btc_sockaddr_t *addr, btc_socket_t *socket) {
  CHECK(btc_sockaddr_set(addr, socket->addr));
}

void
btc_socket_on_socket(btc_socket_t *socket, btc_socket_socket_cb *handler) {
  socket->on_socket = handler;
}

void
btc_socket_on_connect(btc_socket_t *socket, btc_socket_connect_cb *handler) {
  socket->on_connect = handler;
}

void
btc_socket_on_close(btc_socket_t *socket, btc_socket_close_cb *handler) {
  socket->on_close = handler;
}

void
btc_socket_on_error(btc_socket_t *socket, btc_socket_error_cb *handler) {
  socket->on_error = handler;
}

void
btc_socket_on_data(btc_socket_t *socket, btc_socket_data_cb *handler) {
  socket->on_data = handler;
}

void
btc_socket_on_drain(btc_socket_t *socket, btc_socket_drain_cb *handler) {
  socket->on_drain = handler;
}

void
btc_socket_on_message(btc_socket_t *socket, btc_socket_message_cb *handler) {
  socket->on_message = handler;
}

void
btc_socket_complete(btc_socket_t *socket) {
  /* This function essentialy means, "I'm ready for on_connect to be called." */
  /* Necessary in cases where the socket connects immediately. */
  if (socket->state == BTC_SOCKET_CONNECTED && socket->on_connect != NULL) {
    socket->on_connect(socket);
    socket->on_connect = NULL;
  }
}

void
btc_socket_set_data(btc_socket_t *socket, void *data) {
  socket->data = data;
}

void *
btc_socket_get_data(btc_socket_t *socket) {
  return socket->data;
}

const char *
btc_socket_strerror(btc_socket_t *socket) {
  return btc_loop_strerror(socket->loop);
}

size_t
btc_socket_buffered(btc_socket_t *socket) {
  return socket->total;
}

void
btc_socket_set_nodelay(btc_socket_t *socket, int value) {
  char val = (value != 0);
  setsockopt(socket->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
}

static int
btc_socket_setaddr(btc_socket_t *socket, const btc_sockaddr_t *addr) {
  if (!btc_sockaddr_get(socket->addr, addr)) {
    socket->loop->error = WSAEAFNOSUPPORT;
    return 0;
  }

  return 1;
}

static int
btc_socket_listen(btc_socket_t *server,
                  const btc_sockaddr_t *addr,
                  int backlog) {
  SOCKET fd;

  if (!btc_socket_setaddr(server, addr))
    return 0;

  fd = safe_listener(sa_domain(server->addr), SOCK_STREAM, 0);

  if (fd == INVALID_SOCKET) {
    server->loop->error = WSAGetLastError();
    return 0;
  }

  if (bind(fd, server->addr, sa_addrlen(server->addr)) == SOCKET_ERROR) {
    server->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  if (listen(fd, backlog) == SOCKET_ERROR) {
    server->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  if (set_nonblocking(fd) == SOCKET_ERROR) {
    server->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  server->fd = fd;
  server->state = BTC_SOCKET_LISTENING;

  return 1;
}

static int
btc_socket_accept(btc_socket_t *socket, btc_socket_t *server) {
  int addrlen = sizeof(socket->storage);
  SOCKET fd;

  memset(&socket->storage, 0, sizeof(socket->storage));

  fd = accept(server->fd, socket->addr, &addrlen);

  if (fd == INVALID_SOCKET) {
    socket->loop->error = WSAGetLastError();
    return 0;
  }

  if (set_nonblocking(fd) == SOCKET_ERROR) {
    socket->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTED;

  return 1;
}

static int
btc_socket_connect(btc_socket_t *socket, const btc_sockaddr_t *addr) {
  SOCKET fd;

  if (!btc_socket_setaddr(socket, addr))
    return 0;

  fd = safe_socket(sa_domain(socket->addr), SOCK_STREAM, 0);

  if (fd == INVALID_SOCKET) {
    socket->loop->error = WSAGetLastError();
    return 0;
  }

  if (set_nonblocking(fd) == SOCKET_ERROR) {
    socket->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  if (connect(fd, socket->addr, sa_addrlen(socket->addr)) == SOCKET_ERROR) {
    int error = WSAGetLastError();

    /* Note: Check WSAEWOULDBLOCK instead of WSAEINPROGRESS. */
    if (error == WSAEWOULDBLOCK || error == WSAEALREADY) {
      socket->fd = fd;
      socket->state = BTC_SOCKET_CONNECTING;
      return 1;
    }

    if (error != WSAEISCONN) {
      socket->loop->error = error;
      closesocket(fd);
      return 0;
    }
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTED;

  return 1;
}

static int
btc_socket_bind(btc_socket_t *socket, const btc_sockaddr_t *addr) {
  SOCKET fd;

  if (!btc_socket_setaddr(socket, addr))
    return 0;

  fd = safe_listener(sa_domain(socket->addr), SOCK_DGRAM, 0);

  if (fd == INVALID_SOCKET) {
    socket->loop->error = WSAGetLastError();
    return 0;
  }

  if (bind(fd, socket->addr, sa_addrlen(socket->addr)) == SOCKET_ERROR) {
    socket->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  if (set_nonblocking(fd) == SOCKET_ERROR) {
    socket->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_BOUND;

  return 1;
}

static int
btc_socket_talk(btc_socket_t *socket, int family) {
  int domain;
  SOCKET fd;

  switch (family) {
    case BTC_AF_INET:
      domain = PF_INET;
      break;
    case BTC_AF_INET6:
      domain = PF_INET6;
      break;
    default:
      socket->loop->error = WSAEAFNOSUPPORT;
      return 0;
  }

  fd = safe_socket(domain, SOCK_DGRAM, 0);

  if (fd == INVALID_SOCKET) {
    socket->loop->error = WSAGetLastError();
    return 0;
  }

  if (set_nonblocking(fd) == SOCKET_ERROR) {
    socket->loop->error = WSAGetLastError();
    closesocket(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_BOUND;

  return 1;
}

static int
btc_socket_flush_write(btc_socket_t *socket) {
  chunk_t *chunk, *next;
  int len;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    CHECK(chunk->len <= INT_MAX);

    while (chunk->len > 0) {
      len = send(socket->fd, (char *)chunk->raw, chunk->len, 0);

      if (len == SOCKET_ERROR) {
        int error = WSAGetLastError();

        if (error == WSAEWOULDBLOCK)
          break;

        socket->loop->error = error;

        return -1;
      }

      if (len == 0)
        break;

      if ((size_t)len > chunk->len)
        abort();

      chunk->raw += len;
      chunk->len -= len;

      socket->total -= len;
    }

    if (chunk->len != 0) {
      socket->draining = 1;
      return 0;
    }

    free(chunk->ptr);
    free(chunk);

    socket->head = next;
  }

  CHECK(socket->total == 0);

  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;

  if (socket->draining) {
    socket->draining = 0;
    if (socket->on_drain != NULL)
      socket->on_drain(socket);
  }

  return 1;
}

int
btc_socket_write(btc_socket_t *socket, void *data, size_t len) {
  unsigned char *raw = (unsigned char *)data;
  chunk_t *chunk;

  if (socket->state != BTC_SOCKET_CONNECTING
      && socket->state != BTC_SOCKET_CONNECTED) {
    socket->loop->error = WSAENOTCONN;

    if (data != NULL)
      free(data);

    return -1;
  }

  if (len == 0) {
    if (data != NULL)
      free(data);

    return !socket->draining;
  }

  chunk = (chunk_t *)safe_malloc(sizeof(chunk_t));

  chunk->addr = NULL;
  chunk->ptr = raw;
  chunk->raw = raw;
  chunk->len = len;
  chunk->next = NULL;

  if (socket->head == NULL)
    socket->head = chunk;

  if (socket->tail != NULL)
    socket->tail->next = chunk;

  socket->tail = chunk;
  socket->total += len;

  if (socket->state == BTC_SOCKET_CONNECTING) {
    socket->draining = 1;
    return 0;
  }

  return btc_socket_flush_write(socket);
}

static int
btc_socket_flush_send(btc_socket_t *socket) {
  chunk_t *chunk, *next;
  int addrlen, len;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    CHECK(chunk->len <= INT_MAX);

    addrlen = sa_addrlen(chunk->addr);

    len = sendto(socket->fd,
                 (char *)chunk->raw,
                 chunk->len,
                 0,
                 chunk->addr,
                 addrlen);

    if (len == SOCKET_ERROR) {
      int error = WSAGetLastError();

      if (error == WSAEWOULDBLOCK)
        return 0;

      if (error == WSAENOBUFS)
        return 0;
    }

    socket->total -= chunk->len;

    free(chunk->addr);
    free(chunk->ptr);
    free(chunk);

    socket->head = next;
  }

  CHECK(socket->total == 0);

  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;

  return 1;
}

int
btc_socket_send(btc_socket_t *socket,
                void *data,
                size_t len,
                const btc_sockaddr_t *addr) {
  unsigned char *raw = (unsigned char *)data;
  chunk_t *chunk;

  if (socket->state != BTC_SOCKET_BOUND) {
    socket->loop->error = WSAENOTCONN;

    if (data != NULL)
      free(data);

    return -1;
  }

  if (len == 0) {
    if (data != NULL)
      free(data);

    return 1;
  }

  chunk = (chunk_t *)safe_malloc(sizeof(chunk_t));

  chunk->addr = (struct sockaddr *)safe_malloc(sizeof(struct sockaddr_storage));
  chunk->ptr = raw;
  chunk->raw = raw;
  chunk->len = len;
  chunk->next = NULL;

  btc_sockaddr_get(chunk->addr, addr);

  if (socket->head == NULL)
    socket->head = chunk;

  if (socket->tail != NULL)
    socket->tail->next = chunk;

  socket->tail = chunk;
  socket->total += len;

  return btc_socket_flush_send(socket);
}

static void
btc_loop_unregister(btc_loop_t *loop, btc_socket_t *socket);

void
btc_socket_close(btc_socket_t *socket) {
  chunk_t *chunk, *next;

  if (socket->state == BTC_SOCKET_DISCONNECTED)
    return;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    if (chunk->addr != NULL)
      free(chunk->addr);

    free(chunk->ptr);
    free(chunk);
  }

  btc_loop_unregister(socket->loop, socket);

  CHECK(socket->fd != INVALID_SOCKET);

  closesocket(socket->fd);

  socket->fd = INVALID_SOCKET;
  socket->state = BTC_SOCKET_DISCONNECTED;
  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;
  socket->draining = 0;

  btc_queue_push(&socket->loop->closed, socket);
}

/*
 * Loop
 */

btc_loop_t *
btc_loop_create(void) {
  btc_loop_t *loop = (btc_loop_t *)safe_malloc(sizeof(btc_loop_t));

  memset(loop, 0, sizeof(*loop));

  FD_ZERO(&loop->rfds);
  FD_ZERO(&loop->wfds);

  return loop;
}

void
btc_loop_destroy(btc_loop_t *loop) {
  btc_tick_t *tick, *next;

  CHECK(loop->running == 0);

  for (tick = loop->ticks.head; tick != NULL; tick = next) {
    next = tick->next;
    free(tick);
  }

  free(loop);
}

void
btc_loop_on_tick(btc_loop_t *loop, btc_loop_tick_cb *handler, void *data) {
  btc_tick_t *tick = (btc_tick_t *)safe_malloc(sizeof(btc_tick_t));

  tick->handler = handler;
  tick->data = data;
  tick->prev = NULL;
  tick->next = NULL;

  btc_list_push(&loop->ticks, tick, btc_tick_t);
}

void
btc_loop_off_tick(btc_loop_t *loop, btc_loop_tick_cb *handler, void *data) {
  btc_tick_t *tick;

  for (tick = loop->ticks.head; tick != NULL; tick = tick->next) {
    if (tick->handler == handler && tick->data == data) {
      btc_list_remove(&loop->ticks, tick, btc_tick_t);
      free(tick);
      break;
    }
  }
}

const char *
btc_loop_strerror(btc_loop_t *loop) {
  /* https://stackoverflow.com/questions/3400922 */
  memset(loop->errmsg, 0, sizeof(loop->errmsg));

  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL,
                 loop->error,
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 loop->errmsg,
                 sizeof(loop->errmsg),
                 NULL);

  if (loop->errmsg[0] == '\0')
    sprintf(loop->errmsg, "WSA Error: %d", loop->error);

  loop->errmsg[sizeof(loop->errmsg) - 1] = '\0';

  return loop->errmsg;
}

static int
btc_loop_register(btc_loop_t *loop, btc_socket_t *socket) {
  if (socket->fd >= FD_SETSIZE) {
    loop->error = WSAEMFILE;
    return 0;
  }

  CHECK(loop->sockets[socket->fd] == NULL);

  if (socket->fd + 1 > loop->nfds)
    loop->nfds = socket->fd + 1;

  FD_SET(socket->fd, &loop->rfds);
  FD_SET(socket->fd, &loop->wfds);

  loop->sockets[socket->fd] = socket;

  return 1;
}

static void
btc_loop_unregister(btc_loop_t *loop, btc_socket_t *socket) {
  FD_CLR(socket->fd, &loop->rfds);
  FD_CLR(socket->fd, &loop->wfds);

  loop->sockets[socket->fd] = NULL;
}

btc_socket_t *
btc_loop_listen(btc_loop_t *loop, const btc_sockaddr_t *addr, int backlog) {
  btc_socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_listen(socket, addr, backlog))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    closesocket(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

btc_socket_t *
btc_loop_connect(btc_loop_t *loop, const btc_sockaddr_t *addr) {
  btc_socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_connect(socket, addr))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    closesocket(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

btc_socket_t *
btc_loop_bind(btc_loop_t *loop, const btc_sockaddr_t *addr) {
  btc_socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_bind(socket, addr))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    closesocket(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

btc_socket_t *
btc_loop_talk(btc_loop_t *loop, int family) {
  btc_socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_talk(socket, family))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    closesocket(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

static void
handle_read(btc_loop_t *loop, btc_socket_t *socket) {
  switch (socket->state) {
    case BTC_SOCKET_LISTENING: {
      btc_socket_t *child = btc_socket_create(loop);

      if (!btc_socket_accept(child, socket))
        goto fail;

      if (!btc_loop_register(loop, child)) {
        closesocket(socket->fd);
        goto fail;
      }

      socket->on_socket(socket, child);

      break;
fail:
      btc_socket_destroy(child);
      break;
    }

    case BTC_SOCKET_CONNECTED: {
      unsigned char *buf = loop->buffer;
      size_t size = sizeof(loop->buffer);
      SOCKET fd = socket->fd;
      int len;

      CHECK(size <= INT_MAX);

      while (socket->state == BTC_SOCKET_CONNECTED) {
        len = recv(fd, (char *)buf, size, 0);

        if (len == SOCKET_ERROR) {
          int error = WSAGetLastError();

          if (error == WSAEWOULDBLOCK)
            break;

          socket->loop->error = error;
          socket->on_error(socket);

          break;
        }

        if ((size_t)len > size)
          abort();

        if (!socket->on_data(socket, buf, len))
          break;

        if (len == 0)
          break;
      }

      break;
    }

    case BTC_SOCKET_BOUND: {
      unsigned char *buf = loop->buffer;
      size_t size = sizeof(loop->buffer);
      struct sockaddr_storage storage;
      struct sockaddr *from = (struct sockaddr *)&storage;
      SOCKET fd = socket->fd;
      btc_sockaddr_t addr;
      int len, fromlen;

      CHECK(size <= INT_MAX);

      while (socket->state == BTC_SOCKET_BOUND) {
        memset(from, 0, sizeof(storage));
        fromlen = sizeof(storage);

        len = recvfrom(fd, (char *)buf, size, 0, from, &fromlen);

        if (len == SOCKET_ERROR) {
          int error = WSAGetLastError();

          if (error == WSAEWOULDBLOCK)
            break;

          socket->loop->error = error;
          socket->on_error(socket);

          break;
        }

        if ((size_t)len > size)
          abort();

        btc_sockaddr_set(&addr, from);

        socket->on_message(socket, buf, len, &addr);
      }

      break;
    }
  }
}

static void
handle_write(btc_loop_t *loop, btc_socket_t *socket) {
  (void)loop;

  switch (socket->state) {
    case BTC_SOCKET_CONNECTING: {
      int addrlen = sa_addrlen(socket->addr);

      if (connect(socket->fd, socket->addr, addrlen) == SOCKET_ERROR) {
        int error = WSAGetLastError();

        /* Note: Check WSAEWOULDBLOCK instead of WSAEINPROGRESS. */
        if (error == WSAEWOULDBLOCK || error == WSAEALREADY)
          break;

        if (error != WSAEISCONN) {
          socket->loop->error = error;
          socket->on_error(socket);
          btc_socket_close(socket);
          break;
        }
      }

      socket->state = BTC_SOCKET_CONNECTED;

      if (socket->on_connect != NULL) {
        socket->on_connect(socket);
        socket->on_connect = NULL;
      }

      break;
    }

    case BTC_SOCKET_CONNECTED: {
      if (btc_socket_flush_write(socket) == -1)
        socket->on_error(socket);
      break;
    }

    case BTC_SOCKET_BOUND: {
      btc_socket_flush_send(socket);
      break;
    }
  }
}

static void
handle_ticks(btc_loop_t *loop) {
  btc_tick_t *tick, *next;

  for (tick = loop->ticks.head; tick != NULL; tick = next) {
    next = tick->next;

    tick->handler(loop, tick->data);
  }
}

static void
handle_closed(btc_loop_t *loop) {
  btc_socket_t *socket, *next;

  for (socket = loop->closed.head; socket != NULL; socket = next) {
    next = socket->next;

    socket->on_close(socket);
    btc_socket_destroy(socket);
  }

  btc_list_init(&loop->closed);
}

void
btc_loop_start(btc_loop_t *loop) {
  signed __int64 prev, diff;
  struct timeval tv, to;
  btc_socket_t *socket;
  int count;
  SOCKET fd;

  memset(&tv, 0, sizeof(tv));

  tv.tv_usec = BTC_TICK_RATE * 1000;

  loop->running = 1;

  while (loop->running) {
    memcpy(&loop->rfdi, &loop->rfds, sizeof(loop->rfds));
    memcpy(&loop->wfdi, &loop->wfds, sizeof(loop->wfds));
    memcpy(&loop->efdi, &loop->wfds, sizeof(loop->wfds));
    memcpy(&to, &tv, sizeof(tv));

    prev = time_msec();
    count = select(loop->nfds, &loop->rfdi, &loop->wfdi, &loop->efdi, &to);
    diff = time_msec() - prev;

    if (diff < 0)
      diff = 0;

    if (count == SOCKET_ERROR) {
      if (WSAGetLastError() == WSAEINVAL)
        goto next;

      abort();
    }

    if (count != 0) {
      for (fd = 0; fd < loop->nfds; fd++) {
        socket = loop->sockets[fd];

        if (socket == NULL)
          continue;

        if (FD_ISSET(fd, &loop->rfdi))
          handle_read(loop, socket);

        if (FD_ISSET(fd, &loop->wfdi) | FD_ISSET(fd, &loop->efdi))
          handle_write(loop, socket);
      }
    }

    handle_ticks(loop);
    handle_closed(loop);

next:
    time_sleep(BTC_TICK_RATE - diff);
  }

  for (fd = 0; fd < loop->nfds; fd++) {
    socket = loop->sockets[fd];

    if (socket == NULL)
      continue;

    btc_socket_close(socket);
    socket->on_close(socket);
    btc_socket_destroy(socket);
  }

  btc_list_init(&loop->closed);

  loop->nfds = 0;
}

void
btc_loop_stop(btc_loop_t *loop) {
  loop->running = 0;
}
