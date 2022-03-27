/*!
 * loop.c - event loop for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#if defined(_WIN32) && !defined(FD_SETSIZE)
#  define FD_SETSIZE 1024
#endif

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <stdio.h>
#  include <winsock2.h>
#  ifdef BTC_HAVE_RFC3493
#    include <ws2tcpip.h>
#  endif
#  ifndef __MINGW32__
#    pragma comment(lib, "ws2_32.lib")
#  endif
#  include <windows.h>
#else
#  include <sys/types.h>
#  include <sys/time.h>
#  if !defined(FD_SETSIZE) && !defined(FD_SET)
#    include <sys/select.h>
#  endif
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <unistd.h>
#endif

#include <io/core.h>
#include <io/loop.h>

/*
 * Macros
 */

#define BTC_MIN(x, y) ((x) < (y) ? (x) : (y))

/*
 * Compat
 */

#if defined(_WIN32)
typedef int btc_socklen_t;
typedef SOCKET btc_sockfd_t;
typedef char btc_sockopt_t;
#  define BTC_INVALID_SOCKET INVALID_SOCKET
#  define BTC_SOCKET_ERROR SOCKET_ERROR
#  define BTC_NOSIGNAL 0
#  define btc_errno (WSAGetLastError())
#  define BTC_EINTR WSAEINTR
#  define BTC_EAGAIN WSAEWOULDBLOCK
#  define BTC_EINVAL WSAEINVAL
#  define BTC_EMFILE WSAEMFILE
#  define BTC_EPIPE WSAENOTCONN
#  define BTC_EWOULDBLOCK WSAEWOULDBLOCK
#  define BTC_EMSGSIZE WSAEMSGSIZE
#  define BTC_EAFNOSUPPORT WSAEAFNOSUPPORT
#  define BTC_ENOBUFS WSAENOBUFS
#  define BTC_ETIMEDOUT WSAETIMEDOUT
#  define BTC_EINPROGRESS WSAEWOULDBLOCK
#  define btc_closesocket closesocket
#else
typedef socklen_t btc_socklen_t;
typedef int btc_sockfd_t;
typedef int btc_sockopt_t;
#  define BTC_INVALID_SOCKET -1
#  define BTC_SOCKET_ERROR -1
#  if defined(MSG_NOSIGNAL)
#    define BTC_NOSIGNAL MSG_NOSIGNAL
#  else
#    define BTC_NOSIGNAL 0
#  endif
#  define btc_errno errno
#  define BTC_EINTR EINTR
#  define BTC_EAGAIN EAGAIN
#  define BTC_EINVAL EINVAL
#  define BTC_EMFILE EMFILE
#  define BTC_EPIPE EPIPE
#  define BTC_EWOULDBLOCK EWOULDBLOCK
#  define BTC_EMSGSIZE EMSGSIZE
#  define BTC_EAFNOSUPPORT EAFNOSUPPORT
#  define BTC_ENOBUFS ENOBUFS
#  define BTC_ETIMEDOUT ETIMEDOUT
#  define BTC_EINPROGRESS EINPROGRESS
#  define btc_closesocket close
#endif

#ifndef BTC_HAVE_RFC3493
#  define sockaddr_storage sockaddr_in
#endif

/*
 * Backend
 */

#if !defined(BTC_USE_SELECT) \
 && !defined(BTC_USE_POLL)   \
 && !defined(BTC_USE_EPOLL)
#  if defined(__LINUX__) && defined(__WATCOMC__)
#    define BTC_USE_SELECT
#  elif defined(__linux__) && defined(__GNUC__)
#    define BTC_USE_EPOLL
#  elif defined(_WIN32) || defined(_AIX)
#    define BTC_USE_SELECT
#  else
#    define BTC_USE_POLL
#  endif
#endif

#if defined(BTC_USE_EPOLL)
#  include <sys/epoll.h>
#elif defined(BTC_USE_POLL)
#  include <poll.h>
#else
/* include <sys/select.h> */
#endif

#if (defined(BTC_USE_SELECT) \
   + defined(BTC_USE_POLL)   \
   + defined(BTC_USE_EPOLL)) != 1
#  error "more than one backend selected"
#endif

/*
 * Macros
 */

#define CHECK(x) do { if (!(x)) abort(); } while (0)

/*
 * Linked List
 */

typedef struct btc_link_s {
  struct btc_link_s *prev;
  struct btc_link_s *next;
  void *value;
} btc_link_t;

typedef struct btc_list_s {
  btc_link_t *head;
  btc_link_t *tail;
  size_t length;
} btc_list_t;

static void
btc_list_init(btc_list_t *list) {
  list->head = NULL;
  list->tail = NULL;
  list->length = 0;
}

static int
btc_list_has(btc_list_t *q, btc_link_t *x) {
  return x->next != NULL || x == q->tail;
}

static void
btc_list_remove(btc_list_t *q, btc_link_t *x) {
  if (x->prev != NULL)
    x->prev->next = x->next;

  if (x->next != NULL)
    x->next->prev = x->prev;

  if (x == q->head)
    q->head = x->next;

  if (x == q->tail)
    q->tail = x->prev;

  x->prev = NULL;
  x->next = NULL;

  q->length--;
}

static btc_link_t *
btc_list_shift(btc_list_t *q) {
  btc_link_t *x = q->head;

  CHECK(x != NULL);

  if (x->next == NULL) {
    q->head = NULL;
    q->tail = NULL;
    q->length = 0;
  } else {
    q->head = x->next;
    q->head->prev = NULL;
    q->length--;

    x->next = NULL;
  }

  return x;
}

static void
btc_list_push(btc_list_t *q, btc_link_t *x) {
  CHECK(x->prev == NULL);
  CHECK(x->next == NULL);

  if (q->tail == NULL) {
    q->head = x;
    q->tail = x;
    q->length = 1;
  } else {
    x->prev = q->tail;
    x->prev->next = x;
    q->tail = x;
    q->length++;
  }
}

/*
 * Constants
 */

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
  btc_sockfd_t fd;
  int state;
#ifdef BTC_USE_POLL
  size_t index;
#endif
  chunk_t *head;
  chunk_t *tail;
  size_t total;
  int draining;
#ifndef BTC_USE_POLL
  btc_link_t link;
#endif
  btc_link_t deferred;
  btc_link_t closed;
  btc_link_t listener;
  struct btc_server_s *server;
  btc_socket_socket_cb *on_socket;
  btc_socket_connect_cb *on_connect;
  btc_socket_close_cb *on_close;
  btc_socket_error_cb *on_error;
  btc_socket_data_cb *on_data;
  btc_socket_drain_cb *on_drain;
  btc_socket_message_cb *on_message;
  void *data;
};

typedef struct btc_tick_s {
  btc_loop_tick_cb *handler;
  void *data;
  btc_link_t link;
} btc_tick_t;

struct btc_loop_s {
#if defined(BTC_USE_EPOLL)
  int fd;
  struct epoll_event *events;
  int max;
  btc_list_t sockets;
#elif defined(BTC_USE_POLL)
  struct pollfd *pfds;
  btc_socket_t **sockets;
  size_t alloc;
  size_t length;
#else
  fd_set fds;
  fd_set rfds, wfds;
#if defined(_WIN32)
  fd_set efds;
#else
  int nfds;
#endif
  btc_list_t sockets;
#endif
  unsigned char buffer[65536];
#ifdef _WIN32
  char errmsg[256];
#endif
  btc_list_t deferred;
  btc_list_t closed;
  btc_list_t ticks;
  int error;
  int running;
};

struct btc_server_s {
  btc_loop_t *loop;
  btc_list_t sockets;
  btc_socket_socket_cb *on_socket;
  void *data;
  int no_delay;
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

#ifndef BTC_USE_SELECT
static void *
safe__realloc(void *ptr, size_t new_size, size_t old_size) {
  ptr = realloc(ptr, new_size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  if (new_size > old_size)
    memset((char *)ptr + old_size, 0, new_size - old_size);

  return ptr;
}

#define safe_realloc(ptr, new_size, old_size, type)     \
  (type *)safe__realloc(ptr, (new_size) * sizeof(type), \
                             (old_size) * sizeof(type))
#endif

/*
 * Sockaddr Helpers
 */

static int
sa_domain(const struct sockaddr *addr) {
  switch (addr->sa_family) {
    case AF_INET:
      return PF_INET;
#ifdef BTC_HAVE_RFC3493
    case AF_INET6:
      return PF_INET6;
#endif
    default:
      return PF_UNSPEC;
  }
}

static btc_socklen_t
sa_addrlen(const struct sockaddr *addr) {
  switch (addr->sa_family) {
    case AF_INET:
      return sizeof(struct sockaddr_in);
#ifdef BTC_HAVE_RFC3493
    case AF_INET6:
      return sizeof(struct sockaddr_in6);
#endif
    default:
      return 0;
  }
}

/*
 * Socket Helpers
 */

static int
set_nonblocking(btc_sockfd_t fd) {
#if defined(_WIN32)
  u_long yes = 1;
  return ioctlsocket(fd, FIONBIO, &yes);
#else
  int flags = fcntl(fd, F_GETFL);

  if (flags == -1)
    return -1;

  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

#ifndef _WIN32
static int
set_cloexec(int fd) {
#if defined(FD_CLOEXEC)
  int flags = fcntl(fd, F_GETFD);

  if (flags == -1)
    return -1;

  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
#else
  (void)fd;
  return -1;
#endif
}
#endif

#ifndef _WIN32
static int
try_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int fd;

#if defined(__GLIBC__) && defined(_GNU_SOURCE) && defined(SOCK_CLOEXEC)
  fd = accept4(sockfd, addr, addrlen, SOCK_CLOEXEC);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = accept(sockfd, addr, addrlen);

  if (fd == -1)
    return -1;

#ifdef SO_NOSIGPIPE
  {
    btc_sockopt_t yes = 1;

    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
  }
#endif

  set_cloexec(fd);

  return fd;
}
#endif

static btc_sockfd_t
safe_accept(btc_sockfd_t sockfd,
            struct sockaddr *addr,
            btc_socklen_t *addrlen) {
#if defined(_WIN32)
  return accept(sockfd, addr, addrlen);
#else
  socklen_t len;
  int fd;

  do {
    len = *addrlen;
    fd = try_accept(sockfd, addr, &len);
  } while (fd == -1 && errno == EINTR);

  if (fd != -1)
    *addrlen = len;

  return fd;
#endif
}

static btc_sockfd_t
safe_socket(int domain, int type, int protocol) {
#if defined(_WIN32)
  return socket(domain, type, protocol);
#else
  int fd;

#if defined(__GLIBC__) && defined(SOCK_CLOEXEC)
  fd = socket(domain, type | SOCK_CLOEXEC, protocol);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = socket(domain, type, protocol);

  if (fd == -1)
    return -1;

#ifdef SO_NOSIGPIPE
  {
    btc_sockopt_t yes = 1;

    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
  }
#endif

  set_cloexec(fd);

  return fd;
#endif
}

static btc_sockfd_t
safe_listener(int domain, int type, int protocol) {
  btc_sockfd_t fd = safe_socket(domain, type, protocol);
  btc_sockopt_t yes = 1;

  if (fd == BTC_INVALID_SOCKET)
    return BTC_INVALID_SOCKET;

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  /* https://stackoverflow.com/questions/1618240 */
  /* https://datatracker.ietf.org/doc/html/rfc3493#section-5.3 */
#ifdef IPV6_V6ONLY
  if (domain == PF_INET6)
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
#endif

  return fd;
}

static int
safe_connect(btc_sockfd_t sockfd,
             const struct sockaddr *addr,
             btc_socklen_t addrlen) {
#if defined(_WIN32)
  return connect(sockfd, addr, addrlen);
#else
  int rc;

  do {
    errno = 0;
    rc = connect(sockfd, addr, addrlen);
  } while (rc == -1 && errno == EINTR);

  if (rc == -1 && errno == 0)
    rc = 0;

  return rc;
#endif
}

static int
finalize_connect(btc_sockfd_t fd) {
  /* https://stackoverflow.com/questions/17769964 */
  /* https://cr.yp.to/docs/connect.html */
  struct sockaddr_storage storage;
  struct sockaddr *addr = (struct sockaddr *)&storage;
  btc_socklen_t addrlen = sizeof(storage);

  memset(&storage, 0, sizeof(storage));

  if (getpeername(fd, addr, &addrlen) == BTC_SOCKET_ERROR) {
#if defined(_WIN32)
    /* Unsure if we can abuse error slippage on windows. */
    if (WSAGetLastError() == WSAENOTCONN) {
      int len = sizeof(int);
      int rc = 0;

      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&rc, &len) == 0)
        WSASetLastError(rc);
    }

    return SOCKET_ERROR;
#else
    if (errno == ENOTCONN) {
      unsigned char ch;
      read(fd, &ch, 1);
    }

    return -1;
#endif
  }

  return 0;
}

/*
 * Epoll Helper
 */

#ifdef BTC_USE_EPOLL
static int
safe_epoll_create(void) {
  int fd;

#ifdef EPOLL_CLOEXEC
  fd = epoll_create1(EPOLL_CLOEXEC);

  if (fd != -1 || (errno != EINVAL && errno != ENOSYS))
    return fd;
#endif

  fd = epoll_create(128);

  if (fd != -1)
    set_cloexec(fd);

  return fd;
}
#endif

/*
 * Default Callbacks
 */

static void
default_socket_cb(btc_socket_t *socket, btc_socket_t *child) {
  (void)socket;
  (void)child;
}

static void
default_connect_cb(btc_socket_t *socket) {
  (void)socket;
}

static void
default_close_cb(btc_socket_t *socket) {
  (void)socket;
}

static void
default_error_cb(btc_socket_t *socket) {
  btc_socket_close(socket);
}

static int
default_data_cb(btc_socket_t *socket, const void *buf, size_t len) {
  (void)socket;
  (void)buf;
  (void)len;
  return 1;
}

static void
default_drain_cb(btc_socket_t *socket) {
  (void)socket;
}

static void
default_message_cb(btc_socket_t *socket,
                   const void *buf,
                   size_t len,
                   const struct btc_sockaddr_s *addr) {
  (void)socket;
  (void)buf;
  (void)len;
  (void)addr;
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
  socket->fd = BTC_INVALID_SOCKET;
  socket->state = BTC_SOCKET_DISCONNECTED;
#ifndef BTC_USE_POLL
  socket->link.value = socket;
#endif
  socket->deferred.value = socket;
  socket->closed.value = socket;
  socket->listener.value = socket;

  socket->on_socket = default_socket_cb;
  socket->on_connect = default_connect_cb;
  socket->on_close = default_close_cb;
  socket->on_error = default_error_cb;
  socket->on_data = default_data_cb;
  socket->on_drain = default_drain_cb;
  socket->on_message = default_message_cb;

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
  btc_sockopt_t val = (value != 0);

  setsockopt(socket->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
}

static int
btc_socket_setaddr(btc_socket_t *socket, const btc_sockaddr_t *addr) {
  if (!btc_sockaddr_get(socket->addr, addr)) {
    socket->loop->error = BTC_EAFNOSUPPORT;
    return 0;
  }

  return 1;
}

static int
btc_socket_listen(btc_socket_t *server, const btc_sockaddr_t *addr) {
  btc_socklen_t addrlen;
  btc_sockfd_t fd;
  int backlog;

  if (!btc_socket_setaddr(server, addr))
    return 0;

  fd = safe_listener(sa_domain(server->addr), SOCK_STREAM, 0);

  if (fd == BTC_INVALID_SOCKET) {
    server->loop->error = btc_errno;
    return 0;
  }

  addrlen = sa_addrlen(server->addr);

  if (bind(fd, server->addr, addrlen) == BTC_SOCKET_ERROR) {
    server->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  backlog = SOMAXCONN;

  if (backlog > 511)
    backlog = 511;

  if (listen(fd, backlog) == BTC_SOCKET_ERROR) {
    server->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  if (set_nonblocking(fd) == BTC_SOCKET_ERROR) {
    server->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  server->fd = fd;
  server->state = BTC_SOCKET_LISTENING;

  return 1;
}

static int
btc_socket_accept(btc_socket_t *socket, btc_socket_t *server) {
  btc_socklen_t addrlen = sizeof(socket->storage);
  btc_sockfd_t fd;

  memset(&socket->storage, 0, sizeof(socket->storage));

  fd = safe_accept(server->fd, socket->addr, &addrlen);

  if (fd == BTC_INVALID_SOCKET) {
    socket->loop->error = btc_errno;
    return 0;
  }

  if (set_nonblocking(fd) == BTC_SOCKET_ERROR) {
    socket->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTED;

  return 1;
}

static int
btc_socket_connect(btc_socket_t *socket, const btc_sockaddr_t *addr) {
  btc_socklen_t addrlen;
  btc_sockfd_t fd;

  if (!btc_socket_setaddr(socket, addr))
    return 0;

  fd = safe_socket(sa_domain(socket->addr), SOCK_STREAM, 0);

  if (fd == BTC_INVALID_SOCKET) {
    socket->loop->error = btc_errno;
    return 0;
  }

  if (set_nonblocking(fd) == BTC_SOCKET_ERROR) {
    socket->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  addrlen = sa_addrlen(socket->addr);

  if (safe_connect(fd, socket->addr, addrlen) == BTC_SOCKET_ERROR) {
    int error = btc_errno;

    if (error == BTC_EINPROGRESS) {
      socket->fd = fd;
      socket->state = BTC_SOCKET_CONNECTING;
      return 1;
    }

    socket->loop->error = error;

    btc_closesocket(fd);

    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTED;

  return 1;
}

static int
btc_socket_bind(btc_socket_t *socket, const btc_sockaddr_t *addr) {
  btc_socklen_t addrlen;
  btc_sockfd_t fd;

  if (!btc_socket_setaddr(socket, addr))
    return 0;

  fd = safe_listener(sa_domain(socket->addr), SOCK_DGRAM, 0);

  if (fd == BTC_INVALID_SOCKET) {
    socket->loop->error = btc_errno;
    return 0;
  }

  addrlen = sa_addrlen(socket->addr);

  if (bind(fd, socket->addr, addrlen) == BTC_SOCKET_ERROR) {
    socket->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  if (set_nonblocking(fd) == BTC_SOCKET_ERROR) {
    socket->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_BOUND;

  return 1;
}

static int
btc_socket_talk(btc_socket_t *socket, int family) {
  btc_sockfd_t fd;
  int domain;

  switch (family) {
    case BTC_AF_INET:
      domain = PF_INET;
      break;
#ifdef BTC_HAVE_RFC3493
    case BTC_AF_INET6:
      domain = PF_INET6;
      break;
#endif
    default:
      socket->loop->error = BTC_EAFNOSUPPORT;
      return 0;
  }

  fd = safe_socket(domain, SOCK_DGRAM, 0);

  if (fd == BTC_INVALID_SOCKET) {
    socket->loop->error = btc_errno;
    return 0;
  }

  if (set_nonblocking(fd) == BTC_SOCKET_ERROR) {
    socket->loop->error = btc_errno;
    btc_closesocket(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_BOUND;

  return 1;
}

static int
btc_socket_flush_write(btc_socket_t *socket) {
  chunk_t *chunk, *next;
  size_t max;
  int len;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    while (chunk->len > 0) {
      max = BTC_MIN(chunk->len, 1 << 30);
      len = send(socket->fd, (void *)chunk->raw, max, BTC_NOSIGNAL);

      if (len == BTC_SOCKET_ERROR) {
        int error = btc_errno;

        if (error == BTC_EINTR)
          continue;

        if (error == BTC_EAGAIN)
          break;

        if (error == BTC_EWOULDBLOCK)
          break;

        socket->loop->error = error;

        return -1;
      }

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
    socket->loop->error = BTC_EPIPE;

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
  btc_socklen_t addrlen;
  int len;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    CHECK(chunk->len <= (1 << 30));

    addrlen = sa_addrlen(chunk->addr);

    for (;;) {
      len = sendto(socket->fd,
                   (void *)chunk->raw,
                   chunk->len,
                   BTC_NOSIGNAL,
                   chunk->addr,
                   addrlen);

      if (len == BTC_SOCKET_ERROR) {
        int error = btc_errno;

        if (error == BTC_EINTR)
          continue;

        if (error == BTC_EAGAIN)
          return 0;

        if (error == BTC_EWOULDBLOCK)
          return 0;

        if (error == BTC_ENOBUFS)
          return 0;
      }

      break;
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
    socket->loop->error = BTC_EPIPE;

    if (data != NULL)
      free(data);

    return -1;
  }

  if (len == 0) {
    if (data != NULL)
      free(data);

    return 1;
  }

  if (len > (1 << 30)) {
    socket->loop->error = BTC_EMSGSIZE;
    free(data);
    return -1;
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
  btc_loop_t *loop = socket->loop;
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

  socket->state = BTC_SOCKET_DISCONNECTED;
  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;
  socket->draining = 0;

  btc_list_push(&loop->closed, &socket->closed);
}

static void
btc_socket_kill(btc_socket_t *socket) {
  btc_loop_t *loop = socket->loop;

  if (btc_list_has(&loop->deferred, &socket->deferred))
    btc_list_remove(&loop->deferred, &socket->deferred);

  btc_loop_unregister(loop, socket);

  btc_closesocket(socket->fd);

  socket->fd = BTC_INVALID_SOCKET;
  socket->on_close(socket);
}

void
btc_socket_timeout(btc_socket_t *socket) {
  socket->loop->error = BTC_ETIMEDOUT;
  btc_socket_close(socket);
}

/*
 * Loop
 */

static void
btc_loop_grow(btc_loop_t *loop, size_t n) {
#if defined(BTC_USE_EPOLL)
  if (n > (size_t)loop->max) {
    loop->events = safe_realloc(loop->events, n, loop->max, struct epoll_event);
    loop->max = n;
  }
#elif defined(BTC_USE_POLL)
  if (n > loop->alloc) {
    loop->pfds = safe_realloc(loop->pfds, n, loop->alloc, struct pollfd);
    loop->sockets = safe_realloc(loop->sockets, n, loop->alloc, btc_socket_t *);
    loop->alloc = n;
  }
#else
  (void)loop;
  (void)n;
#endif
}

btc_loop_t *
btc_loop_create(void) {
  btc_loop_t *loop = (btc_loop_t *)safe_malloc(sizeof(btc_loop_t));

  memset(loop, 0, sizeof(*loop));

#if defined(BTC_USE_EPOLL)
  loop->fd = safe_epoll_create();

  CHECK(loop->fd != -1);
#elif defined(BTC_USE_POLL)
  /* nothing */
#else
  FD_ZERO(&loop->fds);
#endif

  btc_loop_grow(loop, 64);

  return loop;
}

void
btc_loop_destroy(btc_loop_t *loop) {
  btc_link_t *it, *next;

  CHECK(loop->running == 0);

#if defined(BTC_USE_EPOLL)
  CHECK(loop->fd != -1);
  close(loop->fd);
  free(loop->events);
#elif defined(BTC_USE_POLL)
  free(loop->pfds);
  free(loop->sockets);
#endif

  for (it = loop->ticks.head; it != NULL; it = next) {
    next = it->next;
    free(it->value);
  }

  free(loop);
}

void
btc_loop_on_tick(btc_loop_t *loop, btc_loop_tick_cb *handler, void *data) {
  btc_tick_t *tick = (btc_tick_t *)safe_malloc(sizeof(btc_tick_t));

  memset(tick, 0, sizeof(*tick));

  tick->handler = handler;
  tick->data = data;
  tick->link.value = tick;

  btc_list_push(&loop->ticks, &tick->link);
}

void
btc_loop_off_tick(btc_loop_t *loop, btc_loop_tick_cb *handler, void *data) {
  btc_link_t *it;

  for (it = loop->ticks.head; it != NULL; it = it->next) {
    btc_tick_t *tick = it->value;

    if (tick->handler == handler && tick->data == data) {
      btc_list_remove(&loop->ticks, &tick->link);
      free(tick);
      break;
    }
  }
}

const char *
btc_loop_strerror(btc_loop_t *loop) {
#if defined(_WIN32)
  DWORD version = GetVersion();
  DWORD length = 0;

  /* Winsock error messages only available on Windows 2000 and up. */
  /* See: https://tangentsoft.net/wskfaq/articles/history.html */
  if (version < 0x80000000 && (version & 0xff) >= 5) {
    static const DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM
                             | FORMAT_MESSAGE_IGNORE_INSERTS
                             | FORMAT_MESSAGE_MAX_WIDTH_MASK;

    length = FormatMessageA(flags,
                            NULL,
                            loop->error,
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                            loop->errmsg,
                            sizeof(loop->errmsg),
                            NULL);
  }

  if (length == 0)
    sprintf(loop->errmsg, "WSA Error: %d", loop->error);

  return loop->errmsg;
#else
  return strerror(loop->error);
#endif
}

static int
btc_loop_register(btc_loop_t *loop, btc_socket_t *socket) {
#if defined(BTC_USE_EPOLL)
  struct epoll_event ev;

  memset(&ev, 0, sizeof(ev));

  ev.events = EPOLLIN | EPOLLOUT;
  ev.data.ptr = socket;

  if (epoll_ctl(loop->fd, EPOLL_CTL_ADD, socket->fd, &ev) != 0)
    return 0;

  btc_list_push(&loop->sockets, &socket->link);

  return 1;
#elif defined(BTC_USE_POLL)
  struct pollfd *pfd;

  if (loop->length == loop->alloc)
    btc_loop_grow(loop, (loop->length * 3) / 2);

  pfd = &loop->pfds[loop->length];
  pfd->fd = socket->fd;
  pfd->events = POLLIN | POLLOUT;
  pfd->revents = 0;

  socket->index = loop->length;

  loop->sockets[loop->length] = socket;
  loop->length++;

  return 1;
#else
#if defined(_WIN32)
  if (loop->sockets.length >= FD_SETSIZE) {
    loop->error = BTC_EMFILE;
    return 0;
  }
#else
  if (socket->fd >= FD_SETSIZE) {
    loop->error = BTC_EMFILE;
    return 0;
  }

  if (socket->fd + 1 > loop->nfds)
    loop->nfds = socket->fd + 1;
#endif

  FD_SET(socket->fd, &loop->fds);

  btc_list_push(&loop->sockets, &socket->link);

  return 1;
#endif
}

static void
btc_loop_unregister(btc_loop_t *loop, btc_socket_t *socket) {
#if defined(BTC_USE_EPOLL)
  struct epoll_event ev;

  memset(&ev, 0, sizeof(ev));

  if (epoll_ctl(loop->fd, EPOLL_CTL_DEL, socket->fd, &ev) != 0) {
    if (errno != EBADF && errno != ENOENT && errno != ELOOP)
      abort(); /* LCOV_EXCL_LINE */
  }

  btc_list_remove(&loop->sockets, &socket->link);
#elif defined(BTC_USE_POLL)
  CHECK(loop->length > 0);

  if (socket->index != loop->length - 1) {
    loop->pfds[socket->index] = loop->pfds[loop->length - 1];
    loop->sockets[socket->index] = loop->sockets[loop->length - 1];
    loop->sockets[socket->index]->index = socket->index;
  }

  loop->length--;
#else
  FD_CLR(socket->fd, &loop->fds);

  btc_list_remove(&loop->sockets, &socket->link);
#endif
}

btc_socket_t *
btc_loop_listen(btc_loop_t *loop, const btc_sockaddr_t *addr) {
  btc_socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_listen(socket, addr))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    btc_closesocket(socket->fd);
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
    btc_closesocket(socket->fd);
    goto fail;
  }

  if (socket->state == BTC_SOCKET_CONNECTED) {
    btc_list_push(&loop->deferred, &socket->deferred);
    socket->state = BTC_SOCKET_CONNECTING;
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
    btc_closesocket(socket->fd);
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
    btc_closesocket(socket->fd);
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
        btc_closesocket(socket->fd);
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
      btc_sockfd_t fd = socket->fd;
      int len;

      while (socket->state == BTC_SOCKET_CONNECTED) {
        len = recv(fd, (void *)buf, size, 0);

        if (len == BTC_SOCKET_ERROR) {
          int error = btc_errno;

          if (error == BTC_EINTR)
            continue;

          if (error == BTC_EAGAIN)
            break;

          if (error == BTC_EWOULDBLOCK)
            break;

          socket->loop->error = error;
          socket->on_error(socket);

          break;
        }

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
      btc_sockfd_t fd = socket->fd;
      btc_sockaddr_t addr;
      btc_socklen_t fromlen;
      int len;

      while (socket->state == BTC_SOCKET_BOUND) {
        memset(&storage, 0, sizeof(storage));

        fromlen = sizeof(storage);

        len = recvfrom(fd, (void *)buf, size, 0, from, &fromlen);

        if (len == BTC_SOCKET_ERROR) {
          int error = btc_errno;

          if (error == BTC_EINTR)
            continue;

          if (error == BTC_EAGAIN)
            break;

          if (error == BTC_EWOULDBLOCK)
            break;

          socket->loop->error = error;
          socket->on_error(socket);

          break;
        }

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
      if (finalize_connect(socket->fd) == BTC_SOCKET_ERROR) {
        socket->loop->error = btc_errno;
        socket->on_error(socket);
        btc_socket_close(socket);
        break;
      }

      socket->state = BTC_SOCKET_CONNECTED;
      socket->on_connect(socket);

      /* fall through */
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
handle_deferred(btc_loop_t *loop) {
  while (loop->deferred.length > 0) {
    btc_link_t *it = btc_list_shift(&loop->deferred);
    btc_socket_t *socket = it->value;

    if (socket->state != BTC_SOCKET_CONNECTING)
      continue;

    socket->state = BTC_SOCKET_CONNECTED;
    socket->on_connect(socket);

    if (btc_socket_flush_write(socket) == -1)
      socket->on_error(socket);
  }
}

static void
handle_ticks(btc_loop_t *loop) {
  btc_link_t *it;

  for (it = loop->ticks.head; it != NULL; it = it->next) {
    btc_tick_t *tick = it->value;

    tick->handler(tick->data);
  }
}

static void
handle_closed(btc_loop_t *loop) {
  btc_link_t *it, *next;
  btc_socket_t *socket;

  for (it = loop->closed.head; it != NULL; it = next) {
    socket = it->value;
    next = it->next;

    btc_socket_kill(socket);
    btc_socket_destroy(socket);
  }

  btc_list_init(&loop->closed);
}

void
btc_loop_start(btc_loop_t *loop) {
  loop->running = 1;

  while (loop->running) {
    btc_loop_poll(loop, 25);
    btc_time_sleep(1);
  }

  btc_loop_close(loop);
}

void
btc_loop_stop(btc_loop_t *loop) {
  loop->running = 0;
}

void
btc_loop_cleanup(btc_loop_t *loop) {
  CHECK(loop->running == 0);

  handle_closed(loop);
}

void
btc_loop_poll(btc_loop_t *loop, int timeout) {
#if defined(BTC_USE_EPOLL)
  int i, count;

  handle_deferred(loop);

retry:
  count = epoll_wait(loop->fd, loop->events, loop->max, timeout);

  if (count == -1) {
    if (errno == EINTR)
      goto retry;

    abort(); /* LCOV_EXCL_LINE */
  }

  for (i = 0; i < count; i++) {
    struct epoll_event *ev = &loop->events[i];
    btc_socket_t *socket = ev->data.ptr;

    if (ev->events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
      handle_write(loop, socket);

    if (ev->events & (EPOLLIN | EPOLLERR | EPOLLHUP))
      handle_read(loop, socket);
  }

  if (count == loop->max)
    btc_loop_grow(loop, (count * 3) / 2);

  handle_ticks(loop);
  handle_closed(loop);
#elif defined(BTC_USE_POLL)
  int count;

  handle_deferred(loop);

retry:
  count = poll(loop->pfds, loop->length, timeout);

  if (count == -1) {
    if (errno == EINTR)
      goto retry;

    abort(); /* LCOV_EXCL_LINE */
  }

  if (count > 0) {
    size_t length = loop->length;
    size_t i;

    for (i = 0; i < length; i++) {
      btc_socket_t *socket = loop->sockets[i];
      struct pollfd *pfd = &loop->pfds[i];

      if (pfd->revents & POLLNVAL) {
        btc_socket_close(socket);
        continue;
      }

      if (pfd->revents & (POLLOUT | POLLERR | POLLHUP))
        handle_write(loop, socket);

      if (pfd->revents & (POLLIN | POLLERR | POLLHUP))
        handle_read(loop, socket);

      pfd->revents = 0;
    }
  }

  handle_ticks(loop);
  handle_closed(loop);
#else /* BTC_USE_SELECT */
  struct timeval *tp = NULL;
  struct timeval tv;
  int count;

  handle_deferred(loop);

retry:
  memcpy(&loop->rfds, &loop->fds, sizeof(loop->fds));
  memcpy(&loop->wfds, &loop->fds, sizeof(loop->fds));
#ifdef _WIN32
  memcpy(&loop->efds, &loop->fds, sizeof(loop->fds));
#endif

  if (timeout >= 0) {
    memset(&tv, 0, sizeof(tv));

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    tp = &tv;
  }

#if defined(_WIN32)
  count = select(FD_SETSIZE, &loop->rfds, &loop->wfds, &loop->efds, tp);
#else
  count = select(loop->nfds, &loop->rfds, &loop->wfds, NULL, tp);
#endif

  if (count == BTC_SOCKET_ERROR) {
    int error = btc_errno;

    if (error == BTC_EINTR)
      goto retry;

#if defined(_WIN32)
    if (error != BTC_EINVAL)
      abort(); /* LCOV_EXCL_LINE */

    if (timeout > 0)
      Sleep(timeout);

    count = 0;
#else
    abort(); /* LCOV_EXCL_LINE */
#endif
  }

  if (count > 0) {
    btc_link_t *tail = loop->sockets.tail;
    btc_link_t *it;

    CHECK(tail != NULL);

    for (it = loop->sockets.head; it != tail->next; it = it->next) {
      btc_socket_t *socket = it->value;
      btc_sockfd_t fd = socket->fd;

#if defined(_WIN32)
      if (FD_ISSET(fd, &loop->wfds) | FD_ISSET(fd, &loop->efds))
        handle_write(loop, socket);
#else
      if (FD_ISSET(fd, &loop->wfds))
        handle_write(loop, socket);
#endif

      if (FD_ISSET(fd, &loop->rfds))
        handle_read(loop, socket);
    }
  }

  handle_ticks(loop);
  handle_closed(loop);
#endif /* BTC_USE_SELECT */
}

void
btc_loop_close(btc_loop_t *loop) {
#if defined(BTC_USE_POLL)
  size_t i;

  handle_deferred(loop);

  for (i = 0; i < loop->length; i++)
    btc_socket_close(loop->sockets[i]);

  handle_closed(loop);
#else /* !BTC_USE_POLL */
  btc_link_t *it;

  handle_deferred(loop);

  for (it = loop->sockets.head; it != NULL; it = it->next)
    btc_socket_close(it->value);

  handle_closed(loop);

#if defined(BTC_USE_SELECT) && !defined(_WIN32)
  loop->nfds = 0;
#endif
#endif /* !BTC_USE_POLL */
}

int
btc_loop_fd_setsize(void) {
#if !defined(_WIN32) && defined(BTC_USE_SELECT)
  return FD_SETSIZE;
#else
  return -1;
#endif
}

/*
 * Server
 */

btc_server_t *
btc_server_create(btc_loop_t *loop) {
  btc_server_t *server = (btc_server_t *)safe_malloc(sizeof(btc_server_t));

  memset(server, 0, sizeof(*server));

  server->loop = loop;
  server->no_delay = -1;

  return server;
}

void
btc_server_destroy(btc_server_t *server) {
  CHECK(server->loop->running == 0);
  CHECK(server->sockets.length == 0);

  free(server);
}

const char *
btc_server_strerror(btc_server_t *server) {
  return btc_loop_strerror(server->loop);
}

static void
btc_server_on_close(btc_socket_t *socket) {
  btc_server_t *server = socket->server;

  btc_list_remove(&server->sockets, &socket->listener);
}

int
btc_server_listen(btc_server_t *server, const btc_sockaddr_t *addr) {
  btc_socket_t *socket = btc_loop_listen(server->loop, addr);

  if (socket == NULL)
    return 0;

  socket->server = server;
  socket->on_close = btc_server_on_close;

  if (server->on_socket != NULL)
    socket->on_socket = server->on_socket;

  if (server->data != NULL)
    socket->data = server->data;

  if (server->no_delay != -1)
    btc_socket_set_nodelay(socket, server->no_delay);

  btc_list_push(&server->sockets, &socket->listener);

  return 1;
}

int
btc_server_listen_local(btc_server_t *server, int port) {
  btc_sockaddr_t addr;
  int ret = 0;

  if (port < 0 || port > 0xffff)
    return 0;

  CHECK(btc_sockaddr_import(&addr, "::1", port));

  ret |= btc_server_listen(server, &addr);

  CHECK(btc_sockaddr_import(&addr, "127.0.0.1", port));

  ret |= btc_server_listen(server, &addr);

  return ret;
}

int
btc_server_listen_external(btc_server_t *server, int port) {
  btc_sockaddr_t addr;
  int ret = 0;

  if (port < 0 || port > 0xffff)
    return 0;

  CHECK(btc_sockaddr_import(&addr, "::", port));

  ret |= btc_server_listen(server, &addr);

  CHECK(btc_sockaddr_import(&addr, "0.0.0.0", port));

  ret |= btc_server_listen(server, &addr);

  return ret;
}

void
btc_server_close(btc_server_t *server) {
  btc_link_t *it;

  for (it = server->sockets.head; it != NULL; it = it->next)
    btc_socket_close(it->value);
}

void
btc_server_on_socket(btc_server_t *server, btc_socket_socket_cb *handler) {
  CHECK(server->sockets.length == 0);

  server->on_socket = handler;
}

void
btc_server_set_data(btc_server_t *server, void *data) {
  CHECK(server->sockets.length == 0);

  server->data = data;
}

void
btc_server_set_nodelay(btc_server_t *server, int value) {
  CHECK(server->sockets.length == 0);

  server->no_delay = (value != 0);
}
