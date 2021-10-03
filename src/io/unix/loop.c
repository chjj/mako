/*!
 * loop.c - event loop for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <io/core.h>
#include <io/loop.h>

/*
 * Backend
 */

#if !defined(BTC_USE_SELECT) \
 && !defined(BTC_USE_POLL)   \
 && !defined(BTC_USE_EPOLL)
#  if defined(__linux__)
#    define BTC_USE_EPOLL
#  elif defined(_AIX)
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
#  include <sys/select.h>
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

typedef struct btc_socket_s {
  struct btc_loop_s *loop;
  struct sockaddr_storage storage;
  struct sockaddr *addr;
  int fd;
  int state;
#ifdef BTC_USE_POLL
  size_t index;
#endif
  unsigned char buffer[65536];
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
} btc__socket_t;

typedef struct btc_tick_s {
  btc_loop_tick_cb *handler;
  void *data;
  struct btc_tick_s *prev;
  struct btc_tick_s *next;
} btc_tick_t;

typedef struct btc_loop_s {
#if defined(BTC_USE_EPOLL)
  int fd;
  struct epoll_event *events;
  int max;
  btc__socket_t *head;
  btc__socket_t *tail;
  size_t length;
#elif defined(BTC_USE_POLL)
  struct pollfd *pfds;
  btc__socket_t **sockets;
  size_t alloc;
  size_t length;
  size_t index;
#else
  fd_set rfds, rfdi;
  fd_set wfds, wfdi;
  int nfds;
  btc__socket_t *sockets[FD_SETSIZE];
#endif
  struct btc_closed_queue {
    btc__socket_t *head;
    btc__socket_t *tail;
    size_t length;
  } closed;
  struct btc_ticks {
    btc_tick_t *head;
    btc_tick_t *tail;
    size_t length;
  } ticks;
  int error;
  int running;
} btc__loop_t;

/*
 * Helpers
 */

static void *
safe_malloc(size_t size) {
  void *ptr = malloc(size);

  CHECK(ptr != NULL);

  return ptr;
}

static void *
safe__realloc(void *ptr, size_t new_size, size_t old_size) {
  ptr = realloc(ptr, new_size);

  if (ptr == NULL) {
    abort(); /* LCOV_EXCL_LINE */
    return NULL;
  }

  if (new_size > old_size)
    memset((char *)ptr + old_size, 0, new_size - old_size);

  return ptr;
}

#define safe_realloc(ptr, new_size, old_size, type)     \
  (type *)safe__realloc(ptr, (new_size) * sizeof(type), \
                             (old_size) * sizeof(type))

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
    case AF_UNIX:
      return PF_UNIX;
    default:
      return PF_UNSPEC;
  }
}

static socklen_t
sa_addrlen(const struct sockaddr *addr) {
  switch (addr->sa_family) {
    case AF_INET: {
      return sizeof(struct sockaddr_in);
    }

    case AF_INET6: {
      return sizeof(struct sockaddr_in6);
    }

    case AF_UNIX: {
      const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
      size_t len = offsetof(struct sockaddr_un, sun_path);

      return len + strlen(un->sun_path);
    }

    default: {
      return 0;
    }
  }
}

/*
 * Socket Helpers
 */

static int
set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);

  if (flags == -1)
    return -1;

  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

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

static int
try_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int fd;

#if defined(__GLIBC__) && defined(_GNU_SOURCE) && defined(SOCK_CLOEXEC)
  fd = accept4(sockfd, addr, addrlen, SOCK_CLOEXEC | SOCK_NONBLOCK);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = accept(sockfd, addr, addrlen);

  if (fd != -1)
    set_cloexec(fd);

  return fd;
}

static int
safe_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  socklen_t len;
  int fd;

  do {
    len = *addrlen;
    fd = try_accept(sockfd, addr, &len);
  } while (fd == -1 && errno == EINTR);

  if (fd != -1)
    *addrlen = len;

  return fd;
}

static int
safe_socket(int domain, int type, int protocol) {
  int fd;

#if defined(__GLIBC__) && defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
  fd = socket(domain, type | SOCK_CLOEXEC | SOCK_NONBLOCK, protocol);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = socket(domain, type, protocol);

  if (fd != -1)
    set_cloexec(fd);

  return fd;
}

static int
safe_listener(int domain, int type, int protocol) {
  int fd = safe_socket(domain, type, protocol);
  int yes = 1;
  int no = 0;

  if (fd == -1)
    return -1;

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  /* https://stackoverflow.com/questions/1618240 */
  /* https://datatracker.ietf.org/doc/html/rfc3493#section-5.3 */
#ifdef IPV6_V6ONLY
  if (domain == PF_INET6)
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
#endif

  return fd;
}

static int
safe_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int rc;

  do {
    errno = 0;
    rc = connect(sockfd, addr, addrlen);
  } while (rc == -1 && errno == EINTR);

  if (rc == -1 && errno == 0)
    rc = 0;

  return rc;
}

/*
 * Epoll Helper
 */

#if defined(BTC_USE_EPOLL)
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
 * Time Helpers
 */

static void
time_sleep(long long ms) {
  struct timeval tv;
  int rc;

  if (ms <= 0)
    return;

  memset(&tv, 0, sizeof(tv));

  tv.tv_sec = 0;
  tv.tv_usec = ms * 1000;

  /* Linux updates the timeval. This is one
     situation where we actually _want_ that
     behavior. */
  do {
    rc = select(0, NULL, NULL, NULL, &tv);
  } while (rc == -1 && errno == EINTR);
}

static long long
time_msec(void) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/*
 * Socket
 */

static btc__socket_t *
btc_socket_create(btc__loop_t *loop) {
  btc__socket_t *socket = (btc__socket_t *)safe_malloc(sizeof(btc__socket_t));

  memset(socket, 0, sizeof(*socket));

  socket->loop = loop;
  socket->addr = (struct sockaddr *)&socket->storage;
  socket->fd = -1;
  socket->state = BTC_SOCKET_DISCONNECTED;

  return socket;
}

void
btc_socket_destroy(btc__socket_t *socket) {
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

btc__loop_t *
btc_socket_loop(btc__socket_t *socket) {
  return socket->loop;
}

void
btc_socket_address(btc_sockaddr_t *addr, btc__socket_t *socket) {
  CHECK(btc_sockaddr_set(addr, socket->addr));
}

void
btc_socket_on_socket(btc__socket_t *socket, btc_socket_socket_cb *handler) {
  socket->on_socket = handler;
}

void
btc_socket_on_connect(btc__socket_t *socket, btc_socket_connect_cb *handler) {
  socket->on_connect = handler;
}

void
btc_socket_on_close(btc__socket_t *socket, btc_socket_close_cb *handler) {
  socket->on_close = handler;
}

void
btc_socket_on_error(btc__socket_t *socket, btc_socket_error_cb *handler) {
  socket->on_error = handler;
}

void
btc_socket_on_data(btc__socket_t *socket, btc_socket_data_cb *handler) {
  socket->on_data = handler;
}

void
btc_socket_on_drain(btc__socket_t *socket, btc_socket_drain_cb *handler) {
  socket->on_drain = handler;
}

void
btc_socket_on_message(btc_socket_t *socket, btc_socket_message_cb *handler) {
  socket->on_message = handler;
}

void
btc_socket_complete(btc__socket_t *socket) {
  /* This function essentialy means, "I'm ready for on_connect to be called." */
  /* Necessary in cases where the socket connects immediately. */
  if (socket->state == BTC_SOCKET_CONNECTED && socket->on_connect != NULL) {
    socket->on_connect(socket);
    socket->on_connect = NULL;
  }
}

void
btc_socket_set_data(btc__socket_t *socket, void *data) {
  socket->data = data;
}

void *
btc_socket_get_data(btc__socket_t *socket) {
  return socket->data;
}

const char *
btc_socket_strerror(btc__socket_t *socket) {
  return strerror(socket->loop->error);
}

size_t
btc_socket_buffered(btc__socket_t *socket) {
  return socket->total;
}

static int
btc_socket_setaddr(btc__socket_t *socket, const btc_sockaddr_t *addr) {
  if (!btc_sockaddr_get(socket->addr, addr)) {
    socket->loop->error = EAFNOSUPPORT;
    return 0;
  }

  return 1;
}

static int
btc_socket_listen(btc__socket_t *server, const btc_sockaddr_t *addr, int max) {
  int fd;

  if (!btc_socket_setaddr(server, addr))
    return 0;

  fd = safe_listener(sa_domain(server->addr), SOCK_STREAM, 0);

  if (fd == -1) {
    server->loop->error = errno;
    return 0;
  }

  if (bind(fd, server->addr, sa_addrlen(server->addr)) == -1) {
    server->loop->error = errno;
    close(fd);
    return 0;
  }

  if (listen(fd, max) == -1) {
    server->loop->error = errno;
    close(fd);
    return 0;
  }

  if (set_nonblocking(fd) == -1) {
    server->loop->error = errno;
    close(fd);
    return 0;
  }

  server->fd = fd;
  server->state = BTC_SOCKET_LISTENING;

  return 1;
}

static int
btc_socket_accept(btc__socket_t *socket, btc__socket_t *server) {
  socklen_t addrlen = sizeof(socket->storage);
  int fd;

  memset(&socket->storage, 0, sizeof(socket->storage));

  fd = safe_accept(server->fd, socket->addr, &addrlen);

  if (fd == -1) {
    socket->loop->error = errno;
    return 0;
  }

  if (set_nonblocking(fd) == -1) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTED;

  return 1;
}

static int
btc_socket_connect(btc__socket_t *socket, const btc_sockaddr_t *addr) {
  int fd;

  if (!btc_socket_setaddr(socket, addr))
    return 0;

  fd = safe_socket(sa_domain(socket->addr), SOCK_STREAM, 0);

  if (fd == -1) {
    socket->loop->error = errno;
    return 0;
  }

  if (set_nonblocking(fd) == -1) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  if (safe_connect(fd, socket->addr, sa_addrlen(socket->addr)) == -1) {
    if (errno == EINPROGRESS || errno == EALREADY) {
      socket->fd = fd;
      socket->state = BTC_SOCKET_CONNECTING;
      return 1;
    }

    if (errno != EISCONN) {
      socket->loop->error = errno;
      close(fd);
      return 0;
    }
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTED;

  return 1;
}

static int
btc_socket_bind(btc__socket_t *socket, const btc_sockaddr_t *addr) {
  int fd;

  if (!btc_socket_setaddr(socket, addr))
    return 0;

  fd = safe_listener(sa_domain(socket->addr), SOCK_DGRAM, 0);

  if (fd == -1) {
    socket->loop->error = errno;
    return 0;
  }

  if (bind(fd, socket->addr, sa_addrlen(socket->addr)) == -1) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  if (set_nonblocking(fd) == -1) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_BOUND;

  return 1;
}

static int
btc_socket_talk(btc__socket_t *socket, int family) {
  int fd, domain;

  switch (family) {
    case BTC_AF_INET:
      domain = PF_INET;
      break;
    case BTC_AF_INET6:
      domain = PF_INET6;
      break;
    case BTC_AF_UNIX:
      domain = PF_UNIX;
      break;
    default:
      socket->loop->error = EAFNOSUPPORT;
      return 0;
  }

  fd = safe_socket(domain, SOCK_DGRAM, 0);

  if (fd == -1) {
    socket->loop->error = errno;
    return 0;
  }

  if (set_nonblocking(fd) == -1) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_BOUND;

  return 1;
}

static int
btc_socket_flush_write(btc__socket_t *socket) {
  chunk_t *chunk, *next;
  int len;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    CHECK(chunk->len <= INT_MAX);

    while (chunk->len > 0) {
      len = write(socket->fd, chunk->raw, chunk->len);

      if (len == -1) {
        if (errno == EINTR)
          continue;

        if (errno == EAGAIN)
          break;

        if (errno == EWOULDBLOCK)
          break;

        socket->loop->error = errno;

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
btc_socket_write(btc__socket_t *socket, void *data, size_t len) {
  unsigned char *raw = (unsigned char *)data;
  chunk_t *chunk;

  if (socket->state != BTC_SOCKET_CONNECTING
      && socket->state != BTC_SOCKET_CONNECTED) {
    socket->loop->error = EPIPE;

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
btc_socket_flush_send(btc__socket_t *socket) {
  chunk_t *chunk, *next;
  socklen_t addrlen;
  int len;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    CHECK(chunk->len <= INT_MAX);

    addrlen = sa_addrlen(chunk->addr);

    do {
      len = sendto(socket->fd,
                   chunk->raw,
                   chunk->len,
                   0,
                   chunk->addr,
                   addrlen);
    } while (len == -1 && errno == EINTR);

    if (len == -1) {
      if (errno == EAGAIN)
        return 0;

      if (errno == EWOULDBLOCK)
        return 0;

      if (errno == ENOBUFS)
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
btc_socket_send(btc__socket_t *socket,
                void *data,
                size_t len,
                const btc_sockaddr_t *addr) {
  unsigned char *raw = (unsigned char *)data;
  chunk_t *chunk;

  if (socket->state != BTC_SOCKET_BOUND) {
    socket->loop->error = EPIPE;
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
btc_loop_unregister(btc__loop_t *loop, btc__socket_t *socket);

void
btc_socket_close(btc__socket_t *socket) {
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

  CHECK(socket->fd != -1);

  close(socket->fd);

  socket->fd = -1;
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

static void
btc_loop_grow(btc__loop_t *loop, size_t n) {
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
  (void)safe__realloc;
  (void)loop;
  (void)n;
#endif
}

btc__loop_t *
btc_loop_create(void) {
  btc__loop_t *loop = (btc__loop_t *)safe_malloc(sizeof(btc__loop_t));

  memset(loop, 0, sizeof(*loop));

#if defined(BTC_USE_EPOLL)
  loop->fd = safe_epoll_create();

  CHECK(loop->fd != -1);
#elif defined(BTC_USE_POLL)
  /* nothing */
#else
  FD_ZERO(&loop->rfds);
  FD_ZERO(&loop->wfds);
#endif

  btc_loop_grow(loop, 64);

  return loop;
}

void
btc_loop_destroy(btc__loop_t *loop) {
  btc_tick_t *tick, *next;

  CHECK(loop->running == 0);

#if defined(BTC_USE_EPOLL)
  CHECK(loop->fd != -1);
  close(loop->fd);
  free(loop->events);
#elif defined(BTC_USE_POLL)
  free(loop->pfds);
  free(loop->sockets);
#endif

  for (tick = loop->ticks.head; tick != NULL; tick = next) {
    next = tick->next;
    free(tick);
  }

  free(loop);
}

void
btc_loop_on_tick(btc__loop_t *loop, btc_loop_tick_cb *handler, void *data) {
  btc_tick_t *tick = (btc_tick_t *)safe_malloc(sizeof(btc_tick_t));

  tick->handler = handler;
  tick->data = data;
  tick->prev = NULL;
  tick->next = NULL;

  btc_list_push(&loop->ticks, tick, btc_tick_t);
}

void
btc_loop_off_tick(btc__loop_t *loop, btc_loop_tick_cb *handler, void *data) {
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
btc_loop_strerror(btc__loop_t *loop) {
  return strerror(loop->error);
}

static int
btc_loop_register(btc__loop_t *loop, btc__socket_t *socket) {
#if defined(BTC_USE_EPOLL)
  struct epoll_event ev;

  CHECK(socket->fd != -1);

  memset(&ev, 0, sizeof(ev));

  ev.events = EPOLLIN | EPOLLOUT;
  ev.data.fd = socket->fd;
  ev.data.ptr = socket;

  if (epoll_ctl(loop->fd, EPOLL_CTL_ADD, socket->fd, &ev) != 0)
    return 0;

  btc_list_push(loop, socket, btc__socket_t);

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
  if (socket->fd >= FD_SETSIZE) {
    loop->error = EMFILE;
    return 0;
  }

  CHECK(loop->sockets[socket->fd] == NULL);

  if (socket->fd + 1 > loop->nfds)
    loop->nfds = socket->fd + 1;

  FD_SET(socket->fd, &loop->rfds);
  FD_SET(socket->fd, &loop->wfds);

  loop->sockets[socket->fd] = socket;

  return 1;
#endif
}

static void
btc_loop_unregister(btc__loop_t *loop, btc__socket_t *socket) {
#if defined(BTC_USE_EPOLL)
  struct epoll_event ev;

  memset(&ev, 0, sizeof(ev));

  if (epoll_ctl(loop->fd, EPOLL_CTL_DEL, socket->fd, &ev) != 0) {
    if (errno != EBADF && errno != ENOENT && errno != ELOOP)
      abort(); /* LCOV_EXCL_LINE */
  }

  btc_list_remove(loop, socket, btc__socket_t);
#elif defined(BTC_USE_POLL)
  loop->pfds[socket->index] = loop->pfds[loop->length - 1];
  loop->sockets[socket->index] = loop->sockets[loop->length - 1];
  loop->sockets[socket->index]->index = socket->index;
  loop->length--;

  if (loop->index > 0)
    loop->index--;
#else
  FD_CLR(socket->fd, &loop->rfds);
  FD_CLR(socket->fd, &loop->wfds);

  loop->sockets[socket->fd] = NULL;
#endif
}

btc__socket_t *
btc_loop_listen(btc__loop_t *loop, const btc_sockaddr_t *addr, int max) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_listen(socket, addr, max))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    close(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

btc__socket_t *
btc_loop_connect(btc__loop_t *loop, const btc_sockaddr_t *addr) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_connect(socket, addr))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    close(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

btc__socket_t *
btc_loop_bind(btc__loop_t *loop, const btc_sockaddr_t *addr) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_bind(socket, addr))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    close(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

btc__socket_t *
btc_loop_talk(btc__loop_t *loop, int family) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_talk(socket, family))
    goto fail;

  if (!btc_loop_register(loop, socket)) {
    close(socket->fd);
    goto fail;
  }

  return socket;
fail:
  btc_socket_destroy(socket);
  return NULL;
}

static void
handle_read(btc__loop_t *loop, btc__socket_t *socket) {
  switch (socket->state) {
    case BTC_SOCKET_LISTENING: {
      btc__socket_t *child = btc_socket_create(loop);

      if (!btc_socket_accept(child, socket))
        goto fail;

      if (!btc_loop_register(loop, child)) {
        close(socket->fd);
        goto fail;
      }

      socket->on_socket(socket, child);

      break;
fail:
      btc_socket_destroy(child);
      break;
    }

    case BTC_SOCKET_CONNECTED: {
      unsigned char *buf = socket->buffer;
      size_t size = sizeof(socket->buffer);
      int fd = socket->fd;
      int len;

      CHECK(size <= INT_MAX);

      while (socket->state == BTC_SOCKET_CONNECTED) {
        len = read(fd, buf, size);

        if (len == -1) {
          if (errno == EINTR)
            continue;

          if (errno == EAGAIN)
            break;

          if (errno == EWOULDBLOCK)
            break;

          socket->loop->error = errno;
          socket->on_error(socket);

          break;
        }

        if ((size_t)len > size)
          abort();

        socket->on_data(socket, buf, len);

        if (len == 0)
          break;
      }

      break;
    }

    case BTC_SOCKET_BOUND: {
      unsigned char *buf = socket->buffer;
      size_t size = sizeof(socket->buffer);
      struct sockaddr_storage storage;
      struct sockaddr *from = (struct sockaddr *)&storage;
      int fd = socket->fd;
      btc_sockaddr_t addr;
      socklen_t fromlen;
      int len;

      CHECK(size <= INT_MAX);

      while (socket->state == BTC_SOCKET_BOUND) {
        memset(from, 0, sizeof(storage));
        fromlen = sizeof(storage);

        len = recvfrom(fd, buf, size, 0, from, &fromlen);

        if (len == -1) {
          if (errno == EINTR)
            continue;

          if (errno == EAGAIN)
            break;

          if (errno == EWOULDBLOCK)
            break;

          socket->loop->error = errno;
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
handle_write(btc__loop_t *loop, btc__socket_t *socket) {
  (void)loop;

  switch (socket->state) {
    case BTC_SOCKET_CONNECTING: {
      socklen_t addrlen = sa_addrlen(socket->addr);

      if (safe_connect(socket->fd, socket->addr, addrlen) == -1) {
        if (errno == EINPROGRESS || errno == EALREADY)
          break;

        if (errno != EISCONN) {
          socket->loop->error = errno;
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
handle_ticks(btc__loop_t *loop) {
  btc_tick_t *tick, *next;

  for (tick = loop->ticks.head; tick != NULL; tick = next) {
    next = tick->next;

    tick->handler(loop, tick->data);
  }
}

static void
handle_closed(btc__loop_t *loop) {
  btc__socket_t *socket, *next;

  for (socket = loop->closed.head; socket != NULL; socket = next) {
    next = socket->next;

    socket->on_close(socket);
    btc_socket_destroy(socket);
  }

  btc_list_init(&loop->closed);
}

#if defined(BTC_USE_EPOLL)
void
btc_loop_start(btc__loop_t *loop) {
  btc__socket_t *socket, *next;
  struct epoll_event *event;
  long long prev, diff;
  int i, count;

  loop->running = 1;

  while (loop->running) {
    prev = time_msec();
    count = epoll_wait(loop->fd, loop->events, loop->max, BTC_TICK_RATE);
    diff = time_msec() - prev;

    if (diff < 0)
      diff = 0;

    if (count == -1) {
      if (errno == EINTR)
        continue;

      abort();
    }

    for (i = 0; i < count; i++) {
      event = &loop->events[i];
      socket = (btc__socket_t *)event->data.ptr;

      if (event->events & (EPOLLIN | EPOLLERR | EPOLLHUP))
        handle_read(loop, socket);

      if (event->events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
        handle_write(loop, socket);
    }

    handle_ticks(loop);
    handle_closed(loop);

    if (count == loop->max)
      btc_loop_grow(loop, (count * 3) / 2);

    time_sleep(BTC_TICK_RATE - diff);
  }

  for (socket = loop->head; socket != NULL; socket = next) {
    next = socket->next;

    btc_socket_close(socket);
    socket->on_close(socket);
    btc_socket_destroy(socket);
  }

  btc_list_init(&loop->closed);
  btc_list_init(loop);
}
#elif defined(BTC_USE_POLL)
void
btc_loop_start(btc__loop_t *loop) {
  btc__socket_t *socket;
  long long prev, diff;
  struct pollfd *pfd;
  int count;

  loop->running = 1;

  while (loop->running) {
    prev = time_msec();
    count = poll(loop->pfds, loop->length, BTC_TICK_RATE);
    diff = time_msec() - prev;

    if (diff < 0)
      diff = 0;

    if (count == -1) {
      if (errno == EINTR)
        continue;

      abort();
    }

    if (count != 0) {
      for (loop->index = 0; loop->index < loop->length; loop->index++) {
        socket = loop->sockets[loop->index];
        pfd = &loop->pfds[loop->index];

        if (pfd->revents & POLLNVAL) {
          btc_socket_close(socket);
          continue;
        }

        if (pfd->revents & (POLLIN | POLLERR | POLLHUP))
          handle_read(loop, socket);

        if (pfd->revents & (POLLOUT | POLLERR | POLLHUP))
          handle_write(loop, socket);

        pfd->revents = 0;
      }
    }

    handle_ticks(loop);
    handle_closed(loop);

    time_sleep(BTC_TICK_RATE - diff);
  }

  while (loop->length > 0) {
    socket = loop->sockets[0];

    btc_socket_close(socket);
    socket->on_close(socket);
    btc_socket_destroy(socket);
  }

  btc_list_init(&loop->closed);

  loop->index = 0;
  loop->length = 0;
}
#else /* BTC_USE_SELECT */
void
btc_loop_start(btc__loop_t *loop) {
  btc__socket_t *socket;
  struct timeval tv, to;
  long long prev, diff;
  int fd, count;

  memset(&tv, 0, sizeof(tv));

  tv.tv_usec = BTC_TICK_RATE * 1000;

  loop->running = 1;

  while (loop->running) {
    memcpy(&loop->rfdi, &loop->rfds, sizeof(loop->rfds));
    memcpy(&loop->wfdi, &loop->wfds, sizeof(loop->wfds));
    memcpy(&to, &tv, sizeof(tv));

    prev = time_msec();
    count = select(loop->nfds, &loop->rfdi, &loop->wfdi, NULL, &to);
    diff = time_msec() - prev;

    if (diff < 0)
      diff = 0;

    if (count == -1) {
      if (errno == EINTR)
        continue;

      abort();
    }

    if (count != 0) {
      for (fd = 0; fd < loop->nfds; fd++) {
        socket = loop->sockets[fd];

        if (socket == NULL)
          continue;

        if (FD_ISSET(fd, &loop->rfdi))
          handle_read(loop, socket);

        if (FD_ISSET(fd, &loop->wfdi))
          handle_write(loop, socket);
      }
    }

    handle_ticks(loop);
    handle_closed(loop);

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
#endif /* BTC_USE_SELECT */

void
btc_loop_stop(btc__loop_t *loop) {
  loop->running = 0;
}
