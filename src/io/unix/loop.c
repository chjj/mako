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
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <io/core.h>
#include <io/loop.h>

/*
 * Macros
 */

#define CHECK(x) do { if (!(x)) abort(); } while (0)
#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Constants
 */

#define BTC_TICK_RATE 40

enum btc_socket_state {
  BTC_SOCKET_DISCONNECTED,
  BTC_SOCKET_CONNECTING,
  BTC_SOCKET_CONNECTED,
  BTC_SOCKET_DISCONNECTING,
  BTC_SOCKET_LISTENING,
  BTC_SOCKET_BOUND
};

enum btc_socket_flags {
  BTC_FLAG_READ = 1 << 0,
  BTC_FLAG_WRITE = 1 << 1
};

/*
 * Types
 */

typedef struct chunk_s {
  struct sockaddr *addr;
  socklen_t addrlen;
  void *ptr;
  unsigned char *raw;
  size_t len;
  struct chunk_s *next;
} chunk_t;

typedef struct btc_socket_s {
  struct btc_loop_s *loop;
  struct sockaddr_storage storage;
  struct sockaddr *addr;
  socklen_t addrlen;
  int fd;
  int state;
  unsigned int flags;
  size_t index;
  unsigned char buffer[65536];
  chunk_t *head;
  chunk_t *tail;
  size_t total;
  int draining;
  btc_socket_connect_cb *on_socket;
  btc_socket_connect_cb *on_connect;
  btc_socket_connect_cb *on_disconnect;
  btc_socket_error_cb *on_error;
  btc_socket_data_cb *on_data;
  btc_socket_drain_cb *on_drain;
  btc_socket_message_cb *on_message;
  void *data;
  void *arg;
  int error;
} btc__socket_t;

typedef struct btc_loop_s {
  struct pollfd pfds[128];
  btc__socket_t *sockets[128];
  size_t length;
  int error;
  int running;
  btc_loop_tick_cb *on_tick[8];
  size_t on_ticks;
  void *data[8];
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

/*
 * Socket Helpers
 */

static int
set_nonblocking(int fd) {
  return fcntl(fd, F_SETFL, O_NONBLOCK);
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

#ifdef FD_CLOEXEC
  if (fd != -1) {
    int rc = fcntl(fd, F_GETFD);

    if (rc != -1)
      fcntl(fd, F_SETFD, rc | FD_CLOEXEC);
  }
#endif

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

#ifdef FD_CLOEXEC
  if (fd != -1) {
    int rc = fcntl(fd, F_GETFD);

    if (rc != -1)
      fcntl(fd, F_SETFD, rc | FD_CLOEXEC);
  }
#endif

  return fd;
}

static int
safe_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int rc;

  do {
    rc = connect(sockfd, addr, addrlen);
  } while (rc == -1 && errno == EINTR);

  return rc;
}

/*
 * File Helpers
 */

static int
try_open(const char *name, int flags, unsigned int mode) {
  int fd;

#ifdef O_CLOEXEC
  if (flags & O_CREAT)
    fd = open(name, flags | O_CLOEXEC, mode);
  else
    fd = open(name, flags | O_CLOEXEC);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  if (flags & O_CREAT)
    fd = open(name, flags, mode);
  else
    fd = open(name, flags);

#ifdef FD_CLOEXEC
  if (fd != -1) {
    int rc = fcntl(fd, F_GETFD);

    if (rc != -1)
      fcntl(fd, F_SETFD, rc | FD_CLOEXEC);
  }
#endif

  return fd;
}

static int
safe_open(const char *name, int flags, unsigned int mode) {
  int fd;

  do {
    fd = try_open(name, flags, mode);
  } while (fd == -1 && errno == EINTR);

  return fd;
}

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
  socket->addrlen = 0;
  socket->fd = -1;
  socket->state = BTC_SOCKET_DISCONNECTED;
  socket->flags = 0;
  socket->index = 0;
  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;
  socket->draining = 0;
  socket->on_socket = NULL;
  socket->on_connect = NULL;
  socket->on_disconnect = NULL;
  socket->on_error = NULL;
  socket->on_data = NULL;
  socket->on_drain = NULL;
  socket->on_message = NULL;
  socket->data = NULL;
  socket->arg = NULL;
  socket->error = 0;

  return socket;
}

static void
btc_socket_destroy(btc__socket_t *socket) {
  chunk_t *chunk, *next;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    if (chunk->addr != NULL)
      free(chunk->addr);

    free(chunk->ptr);
    free(chunk);
  }

  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;
  socket->draining = 0;

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
btc_socket_on_socket(btc__socket_t *socket, btc_socket_connect_cb *handler) {
  socket->on_socket = handler;
}

void
btc_socket_on_connect(btc__socket_t *socket, btc_socket_connect_cb *handler) {
  socket->on_connect = handler;
}

void
btc_socket_on_disconnect(btc__socket_t *socket,
                         btc_socket_connect_cb *handler) {
  socket->on_disconnect = handler;
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
  if (addr->family != 4 && addr->family != 6)
    return 0;

  btc_sockaddr_get(socket->addr, addr);

  socket->addrlen = btc_sockaddr_size(addr);

  return 1;
}

static int
btc_socket_listen(btc__socket_t *server, const btc_sockaddr_t *addr, int max) {
  int option = 1;
  int fd;

  if (!btc_socket_setaddr(server, addr)) {
    server->loop->error = EAFNOSUPPORT;
    return 0;
  }

  fd = safe_socket(server->addr->sa_family, SOCK_STREAM, 0);

  if (fd == -1) {
    server->loop->error = errno;
    return 0;
  }

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

  if (bind(fd, server->addr, server->addrlen) == -1) {
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
  server->flags = BTC_FLAG_READ | BTC_FLAG_WRITE;

  return 1;
}

static int
btc_socket_accept(btc__socket_t *socket, btc__socket_t *server) {
  int fd;

  memset(&socket->storage, 0, sizeof(socket->storage));

  socket->addrlen = sizeof(socket->storage);

  fd = safe_accept(server->fd, socket->addr, &socket->addrlen);

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
  socket->flags = BTC_FLAG_READ | BTC_FLAG_WRITE;

  return 1;
}

static int
btc_socket_connect(btc__socket_t *socket, const btc_sockaddr_t *addr) {
  int fd;

  if (!btc_socket_setaddr(socket, addr)) {
    socket->loop->error = EAFNOSUPPORT;
    return 0;
  }

  fd = safe_socket(socket->addr->sa_family, SOCK_STREAM, 0);

  if (fd == -1) {
    socket->loop->error = errno;
    return 0;
  }

  if (set_nonblocking(fd) == -1) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  CHECK(safe_connect(fd, socket->addr, socket->addrlen) == -1);
  CHECK(errno != EISCONN);

  if (errno != EINPROGRESS && errno != EALREADY) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTING;
  socket->flags = BTC_FLAG_READ | BTC_FLAG_WRITE;

  return 1;
}

static int
btc_socket_bind(btc__socket_t *socket, const btc_sockaddr_t *addr) {
  int fd;

  if (!btc_socket_setaddr(socket, addr)) {
    socket->loop->error = EAFNOSUPPORT;
    return 0;
  }

  fd = safe_socket(socket->addr->sa_family, SOCK_DGRAM, 0);

  if (fd == -1) {
    socket->loop->error = errno;
    return 0;
  }

  if (bind(fd, socket->addr, socket->addrlen) == -1) {
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
  socket->flags = BTC_FLAG_READ | BTC_FLAG_WRITE;

  return 1;
}

static int
btc_socket_talk(btc__socket_t *socket, int family) {
  int fd;

  if (family != 4 && family != 6) {
    socket->loop->error = EAFNOSUPPORT;
    return 0;
  }

  fd = safe_socket(family == 4 ? PF_INET : PF_INET6, SOCK_DGRAM, 0);

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
  socket->flags = BTC_FLAG_READ | BTC_FLAG_WRITE;

  return 1;
}

static int
btc_socket_open(btc__socket_t *socket,
                const char *name,
                int flags,
                unsigned int mode) {
  int fd = safe_open(name, flags, mode);

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

  if (flags & O_RDWR)
    socket->flags = BTC_FLAG_READ | BTC_FLAG_WRITE;
  else if (flags & O_WRONLY)
    socket->flags = BTC_FLAG_WRITE;
  else
    socket->flags = BTC_FLAG_READ;

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
    socket->on_drain(socket);
  }

  return 1;
}

int
btc_socket_write(btc__socket_t *socket, unsigned char *raw, size_t len) {
  chunk_t *chunk;

  if (socket->state != BTC_SOCKET_CONNECTING
      && socket->state != BTC_SOCKET_CONNECTED) {
    socket->loop->error = EPIPE;
    return -1;
  }

  chunk = (chunk_t *)safe_malloc(sizeof(chunk_t));

  chunk->addr = NULL;
  chunk->addrlen = 0;
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
  int len;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    CHECK(chunk->len <= INT_MAX);

    socket->loop->error = 0;

    for (;;) {
      len = sendto(socket->fd,
                   chunk->raw,
                   chunk->len,
                   0,
                   chunk->addr,
                   chunk->addrlen);

      if (len == -1) {
        if (errno == EINTR)
          continue;

        if (errno == EAGAIN)
          return 0;

        if (errno == EWOULDBLOCK)
          return 0;

        socket->loop->error = errno;
      }

      break;
    }

    socket->total -= chunk->len;

    free(chunk->addr);
    free(chunk->ptr);
    free(chunk);

    socket->head = next;

    if (socket->head == NULL)
      socket->tail = NULL;

    if (socket->loop->error != 0)
      return -1;
  }

  CHECK(socket->total == 0);

  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;

  return 1;
}

int
btc_socket_send(btc__socket_t *socket,
                unsigned char *raw,
                size_t len,
                const btc_sockaddr_t *addr) {
  chunk_t *chunk;

  if (socket->state != BTC_SOCKET_BOUND) {
    socket->loop->error = EPIPE;
    return -1;
  }

  chunk = (chunk_t *)safe_malloc(sizeof(chunk_t));

  chunk->addr = (struct sockaddr *)safe_malloc(sizeof(struct sockaddr_storage));
  chunk->addrlen = btc_sockaddr_size(addr);
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

void
btc_socket_close(btc__socket_t *socket) {
  chunk_t *chunk, *next;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    if (chunk->addr != NULL)
      free(chunk->addr);

    free(chunk->ptr);
    free(chunk);
  }

  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;
  socket->draining = 0;

  socket->state = BTC_SOCKET_DISCONNECTING;
}

void
btc_socket_kill(btc__socket_t *socket) {
  btc_socket_close(socket);

  if (socket->fd != -1)
    close(socket->fd);

  socket->fd = -1;
  socket->state = BTC_SOCKET_DISCONNECTED;
}

/*
 * Loop
 */

btc__loop_t *
btc_loop_create(void) {
  btc__loop_t *loop = (btc__loop_t *)safe_malloc(sizeof(btc__loop_t));

  memset(loop, 0, sizeof(*loop));

  loop->length = 0;
  loop->error = 0;
  loop->running = 0;
  loop->on_ticks = 0;

  return loop;
}

void
btc_loop_destroy(btc__loop_t *loop) {
  CHECK(loop->running == 0);

  free(loop);
}

void
btc_loop_on_tick(btc__loop_t *loop, btc_loop_tick_cb *handler) {
  CHECK(loop->on_ticks < lengthof(loop->on_tick));
  loop->on_tick[loop->on_ticks++] = handler;
}

void
btc_loop_set_data(btc__loop_t *loop, int name, void *data) {
  CHECK((size_t)name < lengthof(loop->data));
  loop->data[name] = data;
}

void *
btc_loop_get_data(btc__loop_t *loop, int name) {
  CHECK((size_t)name < lengthof(loop->data));
  return loop->data[name];
}

const char *
btc_loop_strerror(btc__loop_t *loop) {
  return strerror(loop->error);
}

static void
btc_loop_register(btc__loop_t *loop, btc__socket_t *socket) {
  struct pollfd *pfd = &loop->pfds[loop->length];

  CHECK(loop->length < lengthof(loop->sockets));

  pfd->fd = socket->fd;
  pfd->events = POLLIN | POLLOUT;
  pfd->revents = 0;

  socket->index = loop->length;

  loop->sockets[loop->length] = socket;
  loop->length++;
}

static void
btc_loop_unregister(btc__loop_t *loop, btc__socket_t *socket) {
  loop->pfds[socket->index] = loop->pfds[loop->length - 1];
  loop->sockets[socket->index] = loop->sockets[loop->length - 1];
  loop->sockets[socket->index]->index = socket->index;
  loop->length--;
}

btc__socket_t *
btc_loop_listen(btc__loop_t *loop, const btc_sockaddr_t *addr, int max) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_listen(socket, addr, max)) {
    btc_socket_destroy(socket);
    return NULL;
  }

  btc_loop_register(loop, socket);

  return socket;
}

btc__socket_t *
btc_loop_connect(btc__loop_t *loop, const btc_sockaddr_t *addr) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_connect(socket, addr)) {
    btc_socket_destroy(socket);
    return NULL;
  }

  btc_loop_register(loop, socket);

  return socket;
}

btc__socket_t *
btc_loop_bind(btc__loop_t *loop, const btc_sockaddr_t *addr) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_bind(socket, addr)) {
    btc_socket_destroy(socket);
    return NULL;
  }

  btc_loop_register(loop, socket);

  return socket;
}

btc__socket_t *
btc_loop_talk(btc__loop_t *loop, int family) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_talk(socket, family)) {
    btc_socket_destroy(socket);
    return NULL;
  }

  btc_loop_register(loop, socket);

  return socket;
}

static btc__socket_t *
btc_loop_open(btc__loop_t *loop,
              const char *name,
              int flags,
              unsigned int mode) {
  btc__socket_t *socket = btc_socket_create(loop);

  if (!btc_socket_open(socket, name, flags, mode)) {
    btc_socket_destroy(socket);
    return NULL;
  }

  btc_loop_register(loop, socket);

  return socket;
}

static void
write_on_error(btc__socket_t *socket) {
  socket->error = socket->loop->error;
  btc_socket_kill(socket);
}

static void
write_on_drain(btc__socket_t *socket) {
  socket->error = 0;
  btc_socket_kill(socket);
}

static void
write_on_disconnect(btc__socket_t *socket) {
  btc_loop_write_file_cb *callback = (btc_loop_write_file_cb *)socket->data;

  if (socket->error != 0)
    callback(strerror(socket->error), socket->arg);
  else
    callback(NULL, socket->arg);
}

void
btc_loop_write(btc__loop_t *loop,
               const char *name,
               unsigned int mode,
               const void *data,
               size_t size,
               btc_loop_write_file_cb *callback,
               void *arg) {
  /* Write a file asynchronously. This really does
     not belong here, but it's hard to replicate
     btc_loop_open on windows. Life is suffering. */
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  btc__socket_t *socket = btc_loop_open(loop, name, flags, mode);
  int rc;

  if (socket == NULL) {
    callback(btc_loop_strerror(loop), arg);
    return;
  }

  socket->on_disconnect = write_on_disconnect;
  socket->on_error = write_on_error;
  socket->on_drain = write_on_drain;
  socket->data = (void *)callback;
  socket->arg = arg;

  rc = btc_socket_write(socket, (unsigned char *)data, size);

  if (rc == -1) {
    /* Error callback is not automatically
       called by btc_socket_write. Maybe
       change this in the future? */
    write_on_error(socket);
    return;
  }

  if (rc == 0) {
    /* Wait for drain. */
    return;
  }

  btc_socket_kill(socket);
}

static void
handle_read(btc__loop_t *loop, btc__socket_t *socket) {
  switch (socket->state) {
    case BTC_SOCKET_LISTENING: {
      btc__socket_t *child = btc_socket_create(loop);

      if (!btc_socket_accept(child, socket)) {
        btc_socket_destroy(child);
        break;
      }

      btc_loop_register(loop, child);

      socket->on_socket(child);

      break;
    }

    case BTC_SOCKET_CONNECTED: {
      unsigned char *buf = socket->buffer;
      size_t size = sizeof(socket->buffer);
      int fd = socket->fd;
      int len;

      if (!(socket->flags & BTC_FLAG_READ))
        break;

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

        if (len == 0) {
          socket->loop->error = ENODATA;
          socket->on_error(socket);
          break;
        }

        if ((size_t)len > size)
          abort();

        socket->on_data(socket, buf, len);
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

      if (!(socket->flags & BTC_FLAG_READ))
        break;

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
      if (safe_connect(socket->fd, socket->addr, socket->addrlen) == -1) {
        if (errno != EISCONN) {
          if (errno == EINPROGRESS || errno == EALREADY)
            break;

          socket->state = BTC_SOCKET_DISCONNECTING;
          socket->loop->error = errno;
          socket->on_error(socket);

          break;
        }
      }

      socket->state = BTC_SOCKET_CONNECTED;
      socket->on_connect(socket);

      break;
    }

    case BTC_SOCKET_CONNECTED: {
      if (!(socket->flags & BTC_FLAG_WRITE))
        break;

      if (btc_socket_flush_write(socket) == -1)
        socket->on_error(socket);

      break;
    }

    case BTC_SOCKET_BOUND: {
      if (!(socket->flags & BTC_FLAG_WRITE))
        break;

      if (btc_socket_flush_send(socket) == -1)
        socket->on_error(socket);

      break;
    }
  }
}

void
btc_loop_start(btc__loop_t *loop) {
  btc__socket_t *socket;
  long long prev, diff;
  struct pollfd *pfd;
  int count;
  size_t i;

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
      for (i = 0; i < loop->length; i++) {
        socket = loop->sockets[i];
        pfd = &loop->pfds[i];

        if (pfd->revents & POLLNVAL) {
          btc_socket_kill(socket);
          continue;
        }

        if (pfd->revents & (POLLIN | POLLERR | POLLHUP))
          handle_read(loop, socket);

        if (pfd->revents & (POLLOUT | POLLERR | POLLHUP))
          handle_write(loop, socket);

        pfd->revents = 0;
      }
    }

    for (i = 0; i < loop->on_ticks; i++)
      loop->on_tick[i](loop);

    for (i = 0; i < loop->length; i++) {
      socket = loop->sockets[i];

      if (socket->state == BTC_SOCKET_DISCONNECTING) {
        close(socket->fd);
        socket->fd = -1;
        socket->state = BTC_SOCKET_DISCONNECTED;
      }

      if (socket->state == BTC_SOCKET_DISCONNECTED) {
        btc_loop_unregister(loop, socket);
        socket->on_disconnect(socket);
        btc_socket_destroy(socket);
        i -= 1;
      }
    }

    time_sleep(BTC_TICK_RATE - diff);
  }

  for (i = 0; i < loop->length; i++) {
    socket = loop->sockets[i];

    close(socket->fd);

    socket->fd = -1;
    socket->state = BTC_SOCKET_DISCONNECTED;

    socket->on_disconnect(socket);

    btc_socket_destroy(socket);
  }

  loop->length = 0;
}

void
btc_loop_stop(btc__loop_t *loop) {
  loop->running = 0;
}
