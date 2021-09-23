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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <io/core.h>
#include <io/loop.h>
#include "../../internal.h" /* XXX */

/*
 * Constants
 */

enum btc_socket_state {
  BTC_SOCKET_DISCONNECTED,
  BTC_SOCKET_CONNECTING,
  BTC_SOCKET_CONNECTED,
  BTC_SOCKET_DISCONNECTING,
  BTC_SOCKET_LISTENING
};

/*
 * Types
 */

typedef struct chunk_s {
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
  unsigned char buffer[65536];
  chunk_t *head;
  chunk_t *tail;
  size_t total;
  int draining;
  int state;
  int fd;
  size_t index;
  btc_socket_connect_cb *on_socket;
  btc_socket_connect_cb *on_connect;
  btc_socket_connect_cb *on_disconnect;
  btc_socket_error_cb *on_error;
  btc_socket_data_cb *on_data;
  btc_socket_drain_cb *on_drain;
  void *data;
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

static int
try_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int fd;

#if defined(__GLIBC__) && defined(_GNU_SOURCE) && defined(SOCK_CLOEXEC)
  fd = accept4(sockfd, addr, addrlen, SOCK_CLOEXEC | SOCK_NONBLOCK);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = accept(sockfd, addr, addrlen);

  if (fd == -1)
    return -1;

#ifdef FD_CLOEXEC
  {
    int rc = fcntl(fd, F_GETFD);

    if (rc != -1)
      fcntl(fd, F_SETFD, rc | FD_CLOEXEC);
  }
#endif

  if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
    close(fd);
    return -1;
  }

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

  if (fd == -1)
    return -1;

#ifdef FD_CLOEXEC
  {
    int rc = fcntl(fd, F_GETFD);

    if (rc != -1)
      fcntl(fd, F_SETFD, rc | FD_CLOEXEC);
  }
#endif

  if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
    close(fd);
    return -1;
  }

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
 * Socket
 */

static btc__socket_t *
btc_socket_create(btc__loop_t *loop) {
  btc__socket_t *socket = (btc__socket_t *)btc_malloc(sizeof(btc__socket_t));

  memset(socket, 0, sizeof(*socket));

  socket->loop = loop;
  socket->addr = (struct sockaddr *)&socket->storage;
  socket->addrlen = 0;
  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;
  socket->draining = 0;
  socket->state = BTC_SOCKET_DISCONNECTED;
  socket->fd = -1;
  socket->index = 0;
  socket->on_socket = NULL;
  socket->on_connect = NULL;
  socket->on_disconnect = NULL;
  socket->on_error = NULL;
  socket->on_data = NULL;
  socket->on_drain = NULL;
  socket->data = NULL;

  return socket;
}

static void
btc_socket_destroy(btc__socket_t *socket) {
  chunk_t *chunk, *next;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    btc_free(chunk->ptr);
    btc_free(chunk);
  }

  socket->head = NULL;
  socket->tail = NULL;
  socket->total = 0;
  socket->draining = 0;

  btc_free(socket);
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
  btc_sockaddr_get(socket->addr, addr);

  if (socket->addr->sa_family == PF_INET) {
    socket->addrlen = sizeof(struct sockaddr_in);
    return 1;
  }

  if (socket->addr->sa_family == PF_INET6) {
    socket->addrlen = sizeof(struct sockaddr_in6);
    return 1;
  }

  return 0;
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

  server->fd = fd;
  server->state = BTC_SOCKET_LISTENING;

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

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTED;

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

  CHECK(safe_connect(fd, socket->addr, socket->addrlen) == -1);
  CHECK(errno != EISCONN);

  if (errno != EINPROGRESS && errno != EALREADY) {
    socket->loop->error = errno;
    close(fd);
    return 0;
  }

  socket->fd = fd;
  socket->state = BTC_SOCKET_CONNECTING;

  return 1;
}

static int
btc_socket_flush(btc__socket_t *socket) {
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

    btc_free(chunk->ptr);
    btc_free(chunk);

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

  chunk = (chunk_t *)btc_malloc(sizeof(chunk_t));

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

  return btc_socket_flush(socket);
}

void
btc_socket_close(btc__socket_t *socket) {
  chunk_t *chunk, *next;

  for (chunk = socket->head; chunk != NULL; chunk = next) {
    next = chunk->next;

    btc_free(chunk->ptr);
    btc_free(chunk);
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
  btc__loop_t *loop = (btc__loop_t *)btc_malloc(sizeof(btc__loop_t));

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

  btc_free(loop);
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
      if (btc_socket_flush(socket) == -1)
        socket->on_error(socket);
      break;
    }
  }
}

void
btc_loop_start(btc__loop_t *loop) {
  btc__socket_t *socket;
  struct pollfd *pfd;
  size_t i;
  int c;

  loop->running = 1;

  while (loop->running) {
    c = poll(loop->pfds, loop->length, 1000);

    if (c == -1) {
      if (errno == EINTR)
        continue;

      abort();
    }

    if (c != 0) {
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
