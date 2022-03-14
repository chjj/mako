/*!
 * loop.h - event loop for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_LOOP_H
#define BTC_LOOP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "../mako/common.h"

/*
 * Types
 */

typedef struct btc_loop_s btc_loop_t;
typedef struct btc_socket_s btc_socket_t;
typedef struct btc_server_s btc_server_t;

struct btc_sockaddr_s;

typedef void btc_loop_tick_cb(void *arg);
typedef void btc_socket_socket_cb(btc_socket_t *, btc_socket_t *);
typedef void btc_socket_connect_cb(btc_socket_t *);
typedef void btc_socket_close_cb(btc_socket_t *);
typedef void btc_socket_error_cb(btc_socket_t *);
typedef  int btc_socket_data_cb(btc_socket_t *, const void *, size_t);
typedef void btc_socket_drain_cb(btc_socket_t *);
typedef void btc_socket_message_cb(btc_socket_t *,
                                   const void *,
                                   size_t,
                                   const struct btc_sockaddr_s *);

/*
 * Socket
 */

BTC_EXTERN btc_loop_t *
btc_socket_loop(btc_socket_t *socket);

BTC_EXTERN void
btc_socket_address(struct btc_sockaddr_s *addr, btc_socket_t *socket);

BTC_EXTERN void
btc_socket_on_socket(btc_socket_t *socket, btc_socket_socket_cb *handler);

BTC_EXTERN void
btc_socket_on_connect(btc_socket_t *socket, btc_socket_connect_cb *handler);

BTC_EXTERN void
btc_socket_on_close(btc_socket_t *socket, btc_socket_close_cb *handler);

BTC_EXTERN void
btc_socket_on_error(btc_socket_t *socket, btc_socket_error_cb *handler);

BTC_EXTERN void
btc_socket_on_data(btc_socket_t *socket, btc_socket_data_cb *handler);

BTC_EXTERN void
btc_socket_on_drain(btc_socket_t *socket, btc_socket_drain_cb *handler);

BTC_EXTERN void
btc_socket_on_message(btc_socket_t *socket, btc_socket_message_cb *handler);

BTC_EXTERN void
btc_socket_set_data(btc_socket_t *socket, void *data);

BTC_EXTERN void *
btc_socket_get_data(btc_socket_t *socket);

BTC_EXTERN const char *
btc_socket_strerror(btc_socket_t *socket);

BTC_EXTERN size_t
btc_socket_buffered(btc_socket_t *socket);

BTC_EXTERN void
btc_socket_set_nodelay(btc_socket_t *socket, int value);

BTC_EXTERN int
btc_socket_write(btc_socket_t *socket, void *data, size_t len);

BTC_EXTERN int
btc_socket_send(btc_socket_t *socket,
                void *data,
                size_t len,
                const struct btc_sockaddr_s *addr);

BTC_EXTERN void
btc_socket_close(btc_socket_t *socket);

BTC_EXTERN void
btc_socket_timeout(btc_socket_t *socket);

/*
 * Loop
 */

BTC_EXTERN btc_loop_t *
btc_loop_create(void);

BTC_EXTERN void
btc_loop_destroy(btc_loop_t *loop);

BTC_EXTERN void
btc_loop_on_tick(btc_loop_t *loop, btc_loop_tick_cb *handler, void *data);

BTC_EXTERN void
btc_loop_off_tick(btc_loop_t *loop, btc_loop_tick_cb *handler, void *data);

BTC_EXTERN const char *
btc_loop_strerror(btc_loop_t *loop);

BTC_EXTERN btc_socket_t *
btc_loop_listen(btc_loop_t *loop, const struct btc_sockaddr_s *addr);

BTC_EXTERN btc_socket_t *
btc_loop_connect(btc_loop_t *loop, const struct btc_sockaddr_s *addr);

BTC_EXTERN btc_socket_t *
btc_loop_bind(btc_loop_t *loop, const struct btc_sockaddr_s *addr);

BTC_EXTERN btc_socket_t *
btc_loop_talk(btc_loop_t *loop, int family);

BTC_EXTERN void
btc_loop_start(btc_loop_t *loop);

BTC_EXTERN void
btc_loop_stop(btc_loop_t *loop);

BTC_EXTERN void
btc_loop_cleanup(btc_loop_t *loop);

BTC_EXTERN void
btc_loop_poll(btc_loop_t *loop, int timeout);

BTC_EXTERN void
btc_loop_close(btc_loop_t *loop);

BTC_EXTERN int
btc_loop_fd_setsize(void);

/*
 * Server
 */

BTC_EXTERN btc_server_t *
btc_server_create(btc_loop_t *loop);

BTC_EXTERN void
btc_server_destroy(btc_server_t *server);

BTC_EXTERN const char *
btc_server_strerror(btc_server_t *server);

BTC_EXTERN int
btc_server_listen(btc_server_t *server, const btc_sockaddr_t *addr);

BTC_EXTERN int
btc_server_listen_local(btc_server_t *server, int port);

BTC_EXTERN int
btc_server_listen_external(btc_server_t *server, int port);

BTC_EXTERN void
btc_server_close(btc_server_t *server);

BTC_EXTERN void
btc_server_on_socket(btc_server_t *server, btc_socket_socket_cb *handler);

BTC_EXTERN void
btc_server_set_data(btc_server_t *server, void *data);

BTC_EXTERN void
btc_server_set_nodelay(btc_server_t *server, int value);

#ifdef __cplusplus
}
#endif

#endif /* BTC_LOOP_H */
