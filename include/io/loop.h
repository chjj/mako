/*!
 * loop.h - event loop for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_LOOP_H
#define BTC_LOOP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "../satoshi/common.h"

/*
 * Types
 */

typedef struct btc_loop_s btc_loop_t;
typedef struct btc_socket_s btc_socket_t;

struct btc_sockaddr_s;

typedef void btc_loop_tick_cb(btc_loop_t *);
typedef void btc_socket_connect_cb(btc_socket_t *);
typedef void btc_socket_error_cb(btc_socket_t *);
typedef void btc_socket_data_cb(btc_socket_t *, const unsigned char *, size_t);
typedef void btc_socket_drain_cb(btc_socket_t *);
typedef void btc_socket_message_cb(btc_socket_t *,
                                   const unsigned char *,
                                   size_t,
                                   const struct btc_sockaddr_s *);

/*
 * Socket
 */

BTC_EXTERN void
btc_socket_destroy(btc_socket_t *socket);

BTC_EXTERN btc_loop_t *
btc_socket_loop(btc_socket_t *socket);

BTC_EXTERN void
btc_socket_address(struct btc_sockaddr_s *addr, btc_socket_t *socket);

BTC_EXTERN void
btc_socket_on_socket(btc_socket_t *socket, btc_socket_connect_cb *handler);

BTC_EXTERN void
btc_socket_on_connect(btc_socket_t *socket, btc_socket_connect_cb *handler);

BTC_EXTERN void
btc_socket_on_disconnect(btc_socket_t *socket, btc_socket_connect_cb *handler);

BTC_EXTERN void
btc_socket_on_error(btc_socket_t *socket, btc_socket_error_cb *handler);

BTC_EXTERN void
btc_socket_on_data(btc_socket_t *socket, btc_socket_data_cb *handler);

BTC_EXTERN void
btc_socket_on_drain(btc_socket_t *socket, btc_socket_drain_cb *handler);

BTC_EXTERN void
btc_socket_on_message(btc_socket_t *socket, btc_socket_message_cb *handler);

BTC_EXTERN void
btc_socket_complete(btc_socket_t *socket);

BTC_EXTERN void
btc_socket_set_data(btc_socket_t *socket, void *data);

BTC_EXTERN void *
btc_socket_get_data(btc_socket_t *socket);

BTC_EXTERN const char *
btc_socket_strerror(btc_socket_t *socket);

BTC_EXTERN size_t
btc_socket_buffered(btc_socket_t *socket);

BTC_EXTERN int
btc_socket_write(btc_socket_t *socket, void *data, size_t len);

BTC_EXTERN int
btc_socket_send(btc_socket_t *socket,
                void *data,
                size_t len,
                const struct btc_sockaddr_s *addr);

BTC_EXTERN void
btc_socket_close(btc_socket_t *socket);

/*
 * Loop
 */

BTC_EXTERN btc_loop_t *
btc_loop_create(void);

BTC_EXTERN void
btc_loop_destroy(btc_loop_t *loop);

BTC_EXTERN void
btc_loop_on_tick(btc_loop_t *loop, btc_loop_tick_cb *handler);

BTC_EXTERN void
btc_loop_set_data(btc_loop_t *loop, int name, void *data);

BTC_EXTERN void *
btc_loop_get_data(btc_loop_t *loop, int name);

BTC_EXTERN const char *
btc_loop_strerror(btc_loop_t *loop);

BTC_EXTERN btc_socket_t *
btc_loop_listen(btc_loop_t *loop, const struct btc_sockaddr_s *addr, int max);

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

#ifdef __cplusplus
}
#endif

#endif /* BTC_LOOP_H */
