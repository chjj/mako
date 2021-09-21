/*!
 * loop.h - event loop for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_LOOP_H
#define BTC_LOOP_H

#include <stddef.h>

/*
 * Types
 */

typedef struct btc_loop_s btc_loop_t;
typedef struct btc_socket_s btc_socket_t;

typedef void btc_tick_cb(btc_loop_t *);
typedef void btc_connect_cb(btc_socket_t *);
typedef void btc_error_cb(btc_socket_t *, int);
typedef void btc_data_cb(btc_socket_t *, const unsigned char *, size_t);
typedef void btc_drain_cb(btc_socket_t *);

struct btc_netaddr_s;

/*
 * Socket
 */

btc_loop_t *
btc_socket_loop(btc_socket_t *socket);

void
btc_socket_address(struct btc_netaddr_s *addr, btc_socket_t *socket);

void
btc_socket_on_socket(btc_socket_t *socket, btc_connect_cb *handler);

void
btc_socket_on_connect(btc_socket_t *socket, btc_connect_cb *handler);

void
btc_socket_on_disconnect(btc_socket_t *socket, btc_connect_cb *handler);

void
btc_socket_on_error(btc_socket_t *socket, btc_error_cb *handler);

void
btc_socket_on_data(btc_socket_t *socket, btc_data_cb *handler);

void
btc_socket_on_drain(btc_socket_t *socket, btc_drain_cb *handler);

void
btc_socket_set_data(btc_socket_t *socket, void *data);

void *
btc_socket_get_data(btc_socket_t *socket);

size_t
btc_socket_buffered(btc_socket_t *socket);

int
btc_socket_write(btc_socket_t *socket, unsigned char *raw, size_t len);

void
btc_socket_close(btc_socket_t *socket);

void
btc_socket_kill(btc_socket_t *socket);

/*
 * Loop
 */

btc_loop_t *
btc_loop_create(void);

void
btc_loop_destroy(btc_loop_t *loop);

void
btc_loop_on_tick(btc_loop_t *loop, btc_tick_cb *handler);

void
btc_loop_set_data(btc_loop_t *loop, int name, void *data);

void *
btc_loop_get_data(btc_loop_t *loop, int name);

btc_socket_t *
btc_loop_listen(btc_loop_t *loop, const struct btc_netaddr_s *addr, int max);

btc_socket_t *
btc_loop_connect(btc_loop_t *loop, const struct btc_netaddr_s *addr);

void
btc_loop_start(btc_loop_t *loop);

void
btc_loop_stop(btc_loop_t *loop);

#endif /* BTC_LOOP_H */
