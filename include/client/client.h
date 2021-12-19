/*!
 * client.h - rpc client for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_CLIENT_H
#define BTC_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../mako/common.h"

/*
 * Types
 */

typedef struct btc_client_s btc_client_t;

struct _json_value;

/*
 * Client
 */

BTC_EXTERN btc_client_t *
btc_client_create(void);

BTC_EXTERN void
btc_client_destroy(btc_client_t *client);

BTC_EXTERN int
btc_client_open(btc_client_t *client,
                const char *hostname,
                int port,
                int family);

BTC_EXTERN void
btc_client_close(btc_client_t *client);

BTC_EXTERN void
btc_client_auth(btc_client_t *client, const char *user, const char *pass);

BTC_EXTERN struct _json_value *
btc_client_call(btc_client_t *client,
                const char *method,
                struct _json_value *params);

#ifdef __cplusplus
}
#endif

#endif /* BTC_CLIENT_H */
