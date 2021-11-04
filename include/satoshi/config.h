/*!
 * config.h - config for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_CONFIG_H
#define BTC_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "common.h"
#include "types.h"

/*
 * Types
 */

struct btc_conf_s {
  const btc_network_t *network;
  char prefix[768];
  char config[1024];
  int daemon;
  int network_active;
  int disable_wallet;
  int checkpoints;
  int prune;
  int workers;
  int listen;
  unsigned short port;
  btc_netaddr_t bind;
  btc_netaddr_t external;
  int no_connect;
  btc_netaddr_t connect;
  btc_netaddr_t proxy;
  int max_outbound;
  int max_inbound;
  int ban_time;
  int discover;
  int upnp;
  int onion;
  int blocks_only;
  int bip37;
  int bip152;
  int bip157;
  enum btc_ipnet only_net;
  unsigned short rpc_port;
  btc_netaddr_t rpc_bind;
  char rpc_connect[64];
  char rpc_user[64];
  char rpc_pass[64];
  int version;
  int help;
  const char *method;
  const char *params[8];
  size_t length;
};

/*
 * Config
 */

BTC_EXTERN btc_conf_t *
btc_conf_create(void);

BTC_EXTERN void
btc_conf_destroy(btc_conf_t *conf);

BTC_EXTERN void
btc_conf_init(btc_conf_t *conf,
              const btc_network_t *network,
              const char *prefix);

BTC_EXTERN int
btc_conf_parse(btc_conf_t *args,
               char **argv,
               size_t argc,
               const char *prefix,
               int allow_params);

BTC_EXTERN int
btc_conf_read(btc_conf_t *conf, const char *file);

BTC_EXTERN void
btc_conf_merge(btc_conf_t *args, const btc_conf_t *conf);

BTC_EXTERN void
btc_conf_finalize(btc_conf_t *args, const char *prefix);

#ifdef __cplusplus
}
#endif

#endif /* BTC_CONFIG_H */
