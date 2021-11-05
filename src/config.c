/*!
 * config.c - config for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <satoshi/config.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/network.h>
#include <satoshi/util.h>
#include "internal.h"

/*
 * Constants
 */

#define BTC_CONFIG_FILE "satoshi.conf"

/*
 * Macros
 */

#define btc_str_assign(zp, xp) do { \
  if (sizeof(xp) > sizeof(zp))      \
    abort(); /* LCOV_EXCL_LINE */   \
                                    \
  memcpy(zp, xp, sizeof(xp));       \
} while (0)

#define btc_str_set(zp, xp) do {  \
  size_t _xn = strlen(xp);        \
                                  \
  if (_xn + 1 > sizeof(zp))       \
    abort(); /* LCOV_EXCL_LINE */ \
                                  \
  memcpy(zp, xp, _xn + 1);        \
} while (0)

/*
 * Helpers
 */

static int
btc_die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  exit(EXIT_FAILURE);
  return 0;
}

static void
btc_join(char *zp, ...) {
  const char *xp;
  va_list ap;

  va_start(ap, zp);

  while ((xp = va_arg(ap, const char *))) {
    while (*xp)
      *zp++ = *xp++;

#if defined(_WIN32)
    *zp++ = '\\';
#else
    *zp++ = '/';
#endif
  }

  *--zp = '\0';

  va_end(ap);
}

static int
btc_getline(char **zp, size_t *zn, FILE *stream) {
  char *xp = *zp;
  int xn = *zn;
  int saw = 0;
  int i = 0;
  int ch;

  if (xn == 0) {
    xn = 64;
    xp = btc_malloc(xn + 1);
  }

  for (;;) {
    ch = getc(stream);

    if (ch == '\r')
      continue;

    if (ch == '#') {
      for (;;) {
        ch = getc(stream);

        if (ch == '\n' || ch == EOF)
          break;
      }
    }

    if (ch == '\n') {
      if (i == 0)
        continue;

      break;
    }

    if (ch == EOF) {
      if (i == 0) {
        i = -1;
        goto done;
      }

      break;
    }

    if (!saw) {
      if (ch == ' ' || ch == '\t')
        continue;

      saw = 1;
    }

    if (i == xn) {
      xn = (xn * 3) / 2 + (xn <= 1);
      xp = btc_realloc(xp, xn + 1);
    }

    xp[i++] = ch;
  }

  while (i > 0 && (xp[i - 1] == ' ' || xp[i - 1] == '\t'))
    i -= 1;

  xp[i] = '\0';

done:
  *zp = xp;
  *zn = xn;

  return i;
}

/*
 * Matchers
 */

static int
btc_match(const char **zp, const char *xp, const char *yp) {
  while (*xp && *xp == *yp) {
    xp++;
    yp++;
  }

  if (*yp)
    return 0;

  if (!*xp)
    return 0;

  *zp = xp;

  return 1;
}

static int
btc_match__str(char *zp, size_t zn, const char *xp, const char *yp) {
  const char *val;
  size_t len;

  if (!btc_match(&val, xp, yp))
    return 0;

  len = strlen(val);

  if (len + 1 > zn)
    return btc_die("Invalid value `%s`.", xp);

  memcpy(zp, val, len + 1);

  return 1;
}

#define btc_match_str(zp, xp, yp) btc_match__str(zp, sizeof(zp), xp, yp)

static int
btc_match__path(char *zp, size_t zn, const char *xp, const char *yp) {
  const char *val;
  size_t len;

  if (!btc_match(&val, xp, yp))
    return 0;

#ifndef _WIN32
  if (val[0] == '~' && val[1] == '/' && val[2] != '\0') {
    char *home = getenv("HOME");

    if (home == NULL)
      home = "/";

    if (strlen(home) + strlen(val) > zn)
      return btc_die("Invalid value `%s`.", xp);

    btc_join(zp, home, val + 2, 0);

    return 1;
  }
#endif

  len = strlen(val);

  if (len + 1 > zn)
    return btc_die("Invalid value `%s`.", xp);

  memcpy(zp, val, len + 1);

  return 1;
}

#define btc_match_path(zp, xp, yp) btc_match__path(zp, sizeof(zp), xp, yp)

static int
btc_match_bool(int *z, const char *xp, const char *yp) {
  /* Matches `option={0,1}` */
  const char *val;

  if (!btc_match(&val, xp, yp))
    return 0;

  if (val[0] != '0' && val[0] != '1')
    return 0;

  if (val[1] != '\0')
    return 0;

  *z = val[0] - '0';

  return 1;
}

static int
btc_match_argbool(int *z, const char *xp, const char *yp) {
  /* Matches `option={0,1}`, `option`, and `nooption`. */
  int negate = 0;

  if (btc_match_bool(z, xp, yp))
    return 1;

  if (xp[0] == '-' && xp[1] == 'n' && xp[2] == 'o') {
    negate = 1;
    xp += 3;
    yp += 1;
  }

  while (*xp && *xp == *yp) {
    xp++;
    yp++;
  }

  if (*yp != '=')
    return 0;

  if (*xp)
    return 0;

  *z = 1 ^ negate;

  return 1;
}

static int
btc_parse_int(int *z, const char *xp) {
  int neg = 0;
  int n = 0;
  int x = 0;

  if (*xp == '+') {
    xp++;
  } else if (*xp == '-') {
    neg = 1;
    xp++;
  }

  if (!*xp)
    return 0;

  while (*xp) {
    int ch = *xp;

    if (ch < '0' || ch > '9')
      return 0;

    if (++n > 9)
      return 0;

    x *= 10;
    x += (ch - '0');

    xp++;
  }

  if (neg)
    x = -x;

  *z = x;

  return 1;
}

static int
btc_match_int(int *z, const char *xp, const char *yp) {
  const char *val;

  if (!btc_match(&val, xp, yp))
    return 0;

  if (!btc_parse_int(z, val))
    return btc_die("Invalid value `%s`.", xp);

  return 1;
}

static int
btc_match_port(int *z, const char *xp, const char *yp) {
  if (!btc_match_int(z, xp, yp))
    return 0;

  if (*z < 0 || *z > 0xffff)
    return btc_die("Invalid value `%s`.", xp);

  return 1;
}

static int
btc_match_network(const btc_network_t **z, const char *xp, const char *yp) {
  const char *val;

  if (!btc_match(&val, xp, yp))
    return 0;

  if (strcmp(val, "mainnet") == 0 || strcmp(val, "main") == 0)
    *z = btc_mainnet;
  else if (strcmp(val, "testnet") == 0 || strcmp(val, "test") == 0)
    *z = btc_testnet;
  else if (strcmp(val, "regtest") == 0)
    *z = btc_regtest;
  else if (strcmp(val, "simnet") == 0)
    *z = btc_simnet;
  else
    return btc_die("Invalid value `%s`.", xp);

  return 1;
}

static int
btc_match_netaddr(btc_netaddr_t *z, const char *xp, const char *yp) {
  const char *val;

  if (!btc_match(&val, xp, yp))
    return 0;

  if (!btc_netaddr_set_str(z, val))
    return btc_die("Invalid value `%s`.", xp);

  return 1;
}

static int
btc_match_net(enum btc_ipnet *z, const char *xp, const char *yp) {
  const char *val;

  if (!btc_match(&val, xp, yp))
    return 0;

  if (strcmp(val, "ipv4") == 0)
    *z = BTC_IPNET_IPV4;
  else if (strcmp(val, "ipv6") == 0)
    *z = BTC_IPNET_IPV6;
  else if (strcmp(val, "onion") == 0)
    *z = BTC_IPNET_ONION;
  else
    return btc_die("Invalid value `%s`.", xp);

  return 1;
}

/*
 * Config
 */

btc_conf_t *
btc_conf_create(void) {
  btc_conf_t *conf = btc_malloc(sizeof(btc_conf_t));
  memset(conf, 0, sizeof(*conf));
  return conf;
}

void
btc_conf_destroy(btc_conf_t *conf) {
  btc_free(conf);
}

void
btc_conf_init(btc_conf_t *conf,
              const btc_network_t *network,
              const char *prefix) {
  memset(conf, 0, sizeof(*conf));

  if (network == NULL)
    network = btc_mainnet;

  conf->network = network;

  if (prefix != NULL) {
    if (network->type == BTC_NETWORK_MAINNET)
      btc_str_set(conf->prefix, prefix);
    else
      btc_join(conf->prefix, prefix, network->name, 0);

    btc_join(conf->config, conf->prefix, BTC_CONFIG_FILE, 0);
  }

  conf->daemon = 0;
  conf->network_active = 1;
  conf->disable_wallet = 0;

  conf->map_size = 16;
  conf->checkpoints = 1;
  conf->prune = 0;
  conf->workers = 0;

  conf->listen = 1;

  conf->port = network->port;

  btc_netaddr_set(&conf->bind, "0.0.0.0", network->port);
  btc_netaddr_set(&conf->external, "0.0.0.0", network->port);

  conf->external.time = btc_now();
  conf->external.services = BTC_NET_LOCAL_SERVICES;

  conf->no_connect = 0;

  btc_netaddr_set(&conf->connect, "0.0.0.0", network->port);

  conf->connect.time = btc_now();
  conf->connect.services = BTC_NET_DEFAULT_SERVICES;

  btc_netaddr_set(&conf->proxy, "0.0.0.0", 1080);

  conf->max_outbound = 8;
  conf->max_inbound = 8;
  conf->ban_time = 24 * 60 * 60;
  conf->discover = 1;
  conf->upnp = 0;
  conf->onion = 0;
  conf->blocks_only = 0;
  conf->bip37 = 0;
  conf->bip152 = 1;
  conf->bip157 = 0;
  conf->only_net = BTC_IPNET_NONE;

  conf->rpc_port = network->rpc_port;

  btc_netaddr_set(&conf->rpc_bind, "127.0.0.1", network->rpc_port);

  btc_str_assign(conf->rpc_connect, "127.0.0.1");

  btc_str_assign(conf->rpc_user, "bitcoinrpc");
  btc_str_assign(conf->rpc_pass, "");

  conf->version = 0;
  conf->help = 0;
  conf->method = NULL;
  /* conf->params */
  conf->length = 0;
}

static void
btc_conf_reset(btc_conf_t *conf) {
  memset(conf, 0, sizeof(*conf));

  conf->daemon = -1;
  conf->network_active = -1;
  conf->disable_wallet = -1;
  conf->map_size = -1;
  conf->checkpoints = -1;
  conf->prune = -1;
  conf->workers = INT_MIN;
  conf->listen = -1;
  conf->port = -1;
  conf->bind.port = -1;
  conf->external.port = -1;
  conf->no_connect = -1;
  conf->connect.port = -1;
  conf->proxy.port = -1;
  conf->max_outbound = -1;
  conf->max_inbound = -1;
  conf->ban_time = -1;
  conf->discover = -1;
  conf->upnp = -1;
  conf->onion = -1;
  conf->blocks_only = -1;
  conf->bip37 = -1;
  conf->bip152 = -1;
  conf->bip157 = -1;
  conf->only_net = BTC_IPNET_NONE;
  conf->rpc_port = -1;
  conf->rpc_bind.port = -1;
}

int
btc_conf_parse(btc_conf_t *args,
               char **argv,
               size_t argc,
               const char *prefix,
               int allow_params) {
  size_t i;

  btc_conf_reset(args);

  for (i = 1; i < argc; i++) {
    const char *arg = argv[i];

    if (btc_match_path(args->config, arg, "-conf="))
      continue;

    if (btc_match_path(args->prefix, arg, "-datadir="))
      continue;

    if (btc_match_network(&args->network, arg, "-chain="))
      continue;

    if (btc_match_argbool(&args->daemon, arg, "-daemon="))
      continue;

    if (btc_match_argbool(&args->network_active, arg, "-networkactive="))
      continue;

    if (btc_match_argbool(&args->disable_wallet, arg, "-disablewallet="))
      continue;

    if (btc_match_int(&args->map_size, arg, "-mapsize="))
      continue;

    if (btc_match_argbool(&args->checkpoints, arg, "-checkpoints="))
      continue;

    if (btc_match_argbool(&args->prune, arg, "-prune="))
      continue;

    if (btc_match_int(&args->workers, arg, "-par="))
      continue;

    if (btc_match_argbool(&args->listen, arg, "-listen="))
      continue;

    if (btc_match_port(&args->port, arg, "-port="))
      continue;

    if (btc_match_netaddr(&args->bind, arg, "-bind="))
      continue;

    if (btc_match_netaddr(&args->external, arg, "-externalip="))
      continue;

    if (btc_match_argbool(&args->no_connect, arg, "-connect=")) {
      args->no_connect ^= 1;
      continue;
    }

    if (btc_match_netaddr(&args->connect, arg, "-connect="))
      continue;

    if (btc_match_netaddr(&args->proxy, arg, "-proxy="))
      continue;

    if (btc_match_int(&args->max_outbound, arg, "-maxconnections="))
      continue;

    if (btc_match_int(&args->max_outbound, arg, "-maxoutbound="))
      continue;

    if (btc_match_int(&args->max_inbound, arg, "-maxinbound="))
      continue;

    if (btc_match_int(&args->ban_time, arg, "-bantime="))
      continue;

    if (btc_match_argbool(&args->discover, arg, "-discover="))
      continue;

    if (btc_match_argbool(&args->upnp, arg, "-upnp="))
      continue;

    if (btc_match_argbool(&args->onion, arg, "-onion="))
      continue;

    if (btc_match_netaddr(&args->proxy, arg, "-onion=")) {
      args->onion = 1;
      continue;
    }

    if (btc_match_argbool(&args->blocks_only, arg, "-blocksonly="))
      continue;

    if (btc_match_argbool(&args->bip37, arg, "-peerbloomfilters="))
      continue;

    if (btc_match_argbool(&args->bip152, arg, "-compactblocks="))
      continue;

    if (btc_match_argbool(&args->bip157, arg, "-peerblockfilters="))
      continue;

    if (btc_match_net(&args->only_net, arg, "-onlynet="))
      continue;

    if (btc_match_port(&args->rpc_port, arg, "-rpcport="))
      continue;

    if (btc_match_netaddr(&args->rpc_bind, arg, "-rpcbind="))
      continue;

    if (btc_match_str(args->rpc_connect, arg, "-rpcconnect="))
      continue;

    if (btc_match_str(args->rpc_user, arg, "-rpcuser="))
      continue;

    if (btc_match_str(args->rpc_pass, arg, "-rpcpassword="))
      continue;

    if (strcmp(arg, "-testnet") == 0) {
      args->network = btc_testnet;
      continue;
    }

    if (strcmp(arg, "-version") == 0) {
      args->version = 1;
      continue;
    }

    if (strcmp(arg, "-?") == 0) {
      args->help = 1;
      continue;
    }

    if (allow_params) {
      if (arg[0] == '-' && arg[1] >= 'a' && arg[1] <= 'z')
        return btc_die("Invalid option `%s`.", arg);

      if (args->method == NULL) {
        args->method = arg;
        continue;
      }

      if (args->length == lengthof(args->params))
        return btc_die("Too many parameters.");

      args->params[args->length++] = arg;

      continue;
    }

    return btc_die("Invalid option `%s`.", arg);
  }

  if (args->network == NULL)
    args->network = btc_mainnet;

  if (!*args->config && (*args->prefix || prefix != NULL)) {
    const char *dir = *args->prefix ? args->prefix : prefix;

    if (args->network->type == BTC_NETWORK_MAINNET)
      btc_join(args->config, dir, BTC_CONFIG_FILE, 0);
    else
      btc_join(args->config, dir, args->network->name, BTC_CONFIG_FILE, 0);
  }

  return 1;
}

int
btc_conf_read(btc_conf_t *conf, const char *file) {
  FILE *stream = fopen(file, "r");
  char *zp = NULL;
  size_t zn = 0;
  int len;

  btc_conf_reset(conf);

  if (stream == NULL)
    return 1;

  while ((len = btc_getline(&zp, &zn, stream)) != -1) {
    if (btc_match_path(conf->prefix, zp, "datadir="))
      continue;

    if (btc_match_bool(&conf->disable_wallet, zp, "disablewallet="))
      continue;

    if (btc_match_int(&conf->map_size, zp, "mapsize="))
      continue;

    if (btc_match_bool(&conf->checkpoints, zp, "checkpoints="))
      continue;

    if (btc_match_bool(&conf->prune, zp, "prune="))
      continue;

    if (btc_match_int(&conf->workers, zp, "par="))
      continue;

    if (btc_match_bool(&conf->listen, zp, "listen="))
      continue;

    if (btc_match_port(&conf->port, zp, "port="))
      continue;

    if (btc_match_netaddr(&conf->bind, zp, "bind="))
      continue;

    if (btc_match_netaddr(&conf->external, zp, "externalip="))
      continue;

    if (btc_match_bool(&conf->no_connect, zp, "connect=")) {
      conf->no_connect ^= 1;
      continue;
    }

    if (btc_match_netaddr(&conf->connect, zp, "connect="))
      continue;

    if (btc_match_netaddr(&conf->proxy, zp, "proxy="))
      continue;

    if (btc_match_int(&conf->max_outbound, zp, "maxconnections="))
      continue;

    if (btc_match_int(&conf->max_outbound, zp, "maxoutbound="))
      continue;

    if (btc_match_int(&conf->max_inbound, zp, "maxinbound="))
      continue;

    if (btc_match_int(&conf->ban_time, zp, "bantime="))
      continue;

    if (btc_match_bool(&conf->discover, zp, "discover="))
      continue;

    if (btc_match_bool(&conf->upnp, zp, "upnp="))
      continue;

    if (btc_match_bool(&conf->onion, zp, "onion="))
      continue;

    if (btc_match_netaddr(&conf->proxy, zp, "onion=")) {
      conf->onion = 1;
      continue;
    }

    if (btc_match_bool(&conf->blocks_only, zp, "blocksonly="))
      continue;

    if (btc_match_bool(&conf->bip37, zp, "peerbloomfilters="))
      continue;

    if (btc_match_bool(&conf->bip152, zp, "compactblocks="))
      continue;

    if (btc_match_bool(&conf->bip157, zp, "peerblockfilters="))
      continue;

    if (btc_match_net(&conf->only_net, zp, "onlynet="))
      continue;

    if (btc_match_port(&conf->rpc_port, zp, "rpcport="))
      continue;

    if (btc_match_netaddr(&conf->rpc_bind, zp, "rpcbind="))
      continue;

    if (btc_match_str(conf->rpc_connect, zp, "rpcconnect="))
      continue;

    if (btc_match_str(conf->rpc_user, zp, "rpcuser="))
      continue;

    if (btc_match_str(conf->rpc_pass, zp, "rpcpassword="))
      continue;

    btc_free(zp);

    fclose(stream);

    return btc_die("Invalid option `%s`.", zp);
  }

  if (conf->network == NULL)
    conf->network = btc_mainnet;

  btc_str_set(conf->config, file);

  btc_free(zp);

  fclose(stream);

  return 1;
}

void
btc_conf_merge(btc_conf_t *args, const btc_conf_t *conf) {
  if (!*args->prefix && *conf->prefix)
    btc_str_assign(args->prefix, conf->prefix);

  if (args->disable_wallet == -1 && conf->disable_wallet != -1)
    args->disable_wallet = conf->disable_wallet;

  if (args->map_size == -1 && conf->map_size != -1)
    args->map_size = conf->map_size;

  if (args->checkpoints == -1 && conf->checkpoints != -1)
    args->checkpoints = conf->checkpoints;

  if (args->prune == -1 && conf->prune != -1)
    args->prune = conf->prune;

  if (args->workers == INT_MIN && conf->workers != INT_MIN)
    args->workers = conf->workers;

  if (args->listen == -1 && conf->listen != -1)
    args->listen = conf->listen;

  if (args->port == -1 && conf->port != -1)
    args->port = conf->port;

  if (args->bind.port == -1 && conf->bind.port != -1)
    btc_netaddr_copy(&args->bind, &conf->bind);

  if (args->external.port == -1 && conf->external.port != -1)
    btc_netaddr_copy(&args->external, &conf->external);

  if (args->no_connect == -1 && conf->no_connect != -1)
    args->no_connect = conf->no_connect;

  if (args->connect.port == -1 && conf->connect.port != -1)
    btc_netaddr_copy(&args->connect, &conf->connect);

  if (args->proxy.port == -1 && conf->proxy.port != -1)
    btc_netaddr_copy(&args->proxy, &conf->proxy);

  if (args->max_outbound == -1 && conf->max_outbound != -1)
    args->max_outbound = conf->max_outbound;

  if (args->max_inbound == -1 && conf->max_inbound != -1)
    args->max_inbound = conf->max_inbound;

  if (args->ban_time == -1 && conf->ban_time != -1)
    args->ban_time = conf->ban_time;

  if (args->discover == -1 && conf->discover != -1)
    args->discover = conf->discover;

  if (args->upnp == -1 && conf->upnp != -1)
    args->upnp = conf->upnp;

  if (args->onion == -1 && conf->onion != -1)
    args->onion = conf->onion;

  if (args->blocks_only == -1 && conf->blocks_only != -1)
    args->blocks_only = conf->blocks_only;

  if (args->bip37 == -1 && conf->bip37 != -1)
    args->bip37 = conf->bip37;

  if (args->bip152 == -1 && conf->bip152 != -1)
    args->bip152 = conf->bip152;

  if (args->bip157 == -1 && conf->bip157 != -1)
    args->bip157 = conf->bip157;

  if (args->only_net == BTC_IPNET_NONE && conf->only_net != BTC_IPNET_NONE)
    args->only_net = conf->only_net;

  if (args->rpc_port == -1 && conf->rpc_port != -1)
    args->rpc_port = conf->rpc_port;

  if (args->rpc_bind.port == -1 && conf->rpc_bind.port != -1)
    btc_netaddr_copy(&args->rpc_bind, &conf->rpc_bind);

  if (!*args->rpc_connect && *conf->rpc_connect)
    btc_str_assign(args->rpc_connect, conf->rpc_connect);

  if (!*args->rpc_user && *conf->rpc_user)
    btc_str_assign(args->rpc_user, conf->rpc_user);

  if (!*args->rpc_pass && *conf->rpc_pass)
    btc_str_assign(args->rpc_pass, conf->rpc_pass);
}

void
btc_conf_finalize(btc_conf_t *args, const char *prefix) {
  const btc_network_t *network = args->network;

  if (!*args->prefix && prefix != NULL) {
    if (network->type == BTC_NETWORK_MAINNET)
      btc_str_set(args->prefix, prefix);
    else
      btc_join(args->prefix, prefix, network->name, 0);
  }

  if (args->daemon == -1)
    args->daemon = 0;

  if (args->network_active == -1)
    args->network_active = 1;

  if (args->disable_wallet == -1)
    args->disable_wallet = 0;

  if (args->map_size <= 0)
    args->map_size = 16;

  if (args->map_size > 64)
    args->map_size = 64;

  if (args->checkpoints == -1)
    args->checkpoints = 1;

  if (args->prune == -1)
    args->prune = 0;

  if (args->workers == INT_MIN)
    args->workers = 0;

  if (args->listen == -1)
    args->listen = 1;

  if (args->port == -1)
    args->port = network->port;

  if (args->bind.port == -1)
    btc_netaddr_set(&args->bind, "0.0.0.0", 0);

  if (args->bind.port == 0)
    args->bind.port = args->port;

  if (args->external.port == -1)
    btc_netaddr_set(&args->external, "0.0.0.0", 0);

  if (args->external.port == 0)
    args->external.port = args->port;

  args->external.time = btc_now();
  args->external.services = BTC_NET_LOCAL_SERVICES;

  if (args->no_connect == -1)
    args->no_connect = 0;

  if (args->connect.port == -1)
    btc_netaddr_set(&args->connect, "0.0.0.0", 0);

  if (args->connect.port == 0)
    args->connect.port = network->port;

  args->connect.time = btc_now();
  args->connect.services = BTC_NET_DEFAULT_SERVICES;

  if (args->proxy.port == -1)
    btc_netaddr_set(&args->proxy, "0.0.0.0", 0);

  if (args->proxy.port == 0)
    args->proxy.port = 1080;

  if (args->max_outbound < 0)
    args->max_outbound = 8;

  if (args->max_inbound < 0)
    args->max_inbound = 8;

  if (args->ban_time < 0)
    args->ban_time = 24 * 60 * 60;

  if (args->discover == -1)
    args->discover = 1;

  if (args->upnp == -1)
    args->upnp = 0;

  if (args->onion == -1)
    args->onion = 0;

  if (args->blocks_only == -1)
    args->blocks_only = 0;

  if (args->bip37 == -1)
    args->bip37 = 0;

  if (args->bip152 == -1)
    args->bip152 = 1;

  if (args->bip157 == -1)
    args->bip157 = 0;

  /* conf->only_net */

  if (args->rpc_port == -1)
    args->rpc_port = network->rpc_port;

  if (args->rpc_bind.port == -1)
    btc_netaddr_set(&args->rpc_bind, "127.0.0.1", 0);

  if (args->rpc_bind.port == 0)
    args->rpc_bind.port = args->rpc_port;

  if (!*args->rpc_connect)
    btc_netaddr_get(args->rpc_connect, &args->rpc_bind);

  if (!*args->rpc_user)
    btc_str_assign(args->rpc_user, "bitcoinrpc");

  /* conf->rpc_pass */
  /* conf->version */
  /* conf->help */
  /* conf->method */
  /* conf->params */
  /* conf->length */
}
