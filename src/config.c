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

static int
btc_join(char *buf, size_t size, ...) {
  char *zp = buf;
  size_t zn = 0;
  const char *xp;
  va_list ap;

  va_start(ap, size);

  while ((xp = va_arg(ap, const char *))) {
    zn += strlen(xp) + 1;

    if (zn > size) {
      va_end(ap);
      return 0;
    }

    while (*xp)
      *zp++ = *xp++;

#if defined(_WIN32)
    *zp++ = '\\';
#else
    *zp++ = '/';
#endif
  }

  if (zn > 0)
    zp--;

  *zp = '\0';

  va_end(ap);

  return 1;
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
    return btc_die("Invalid option: `%s`", xp);

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

    if (!btc_join(zp, zn, home, val + 2, 0))
      return btc_die("Invalid option: `%s`", xp);

    return 1;
  }
#endif

  len = strlen(val);

  if (len + 1 > zn)
    return btc_die("Invalid option: `%s`", xp);

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
    return btc_die("Invalid option: `%s`", xp);

  return 1;
}

static int
btc_match_uint(int *z, const char *xp, const char *yp) {
  if (!btc_match_int(z, xp, yp))
    return 0;

  if (*z < 0)
    return btc_die("Invalid option: `%s`", xp);

  return 1;
}

static int
btc_match_range(int *z, const char *xp, const char *yp, int min, int max) {
  if (!btc_match_int(z, xp, yp))
    return 0;

  if (*z < min || *z > max)
    return btc_die("Invalid option: `%s`", xp);

  return 1;
}

static int
btc_match_port(int *z, const char *xp, const char *yp) {
  if (!btc_match_int(z, xp, yp))
    return 0;

  if (*z < 0 || *z > 0xffff)
    return btc_die("Invalid option: `%s`", xp);

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
  else if (strcmp(val, "signet") == 0)
    *z = btc_signet;
  else
    return btc_die("Invalid option: `%s`", xp);

  return 1;
}

static int
btc_match_netaddr(btc_netaddr_t *z, const char *xp, const char *yp) {
  const char *val;

  if (!btc_match(&val, xp, yp))
    return 0;

  if (!btc_netaddr_set_str(z, val))
    return btc_die("Invalid option: `%s`", xp);

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
    return btc_die("Invalid option: `%s`", xp);

  return 1;
}

/*
 * Config Helpers
 */

static void
conf_init(btc_conf_t *conf) {
  memset(conf, 0, sizeof(*conf));

  conf->network = btc_mainnet;
  conf->prefix[0] = '\0';
  conf->daemon = 0;
  conf->network_active = 1;
  conf->disable_wallet = 0;
  conf->map_size = sizeof(void *) >= 8 ? 16 : 1;
  conf->checkpoints = 1;
  conf->prune = 0;
  conf->workers = 0;
  conf->listen = 1;
  conf->port = 0;
  btc_netaddr_set(&conf->bind, "0.0.0.0", 0);
  btc_netaddr_set(&conf->external, "0.0.0.0", 0);
  conf->no_connect = 0;
  btc_netaddr_set(&conf->connect, "0.0.0.0", 0);
  btc_netaddr_set(&conf->proxy, "0.0.0.0", 0);
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
  conf->rpc_port = 0;
  btc_netaddr_set(&conf->rpc_bind, "127.0.0.1", 0);
  btc_str_assign(conf->rpc_connect, "127.0.0.1");
  btc_str_assign(conf->rpc_user, "bitcoinrpc");
  btc_str_assign(conf->rpc_pass, "");
  conf->version = 0;
  conf->help = 0;
  conf->method = NULL;
  conf->params[0] = NULL;
  conf->length = 0;
}

static int
conf_find_file(char *buf, size_t size,
               int argc, char **argv,
               const char *prefix) {
  const btc_network_t *network = btc_mainnet;
  char datadir[1024];
  int i, ret;

  for (i = 1; i < argc; i++) {
    const char *arg = argv[i];

    if (btc_match__path(buf, size, arg, "-conf="))
      return 1;

    if (btc_match_path(datadir, arg, "-datadir=")) {
      prefix = datadir;
      continue;
    }

    if (btc_match_network(&network, arg, "-chain="))
      continue;

    if (strcmp(arg, "-testnet") == 0) {
      network = btc_testnet;
      continue;
    }
  }

  if (network->type == BTC_NETWORK_MAINNET)
    ret = btc_join(buf, size, prefix, BTC_CONFIG_FILE, 0);
  else
    ret = btc_join(buf, size, prefix, network->name, BTC_CONFIG_FILE, 0);

  if (ret == 0)
    return btc_die("Invalid datadir: %s", prefix);

  return 0;
}

static int
conf_read_file(btc_conf_t *conf, const char *file) {
  FILE *stream = fopen(file, "r");
  char *zp = NULL;
  size_t zn = 0;
  int len;

  if (stream == NULL)
    return 0;

  while ((len = btc_getline(&zp, &zn, stream)) != -1) {
    if (btc_match_path(conf->prefix, zp, "datadir="))
      continue;

    if (btc_match_network(&conf->network, zp, "chain="))
      continue;

    if (btc_match_bool(&conf->daemon, zp, "daemon="))
      continue;

    if (btc_match_bool(&conf->network_active, zp, "networkactive="))
      continue;

    if (btc_match_bool(&conf->disable_wallet, zp, "disablewallet="))
      continue;

    if (btc_match_range(&conf->map_size, zp, "mapsize=", 1, 64))
      continue;

    if (btc_match_bool(&conf->checkpoints, zp, "checkpoints="))
      continue;

    if (btc_match_bool(&conf->prune, zp, "prune="))
      continue;

    if (btc_match_range(&conf->workers, zp, "par=", -6, 15))
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

    if (btc_match_uint(&conf->max_outbound, zp, "maxconnections="))
      continue;

    if (btc_match_uint(&conf->max_outbound, zp, "maxoutbound="))
      continue;

    if (btc_match_uint(&conf->max_inbound, zp, "maxinbound="))
      continue;

    if (btc_match_uint(&conf->ban_time, zp, "bantime="))
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

    return btc_die("Invalid option: `%s`", zp);
  }

  btc_free(zp);

  fclose(stream);

  return 1;
}

static int
conf_parse_args(btc_conf_t *conf, int argc, char **argv, int allow_params) {
  const char *ret;
  int i;

  for (i = 1; i < argc; i++) {
    const char *arg = argv[i];

    if (btc_match(&ret, arg, "-conf="))
      continue;

    if (btc_match_path(conf->prefix, arg, "-datadir="))
      continue;

    if (btc_match_network(&conf->network, arg, "-chain="))
      continue;

    if (btc_match_argbool(&conf->daemon, arg, "-daemon="))
      continue;

    if (btc_match_argbool(&conf->network_active, arg, "-networkactive="))
      continue;

    if (btc_match_argbool(&conf->disable_wallet, arg, "-disablewallet="))
      continue;

    if (btc_match_range(&conf->map_size, arg, "-mapsize=", 1, 64))
      continue;

    if (btc_match_argbool(&conf->checkpoints, arg, "-checkpoints="))
      continue;

    if (btc_match_argbool(&conf->prune, arg, "-prune="))
      continue;

    if (btc_match_range(&conf->workers, arg, "-par=", -6, 15))
      continue;

    if (btc_match_argbool(&conf->listen, arg, "-listen="))
      continue;

    if (btc_match_port(&conf->port, arg, "-port="))
      continue;

    if (btc_match_netaddr(&conf->bind, arg, "-bind="))
      continue;

    if (btc_match_netaddr(&conf->external, arg, "-externalip="))
      continue;

    if (btc_match_argbool(&conf->no_connect, arg, "-connect=")) {
      conf->no_connect ^= 1;
      continue;
    }

    if (btc_match_netaddr(&conf->connect, arg, "-connect="))
      continue;

    if (btc_match_netaddr(&conf->proxy, arg, "-proxy="))
      continue;

    if (btc_match_uint(&conf->max_outbound, arg, "-maxconnections="))
      continue;

    if (btc_match_uint(&conf->max_outbound, arg, "-maxoutbound="))
      continue;

    if (btc_match_uint(&conf->max_inbound, arg, "-maxinbound="))
      continue;

    if (btc_match_uint(&conf->ban_time, arg, "-bantime="))
      continue;

    if (btc_match_argbool(&conf->discover, arg, "-discover="))
      continue;

    if (btc_match_argbool(&conf->upnp, arg, "-upnp="))
      continue;

    if (btc_match_argbool(&conf->onion, arg, "-onion="))
      continue;

    if (btc_match_netaddr(&conf->proxy, arg, "-onion=")) {
      conf->onion = 1;
      continue;
    }

    if (btc_match_argbool(&conf->blocks_only, arg, "-blocksonly="))
      continue;

    if (btc_match_argbool(&conf->bip37, arg, "-peerbloomfilters="))
      continue;

    if (btc_match_argbool(&conf->bip152, arg, "-compactblocks="))
      continue;

    if (btc_match_argbool(&conf->bip157, arg, "-peerblockfilters="))
      continue;

    if (btc_match_net(&conf->only_net, arg, "-onlynet="))
      continue;

    if (btc_match_port(&conf->rpc_port, arg, "-rpcport="))
      continue;

    if (btc_match_netaddr(&conf->rpc_bind, arg, "-rpcbind="))
      continue;

    if (btc_match_str(conf->rpc_connect, arg, "-rpcconnect="))
      continue;

    if (btc_match_str(conf->rpc_user, arg, "-rpcuser="))
      continue;

    if (btc_match_str(conf->rpc_pass, arg, "-rpcpassword="))
      continue;

    if (strcmp(arg, "-testnet") == 0) {
      conf->network = btc_testnet;
      continue;
    }

    if (strcmp(arg, "-version") == 0) {
      conf->version = 1;
      continue;
    }

    if (strcmp(arg, "-?") == 0) {
      conf->help = 1;
      continue;
    }

    if (allow_params) {
      if (arg[0] == '-' && arg[1] >= 'a' && arg[1] <= 'z')
        return btc_die("Invalid option: `%s`", arg);

      if (conf->method == NULL) {
        conf->method = arg;
        continue;
      }

      if (conf->length == lengthof(conf->params))
        return btc_die("Too many parameters.");

      conf->params[conf->length++] = arg;

      continue;
    }

    return btc_die("Invalid option: `%s`", arg);
  }

  return 1;
}

static void
conf_finalize(btc_conf_t *conf, const char *prefix) {
  const btc_network_t *network = conf->network;
  size_t size = sizeof(conf->prefix);
  char *path = conf->prefix;

  if (!*conf->prefix)
    btc_str_set(conf->prefix, prefix);

  if (network->type != BTC_NETWORK_MAINNET) {
    if (!btc_join(path, size, path, network->name, 0)) {
      btc_die("Invalid datadir: %s", path);
      return;
    }
  }

  if (sizeof(void *) < 8 && conf->map_size > 1) {
    btc_die("Map size (%dgb) too large for 32-bit.", conf->map_size);
    return;
  }

  if (conf->port == 0)
    conf->port = network->port;

  if (conf->bind.port == 0)
    conf->bind.port = conf->port;

  if (conf->external.port == 0)
    conf->external.port = conf->port;

  if (conf->connect.port == 0)
    conf->connect.port = network->port;

  if (conf->proxy.port == 0)
    conf->proxy.port = 1080;

  if (conf->rpc_port == 0)
    conf->rpc_port = network->rpc_port;

  if (conf->rpc_bind.port == 0)
    conf->rpc_bind.port = conf->rpc_port;

  if (!btc_netaddr_is_null(&conf->proxy))
    conf->discover = 0;

  conf->external.time = btc_now();
  conf->external.services = BTC_NET_LOCAL_SERVICES;

  conf->connect.time = btc_now();
  conf->connect.services = BTC_NET_DEFAULT_SERVICES;
}

/*
 * Config
 */

void
btc_conf_init(btc_conf_t *conf,
              int argc,
              char **argv,
              const char *prefix,
              int allow_params) {
  char file[1024];
  int explicit;

  /* Initialize. */
  conf_init(conf);

  /* First pass to find config file location. */
  explicit = conf_find_file(file, sizeof(file), argc, argv, prefix);

  /* Try to read the config file. Only fail
     if the user explicitly passed one. */
  if (!conf_read_file(conf, file)) {
    if (explicit) {
      btc_die("Could not read file: %s", file);
      return;
    }
  }

  /* Second pass: parse all arguments (ignoring conf=). */
  conf_parse_args(conf, argc, argv, allow_params);

  /* Finalize. */
  conf_finalize(conf, prefix);
}
