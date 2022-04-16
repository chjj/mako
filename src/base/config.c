/*!
 * config.c - config for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include <base/config.h>

#include <io/core.h>

#include <mako/net.h>
#include <mako/netaddr.h>
#include <mako/network.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "../internal.h"

/*
 * Constants
 */

#define BTC_CONFIG_FILE "mako.conf"

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
btc_fgets(char *buf, size_t size, FILE *stream) {
  char *xp, *sp;
  size_t xn;

  while (fgets(buf, size, stream) != NULL) {
    xp = buf;
    sp = strchr(xp, '#');

    if (sp != NULL)
      *sp = '\0';

    while (*xp != '\0' && *xp <= ' ')
      xp++;

    xn = strlen(xp);

    while (xn > 0 && xp[xn - 1] <= ' ')
      xn--;

    xp[xn] = '\0';

    if (xn == 0)
      continue;

    if (xp != buf)
      memmove(buf, xp, xn + 1);

    return 1;
  }

  return 0;
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
    return 0;

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

#if defined(_WIN32)
  if (val[0] == '~' && (val[1] == '/' || val[1] == '\\') && val[2] != '\0') {
    char home[MAX_PATH];
    DWORD ret;

    if (GetVersion() < 0x80000000) {
      WCHAR tmp[MAX_PATH * 4];

      ret = GetEnvironmentVariableW(L"USERPROFILE", tmp, lengthof(tmp));

      if (ret == 0 || ret >= lengthof(tmp)
          || WideCharToMultiByte(CP_UTF8, 0, tmp, -1,
                                 home, sizeof(home),
                                 NULL, NULL) <= 0) {
        btc_str_assign(home, "C:");
      }
    } else {
      ret = GetEnvironmentVariableA("USERPROFILE", home, sizeof(home));

      if (ret == 0 || ret >= sizeof(home))
        btc_str_assign(home, "C:");
    }

    return btc_join(zp, zn, home, val + 2, NULL);
  }
#else
  if (val[0] == '~' && val[1] == '/' && val[2] != '\0') {
    char *home = getenv("HOME");

    if (home == NULL)
      home = "";

    return btc_join(zp, zn, home, val + 2, NULL);
  }
#endif

  len = strlen(val);

  if (len + 1 > zn)
    return 0;

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
    return 0;

  return 1;
}

static int
btc_match_uint(int *z, const char *xp, const char *yp) {
  if (!btc_match_int(z, xp, yp))
    return 0;

  if (*z < 0)
    return 0;

  return 1;
}

static int
btc_match_range(int *z, const char *xp, const char *yp, int min, int max) {
  if (!btc_match_int(z, xp, yp))
    return 0;

  if (*z < min || *z > max)
    return 0;

  return 1;
}

static int
btc_match_port(int *z, const char *xp, const char *yp) {
  return btc_match_range(z, xp, yp, 0, 0xffff);
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
    return 0;

  return 1;
}

static int
btc_match_netaddr(btc_netaddr_t *z, const char *xp, const char *yp) {
  const char *val;

  if (!btc_match(&val, xp, yp))
    return 0;

  if (!btc_netaddr_set_str(z, val))
    return 0;

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
    return 0;

  return 1;
}

static int
btc_match_level(int *z, const char *xp, const char *yp) {
  static const char *levels[] = {
    "none",
    "error",
    "warning",
    "info",
    "debug",
    "spam"
  };

  const char *val;
  size_t i;

  if (!btc_match(&val, xp, yp))
    return 0;

  for (i = 0; i < lengthof(levels); i++) {
    if (strcmp(val, levels[i]) == 0) {
      *z = i;
      return 1;
    }
  }

  return 0;
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
  conf->level = 4; /* BTC_LOG_DEBUG */
  conf->network_active = 1;
  conf->disable_wallet = 0;
  conf->cache_size = 128;
  conf->checkpoints = 1;
  conf->prune = 0;
  conf->workers = 0;
  conf->listen = 1;
  conf->port = 0;
  btc_vector_init(&conf->bind);
  btc_vector_init(&conf->external);
  btc_vector_init(&conf->connect);
  conf->no_connect = 0;
  btc_netaddr_set(&conf->proxy, "0.0.0.0", 0);
  conf->max_connections = 0;
  conf->max_inbound = 128;
  conf->max_outbound = 8;
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
  btc_vector_init(&conf->rpc_bind);
  btc_str_assign(conf->rpc_connect, "127.0.0.1");
  btc_str_assign(conf->rpc_user, "bitcoinrpc");
  btc_str_assign(conf->rpc_pass, "");
  conf->version = 0;
  conf->help = 0;
  conf->method = NULL;
  conf->params[0] = NULL;
  conf->length = 0;
}

static void
conf_clear(btc_conf_t *conf) {
  size_t i;

  for (i = 0; i < conf->bind.length; i++)
    btc_netaddr_destroy(conf->bind.items[i]);

  for (i = 0; i < conf->external.length; i++)
    btc_netaddr_destroy(conf->external.items[i]);

  for (i = 0; i < conf->connect.length; i++)
    btc_netaddr_destroy(conf->connect.items[i]);

  for (i = 0; i < conf->rpc_bind.length; i++)
    btc_netaddr_destroy(conf->rpc_bind.items[i]);

  btc_vector_clear(&conf->bind);
  btc_vector_clear(&conf->external);
  btc_vector_clear(&conf->connect);
  btc_vector_clear(&conf->rpc_bind);
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
    ret = btc_join(buf, size, prefix, BTC_CONFIG_FILE, NULL);
  else
    ret = btc_join(buf, size, prefix, network->name, BTC_CONFIG_FILE, NULL);

  if (ret == 0)
    return btc_die("Invalid datadir: %s", prefix);

  return 0;
}

static int
conf_read_file(btc_conf_t *conf, const char *file) {
  FILE *stream = fopen(file, "r");
  btc_netaddr_t addr;
  char opt[1024];

  if (stream == NULL)
    return 0;

  while (btc_fgets(opt, sizeof(opt), stream)) {
    if (btc_match_path(conf->prefix, opt, "datadir="))
      continue;

    if (btc_match_network(&conf->network, opt, "chain="))
      continue;

    if (btc_match_bool(&conf->daemon, opt, "daemon="))
      continue;

    if (btc_match_level(&conf->level, opt, "loglevel="))
      continue;

    if (btc_match_bool(&conf->network_active, opt, "networkactive="))
      continue;

    if (btc_match_bool(&conf->disable_wallet, opt, "disablewallet="))
      continue;

    if (btc_match_range(&conf->cache_size, opt, "dbcache=", 8, 2048))
      continue;

    if (btc_match_bool(&conf->checkpoints, opt, "checkpoints="))
      continue;

    if (btc_match_bool(&conf->prune, opt, "prune="))
      continue;

    if (btc_match_range(&conf->workers, opt, "par=", -6, 15))
      continue;

    if (btc_match_bool(&conf->listen, opt, "listen="))
      continue;

    if (btc_match_port(&conf->port, opt, "port="))
      continue;

    if (btc_match_netaddr(&addr, opt, "bind=")) {
      btc_vector_push(&conf->bind, btc_netaddr_clone(&addr));
      continue;
    }

    if (btc_match_netaddr(&addr, opt, "externalip=")) {
      btc_vector_push(&conf->external, btc_netaddr_clone(&addr));
      continue;
    }

    if (btc_match_bool(&conf->no_connect, opt, "connect=")) {
      conf->no_connect ^= 1;
      continue;
    }

    if (btc_match_netaddr(&addr, opt, "connect=")) {
      btc_vector_push(&conf->connect, btc_netaddr_clone(&addr));
      continue;
    }

    if (btc_match_netaddr(&conf->proxy, opt, "proxy="))
      continue;

    if (btc_match_uint(&conf->max_connections, opt, "maxconnections="))
      continue;

    if (btc_match_uint(&conf->max_inbound, opt, "maxinbound="))
      continue;

    if (btc_match_uint(&conf->max_outbound, opt, "maxoutbound="))
      continue;

    if (btc_match_uint(&conf->ban_time, opt, "bantime="))
      continue;

    if (btc_match_bool(&conf->discover, opt, "discover="))
      continue;

    if (btc_match_bool(&conf->upnp, opt, "upnp="))
      continue;

    if (btc_match_bool(&conf->onion, opt, "onion="))
      continue;

    if (btc_match_netaddr(&conf->proxy, opt, "onion=")) {
      conf->onion = 1;
      continue;
    }

    if (btc_match_bool(&conf->blocks_only, opt, "blocksonly="))
      continue;

    if (btc_match_bool(&conf->bip37, opt, "peerbloomfilters="))
      continue;

    if (btc_match_bool(&conf->bip152, opt, "compactblocks="))
      continue;

    if (btc_match_bool(&conf->bip157, opt, "peerblockfilters="))
      continue;

    if (btc_match_net(&conf->only_net, opt, "onlynet="))
      continue;

    if (btc_match_port(&conf->rpc_port, opt, "rpcport="))
      continue;

    if (btc_match_netaddr(&addr, opt, "rpcbind=")) {
      btc_vector_push(&conf->rpc_bind, btc_netaddr_clone(&addr));
      continue;
    }

    if (btc_match_str(conf->rpc_connect, opt, "rpcconnect="))
      continue;

    if (btc_match_str(conf->rpc_user, opt, "rpcuser="))
      continue;

    if (btc_match_str(conf->rpc_pass, opt, "rpcpassword="))
      continue;

    fclose(stream);

    return btc_die("Invalid option: `%s`", opt);
  }

  if (ferror(stream)) {
    fclose(stream);
    return btc_die("Could not read file: %s", file);
  }

  fclose(stream);

  return 1;
}

static int
conf_parse_args(btc_conf_t *conf, int argc, char **argv, int allow_params) {
  btc_netaddr_t addr;
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

    if (btc_match_level(&conf->level, arg, "-loglevel="))
      continue;

    if (btc_match_argbool(&conf->network_active, arg, "-networkactive="))
      continue;

    if (btc_match_argbool(&conf->disable_wallet, arg, "-disablewallet="))
      continue;

    if (btc_match_range(&conf->cache_size, arg, "-dbcache=", 8, 2048))
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

    if (btc_match_netaddr(&addr, arg, "-bind=")) {
      btc_vector_push(&conf->bind, btc_netaddr_clone(&addr));
      continue;
    }

    if (btc_match_netaddr(&addr, arg, "-externalip=")) {
      btc_vector_push(&conf->external, btc_netaddr_clone(&addr));
      continue;
    }

    if (btc_match_argbool(&conf->no_connect, arg, "-connect=")) {
      conf->no_connect ^= 1;
      continue;
    }

    if (btc_match_netaddr(&addr, arg, "-connect=")) {
      btc_vector_push(&conf->connect, btc_netaddr_clone(&addr));
      continue;
    }

    if (btc_match_netaddr(&conf->proxy, arg, "-proxy="))
      continue;

    if (btc_match_uint(&conf->max_connections, arg, "-maxconnections="))
      continue;

    if (btc_match_uint(&conf->max_inbound, arg, "-maxinbound="))
      continue;

    if (btc_match_uint(&conf->max_outbound, arg, "-maxoutbound="))
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

    if (btc_match_netaddr(&addr, arg, "-rpcbind=")) {
      btc_vector_push(&conf->rpc_bind, btc_netaddr_clone(&addr));
      continue;
    }

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
  int64_t now = btc_now();
  size_t i;

  if (!*conf->prefix)
    btc_str_set(conf->prefix, prefix);

  if (network->type != BTC_NETWORK_MAINNET) {
    btc_fs_mkdir(path);

    if (!btc_join(path, size, path, network->name, NULL)) {
      btc_die("Invalid datadir: %s", path);
      return;
    }
  }

  if (conf->bind.length > 0)
    conf->listen = 1;

  if (conf->port == 0)
    conf->port = network->port;

  for (i = 0; i < conf->bind.length; i++) {
    btc_netaddr_t *addr = conf->bind.items[i];

    if (addr->port == 0)
      addr->port = conf->port;
  }

  for (i = 0; i < conf->external.length; i++) {
    btc_netaddr_t *addr = conf->external.items[i];

    if (addr->port == 0)
      addr->port = conf->port;

    addr->time = now;
    addr->services = BTC_NET_LOCAL_SERVICES;
  }

  for (i = 0; i < conf->connect.length; i++) {
    btc_netaddr_t *addr = conf->connect.items[i];

    if (addr->port == 0)
      addr->port = network->port;

    addr->time = now;
    addr->services = BTC_NET_DEFAULT_SERVICES;
  }

  if (conf->proxy.port == 0)
    conf->proxy.port = conf->onion ? 9050 : 1080;

  if (conf->rpc_port == 0)
    conf->rpc_port = network->rpc_port;

  for (i = 0; i < conf->rpc_bind.length; i++) {
    btc_netaddr_t *addr = conf->rpc_bind.items[i];

    if (addr->port == 0)
      addr->port = conf->rpc_port;
  }

  if (conf->external.length > 0
      || !btc_netaddr_is_null(&conf->proxy)) {
    conf->discover = 0;
  }

  if (conf->max_connections) {
    conf->max_inbound = conf->max_connections - 8;
    conf->max_outbound = 8;

    if (conf->max_inbound < 0)
      conf->max_inbound = 0;

    if (conf->max_outbound > conf->max_connections)
      conf->max_outbound = conf->max_connections;
  }

  if (conf->max_inbound == 0)
    conf->listen = 0;
}

/*
 * Config
 */

btc_conf_t *
btc_conf_create(int argc,
                char **argv,
                const char *prefix,
                int allow_params) {
  btc_conf_t *conf = btc_malloc(sizeof(btc_conf_t));
  btc_conf_init(conf, argc, argv, prefix, allow_params);
  return conf;
}

void
btc_conf_destroy(btc_conf_t *conf) {
  btc_conf_clear(conf);
  btc_free(conf);
}

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

void
btc_conf_clear(btc_conf_t *conf) {
  conf_clear(conf);
}
