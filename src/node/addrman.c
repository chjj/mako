/*!
 * addrman.c - address manager for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <io/core.h>
#include <node/addrman.h>
#include <node/logger.h>
#include <node/timedata.h>
#include <satoshi/crypto/rand.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/network.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>
#include "../internal.h"

/*
 * Address Manager
 */

struct btc_addrman_s {
  const btc_network_t *network;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_vector_t addrs;
};

struct btc_addrman_s *
btc_addrman_create(const btc_network_t *network) {
  struct btc_addrman_s *man =
    (struct btc_addrman_s *)btc_malloc(sizeof(struct btc_addrman_s));

  memset(man, 0, sizeof(*man));

  man->network = network;
  man->logger = NULL;
  man->timedata = NULL;

  btc_vector_init(&man->addrs);

  return man;
}

void
btc_addrman_destroy(struct btc_addrman_s *man) {
  btc_vector_clear(&man->addrs);
  btc_free(man);
}

void
btc_addrman_set_logger(struct btc_addrman_s *man, btc_logger_t *logger) {
  man->logger = logger;
}

void
btc_addrman_set_timedata(struct btc_addrman_s *man, const btc_timedata_t *td) {
  man->timedata = td;
}

static void
btc_addrman_log(struct btc_addrman_s *man, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(man->logger, "addrman", fmt, ap);
  va_end(ap);
}

int
btc_addrman_open(struct btc_addrman_s *man) {
  const btc_network_t *network = man->network;
  int64_t now = btc_now();
  btc_sockaddr_t *res, *p;
  btc_netaddr_t addr;
  size_t i;

  for (i = 0; i < network->seeds.length; i++) {
    const char *seed = network->seeds.items[i];

    btc_addrman_log(man, "Resolving %s...", seed);

    if (btc_getaddrinfo(&res, seed)) {
      int total = 0;

      for (p = res; p != NULL; p = p->next) {
        btc_netaddr_set_sockaddr(&addr, p);

        addr.time = now;
        addr.services = BTC_NET_LOCAL_SERVICES;
        addr.port = network->port;

        btc_vector_push(&man->addrs, btc_netaddr_clone(&addr));

        total += 1;
      }

      btc_addrman_log(man, "Resolved %d seeds from %s.", total, seed);

      btc_freeaddrinfo(res);
    } else {
      btc_addrman_log(man, "Could not resolve %s.", seed);
    }

    /* Temporary. */
    if (man->addrs.length >= 10)
      break;
  }

  btc_addrman_log(man, "Resolved %zu seeds.", man->addrs.length);

  return man->addrs.length > 0;
}

void
btc_addrman_close(struct btc_addrman_s *man) {
  btc_netaddr_t *addr;
  size_t i;

  for (i = 0; i < man->addrs.length; i++) {
    addr = (btc_netaddr_t *)man->addrs.items[i];

    btc_netaddr_destroy(addr);
  }

  man->addrs.length = 0;
}

void
btc_addrman_flush(struct btc_addrman_s *man) {
  (void)man;
}

size_t
btc_addrman_size(struct btc_addrman_s *man) {
  return man->addrs.length;
}

int
btc_addrman_is_full(struct btc_addrman_s *man) {
  return man->addrs.length >= 65536;
}

void
btc_addrman_reset(struct btc_addrman_s *man) {
  (void)man;
}

void
btc_addrman_ban(struct btc_addrman_s *man, const btc_netaddr_t *addr) {
  (void)man;
  (void)addr;
}

void
btc_addrman_unban(struct btc_addrman_s *man, const btc_netaddr_t *addr) {
  (void)man;
  (void)addr;
}

int
btc_addrman_is_banned(struct btc_addrman_s *man, const btc_netaddr_t *addr) {
  (void)man;
  (void)addr;
  return 0;
}

void
btc_addrman_clear_banned(struct btc_addrman_s *man) {
  (void)man;
}

const btc_netaddr_t *
btc_addrman_get(struct btc_addrman_s *man) {
  size_t index;

  if (man->addrs.length == 0)
    return NULL;

  index = btc_random() % man->addrs.length;

  return (btc_netaddr_t *)man->addrs.items[index];
}

void
btc_addrman_add(struct btc_addrman_s *man,
                const btc_netaddr_t *addr,
                const btc_netaddr_t *src) {
  btc_netaddr_t *entry = btc_netaddr_clone(addr);

  (void)src;

  btc_vector_push(&man->addrs, entry);
}

void
btc_addrman_mark_attempt(struct btc_addrman_s *man,
                         const btc_netaddr_t *addr) {
  (void)man;
  (void)addr;
}

void
btc_addrman_mark_success(struct btc_addrman_s *man,
                         const btc_netaddr_t *addr) {
  (void)man;
  (void)addr;
}

void
btc_addrman_mark_ack(struct btc_addrman_s *man,
                     const btc_netaddr_t *addr,
                     int64_t services) {
  (void)man;
  (void)addr;
  (void)services;
}

int
btc_addrman_has_local(struct btc_addrman_s *man,
                      const btc_netaddr_t *src) {
  (void)man;
  (void)src;
  return 0;
}

const btc_netaddr_t *
btc_addrman_get_local(struct btc_addrman_s *man,
                      const btc_netaddr_t *src) {
  (void)man;
  (void)src;
  return NULL;
}

void
btc_addrman_add_local(struct btc_addrman_s *man,
                      const btc_netaddr_t *addr,
                      enum btc_score score) {
  (void)man;
  (void)addr;
  (void)score;
}

void
btc_addrman_mark_local(struct btc_addrman_s *man,
                       const btc_netaddr_t *addr) {
  (void)man;
  (void)addr;
}

void
btc_addrman_iterate(btc_addriter_t *iter, struct btc_addrman_s *man) {
  iter->man = man;
  iter->it = 0;
}

int
btc_addrman_next(const btc_netaddr_t **addr, btc_addriter_t *iter) {
  struct btc_addrman_s *man = iter->man;

  if (iter->it >= man->addrs.length)
    return 0;

  *addr = man->addrs.items[iter->it++];

  return 1;
}
