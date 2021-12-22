/*!
 * net.h - network constants for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_NET_H
#define BTC_NET_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Default protocol version.
 */

#define BTC_NET_PROTOCOL_VERSION 70015

/**
 * Minimum protocol version we're willing to talk to.
 */

#define BTC_NET_MIN_VERSION 70001

/**
 * Minimum version for getheaders.
 */

#define BTC_NET_HEADERS_VERSION 31800

/**
 * Minimum version for pong.
 */

#define BTC_NET_PONG_VERSION 60000

/**
 * Minimum version for bip37.
 */

#define BTC_NET_BLOOM_VERSION 70011

/**
 * Minimum version for bip152.
 */

#define BTC_NET_SENDHEADERS_VERSION 7012

/**
 * Minimum version for bip152.
 */

#define BTC_NET_COMPACT_VERSION 70014

/**
 * Minimum version for bip152+segwit.
 */

#define BTC_NET_COMPACT_WITNESS_VERSION 70015

/**
 * Service bits.
 */

enum btc_net_services {
  /**
   * Whether network services are enabled.
   */

  BTC_NET_SERVICE_NETWORK = 1 << 0,

  /**
   * Whether the peer supports the getutxos packet.
   */

  BTC_NET_SERVICE_GETUTXO = 1 << 1,

  /**
   * Whether the peer supports BIP37.
   */

  BTC_NET_SERVICE_BLOOM = 1 << 2,

  /**
   * Whether the peer supports segregated witness.
   */

  BTC_NET_SERVICE_WITNESS = 1 << 3,

  /**
   * Default services.
   */

  BTC_NET_DEFAULT_SERVICES = BTC_NET_SERVICE_NETWORK
                           | BTC_NET_SERVICE_WITNESS
                           | BTC_NET_SERVICE_BLOOM,

  /**
   * Our services.
   */

  BTC_NET_LOCAL_SERVICES = BTC_NET_SERVICE_NETWORK | BTC_NET_SERVICE_WITNESS,

  /**
   * Required services.
   */

  BTC_NET_REQUIRED_SERVICES = BTC_NET_SERVICE_NETWORK
};

/**
 * Default user agent.
 */

#define BTC_NET_USER_AGENT "/mako:0.0.0/"

/**
 * Max message size (~4mb with segwit, formerly 2mb)
 */

#define BTC_NET_MAX_MESSAGE (4 * 1000 * 1000)

/**
 * Amount of time to ban misbheaving peers.
 */

#define BTC_NET_BAN_TIME (24 * 60 * 60)

/**
 * Ban score threshold before ban is placed in effect.
 */

#define BTC_NET_BAN_SCORE 100

/**
 * Maximum inv/getdata size.
 */

#define BTC_NET_MAX_INV 50000

/**
 * Maximum number of requests.
 */

#define BTC_NET_MAX_REQUEST 5000

/**
 * Maximum number of block requests.
 */

#define BTC_NET_MAX_BLOCK_REQUEST (50000 + 1000)

/**
 * Maximum number of tx requests.
 */

#define BTC_NET_MAX_TX_REQUEST 10000

#ifdef __cplusplus
}
#endif

#endif /* BTC_NET_H */
