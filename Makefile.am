# Makefile.am - automake file for mako
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

#
# Initialization
#

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(top_srcdir)/include

includedir = $(prefix)/include/mako
licensedir = $(datadir)/licenses/$(PACKAGE_NAME)
pkgconfigdir = $(libdir)/pkgconfig

dist_doc_DATA = README.md
dist_license_DATA = LICENSE
pkgconfig_DATA = libmako.pc

EXTRA_DIST = cmake/              \
             scripts/            \
             autogen.sh          \
             CHANGELOG.md        \
             CMakeLists.txt      \
             libmako-cmake.pc.in

#
# Dependencies
#

if ENABLE_NODE
if ENABLE_LEVELDB
mako_dbdir = deps/lcdb/contrib/lwdb
else
mako_dbdir = deps/lcdb
endif
endif

SUBDIRS = $(mako_dbdir) . test

#
# Headers
#

include_HEADERS = include/mako/address.h           \
                  include/mako/array.h             \
                  include/mako/bip152.h            \
                  include/mako/bip32.h             \
                  include/mako/bip37.h             \
                  include/mako/bip39.h             \
                  include/mako/block.h             \
                  include/mako/bloom.h             \
                  include/mako/buffer.h            \
                  include/mako/coins.h             \
                  include/mako/common.h            \
                  include/mako/config.h            \
                  include/mako/consensus.h         \
                  include/mako/crypto/drbg.h       \
                  include/mako/crypto/ecc.h        \
                  include/mako/crypto/hash.h       \
                  include/mako/crypto/merkle.h     \
                  include/mako/crypto/rand.h       \
                  include/mako/crypto/siphash.h    \
                  include/mako/crypto/stream.h     \
                  include/mako/crypto/types.h      \
                  include/mako/encoding.h          \
                  include/mako/entry.h             \
                  include/mako/header.h            \
                  include/mako/heap.h              \
                  include/mako/impl.h              \
                  include/mako/json.h              \
                  include/mako/json/json_builder.h \
                  include/mako/json/json_parser.h  \
                  include/mako/list.h              \
                  include/mako/map.h               \
                  include/mako/mpi.h               \
                  include/mako/netaddr.h           \
                  include/mako/net.h               \
                  include/mako/netmsg.h            \
                  include/mako/network.h           \
                  include/mako/policy.h            \
                  include/mako/printf.h            \
                  include/mako/script.h            \
                  include/mako/select.h            \
                  include/mako/tx.h                \
                  include/mako/types.h             \
                  include/mako/util.h              \
                  include/mako/vector.h

noinst_HEADERS = src/bio.h                         \
                 src/crypto/asn1.h                 \
                 src/crypto/fields/secp256k1_32.h  \
                 src/crypto/fields/secp256k1_64.h  \
                 src/crypto/rand.h                 \
                 src/crypto/secp256k1.h            \
                 src/impl.h                        \
                 src/internal.h                    \
                 src/io/http/http_common.h         \
                 src/io/http/http_parser.h         \
                 src/map/khash.h                   \
                 src/map/map.h                     \
                 src/printf_core.h                 \
                 src/words.h                       \
                 test/data/bip32_vectors.h         \
                 test/data/bip340_vectors.h        \
                 test/data/bip39_vectors.h         \
                 test/data/chain_vectors_main.h    \
                 test/data/chain_vectors_testnet.h \
                 test/data/ecdsa_vectors.h         \
                 test/data/script_vectors.h        \
                 test/data/sighash_vectors.h       \
                 test/data/tx_invalid_vectors.h    \
                 test/data/tx_valid_vectors.h      \
                 test/lib/tests.h

#
# Sources
#

mako_sources = src/crypto/chacha20.c   \
               src/crypto/drbg.c       \
               src/crypto/ecc.c        \
               src/crypto/hash160.c    \
               src/crypto/hash256.c    \
               src/crypto/hmac256.c    \
               src/crypto/hmac512.c    \
               src/crypto/merkle.c     \
               src/crypto/pbkdf256.c   \
               src/crypto/pbkdf512.c   \
               src/crypto/rand.c       \
               src/crypto/rand_env.c   \
               src/crypto/rand_sys.c   \
               src/crypto/ripemd160.c  \
               src/crypto/sha1.c       \
               src/crypto/sha256.c     \
               src/crypto/sha512.c     \
               src/crypto/siphash.c    \
               src/json/json_builder.c \
               src/json/json_extra.c   \
               src/json/json_parser.c  \
               src/map/addrmap.c       \
               src/map/addrset.c       \
               src/map/hashmap.c       \
               src/map/hashset.c       \
               src/map/hashtab.c       \
               src/map/intmap.c        \
               src/map/longmap.c       \
               src/map/longset.c       \
               src/map/longtab.c       \
               src/map/netmap.c        \
               src/map/outmap.c        \
               src/map/outset.c        \
               src/address.c           \
               src/amount.c            \
               src/array.c             \
               src/base16.c            \
               src/base58.c            \
               src/bech32.c            \
               src/bip32.c             \
               src/bip37.c             \
               src/bip39.c             \
               src/bip152.c            \
               src/block.c             \
               src/bloom.c             \
               src/buffer.c            \
               src/coin.c              \
               src/compact.c           \
               src/compress.c          \
               src/config.c            \
               src/consensus.c         \
               src/entry.c             \
               src/header.c            \
               src/heap.c              \
               src/input.c             \
               src/inpvec.c            \
               src/inspect.c           \
               src/internal.c          \
               src/json.c              \
               src/mainnet.c           \
               src/mpi.c               \
               src/murmur3.c           \
               src/netaddr.c           \
               src/netmsg.c            \
               src/network.c           \
               src/outpoint.c          \
               src/output.c            \
               src/outvec.c            \
               src/policy.c            \
               src/printf.c            \
               src/printf_core.c       \
               src/regtest.c           \
               src/script.c            \
               src/select.c            \
               src/sign.c              \
               src/signet.c            \
               src/simnet.c            \
               src/sprintf.c           \
               src/testnet.c           \
               src/tx.c                \
               src/undo.c              \
               src/util.c              \
               src/vector.c            \
               src/view.c

io_sources = src/io/http/http_client.c \
             src/io/http/http_common.c \
             src/io/http/http_parser.c \
             src/io/http/http_server.c \
             src/io/addrinfo.c         \
             src/io/core.c             \
             src/io/loop.c             \
             src/io/net.c              \
             src/io/sockaddr.c         \
             src/io/workers.c

node_sources = src/node/addrman.c  \
               src/node/chain.c    \
               src/node/chaindb.c  \
               src/node/logger.c   \
               src/node/mempool.c  \
               src/node/miner.c    \
               src/node/node.c     \
               src/node/pool.c     \
               src/node/rpc.c      \
               src/node/timedata.c

client_sources = src/client/client.c

#
# Targets
#

if MINGW
mako_ldflags = -avoid-version -Wl,--output-def,.libs/libmako.def
else
mako_ldflags = -version-info @ABI_VERSION@
endif

libmako_la_SOURCES = $(mako_sources)
libmako_la_CFLAGS = $(WARN_FLAGS)
if ENABLE_SHARED
libmako_la_CFLAGS += -DBTC_EXPORT
libmako_la_LDFLAGS = -no-undefined $(mako_ldflags)
endif

lib_LTLIBRARIES = libmako.la

if ENABLE_NODE
libio_la_SOURCES = $(io_sources)
libio_la_CFLAGS = $(WARN_FLAGS)
libio_la_LDFLAGS = -static

libnode_la_SOURCES = $(node_sources)
libnode_la_CFLAGS = $(WARN_FLAGS) -I$(top_srcdir)/deps/lcdb/include
libnode_la_LDFLAGS = -static
libnode_la_LIBADD = libmako.la libio.la $(mako_dbdir)/liblcdb.la

libclient_la_SOURCES = $(client_sources)
libclient_la_CFLAGS = $(WARN_FLAGS)
libclient_la_LDFLAGS = -static
libclient_la_LIBADD = libmako.la libio.la

makod_SOURCES = src/node/main.c
makod_CFLAGS = $(WARN_FLAGS)
makod_LDFLAGS = -static
makod_LDADD = libnode.la

mako_SOURCES = src/client/main.c
mako_CFLAGS = $(WARN_FLAGS)
mako_LDFLAGS = -static
mako_LDADD = libclient.la

noinst_LTLIBRARIES = libio.la libnode.la libclient.la
bin_PROGRAMS = makod mako
endif
