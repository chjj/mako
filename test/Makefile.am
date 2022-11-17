# Makefile.am - automake file for mako
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_LDFLAGS = -static

if ENABLE_NODE
LDADD = $(top_builddir)/libnode.la   \
        $(top_builddir)/libwallet.la \
        libtests.la                  \
        @ZLIB@
else
LDADD = $(top_builddir)/libmako.la \
        libtests.la                \
        @ZLIB@
endif

SOURCES = data/bip32_vectors.h         \
          data/bip340_vectors.h        \
          data/bip39_vectors.h         \
          data/chain_vectors_main.h    \
          data/chain_vectors_testnet.h \
          data/ecdsa_vectors.h         \
          data/script_vectors.h        \
          data/sighash_vectors.h       \
          data/tx_invalid_vectors.h    \
          data/tx_valid_vectors.h

libtests_la_SOURCES = lib/tests.c            \
                      lib/tests.h            \
                      lib/rimraf.c           \
                      lib/rimraf_unix_impl.h \
                      lib/rimraf_win_impl.h

tests_crypto = t-bip340    \
               t-chacha20  \
               t-drbg      \
               t-ecdsa     \
               t-hash160   \
               t-hash256   \
               t-hmac      \
               t-merkle    \
               t-pbkdf2    \
               t-poly1305  \
               t-rand      \
               t-ripemd160 \
               t-salsa20   \
               t-secretbox \
               t-sha1      \
               t-sha256    \
               t-sha512    \
               t-siphash

tests_lib = t-address  \
            t-array    \
            t-base16   \
            t-base58   \
            t-bech32   \
            t-bip32    \
            t-bip340   \
            t-bip37    \
            t-bip39    \
            t-bip152   \
            t-block    \
            t-bloom    \
            t-coin     \
            t-entry    \
            t-header   \
            t-heap     \
            t-input    \
            t-list     \
            t-map      \
            t-mpi      \
            t-murmur3  \
            t-netaddr  \
            t-netmsg   \
            t-outpoint \
            t-output   \
            t-printf   \
            t-script   \
            t-sighash  \
            t-tx       \
            t-util     \
            t-vector   \
            t-view

tests_io = t-addrinfo \
           t-sockaddr \
           t-fs       \
           t-loop     \
           t-thread   \
           t-http     \
           t-workers

tests_base = t-addrman  \
             t-config   \
             t-timedata

tests_node = t-chaindb \
             t-chain   \
             t-mempool \
             t-miner   \
             t-rpc

tests_wallet = t-wallet

check_LTLIBRARIES = libtests.la
check_PROGRAMS = $(tests_crypto) $(tests_lib)

if ENABLE_NODE
check_PROGRAMS += $(tests_io) $(tests_base) $(tests_node) $(tests_wallet)
endif

TESTS = $(check_PROGRAMS)

if ENABLE_TESTS
all-local: $(check_PROGRAMS)
endif
