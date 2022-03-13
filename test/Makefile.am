# Makefile.am - automake file for mako
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

AM_CPPFLAGS = $(WARN_FLAGS) -I$(top_builddir)/include
AM_LDFLAGS = -no-install
LDADD = libtests.la

libtests_la_SOURCES = lib/tests.h lib/tests.c lib/rimraf.c

if ENABLE_NODE
libtests_la_LIBADD = $(top_builddir)/libnode.la @ZLIB@
else
libtests_la_LIBADD = $(top_builddir)/libmako.la @ZLIB@
endif

# TODO: Eventually move into separate subdirs.
tests_crypto = t-bip340    \
               t-chacha20  \
               t-drbg      \
               t-ecdsa     \
               t-hash160   \
               t-hash256   \
               t-hmac      \
               t-merkle    \
               t-pbkdf2    \
               t-rand      \
               t-ripemd160 \
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
            t-bip37    \
            t-bip39    \
            t-bip152   \
            t-block    \
            t-bloom    \
            t-coin     \
            t-config   \
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

tests_node = t-addrman  \
             t-chaindb  \
             t-chain    \
             t-mempool  \
             t-miner    \
             t-rpc      \
             t-timedata

check_LTLIBRARIES = libtests.la
check_PROGRAMS = $(tests_crypto) $(tests_lib)

if ENABLE_NODE
check_PROGRAMS += $(tests_io) $(tests_node)
endif

TESTS = $(check_PROGRAMS)

if ENABLE_TESTS
all-local: $(check_PROGRAMS)
endif
