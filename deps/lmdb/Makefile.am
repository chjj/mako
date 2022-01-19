# Makefile.am - automake file for mako
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

liblmdb_la_SOURCES = lmdb.h midl.h mdb.c midl.c

if MINGW
liblmdb_la_CFLAGS = -Wno-incompatible-pointer-types -Wno-return-local-addr
endif

liblmdb_la_LDFLAGS = -static

noinst_LTLIBRARIES = liblmdb.la
