# Makefile.am - automake file for mako
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

librdb_la_SOURCES = rdb.h win.h rdb.c
librdb_la_CFLAGS = -DRDB_BACKGROUND_COMPACTION
if HAVE_PTHREAD
librdb_la_CFLAGS += -DRDB_PTHREAD
endif
librdb_la_LDFLAGS = -static

noinst_LTLIBRARIES = librdb.la
