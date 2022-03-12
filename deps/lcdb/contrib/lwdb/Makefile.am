# Makefile.am - automake file for lcdb
# Copyright (c) 2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/lcdb

liblcdb_la_SOURCES = lwdb.c
liblcdb_la_CFLAGS = $(WARN_FLAGS)
liblcdb_la_LDFLAGS = -static
liblcdb_la_LIBADD = -lleveldb

noinst_LTLIBRARIES = liblcdb.la
