# Makefile.am - automake file for mako
# Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
# https://github.com/chjj/mako

if MINGW
os_src = lsm_win32.c
else
os_src = lsm_unix.c
endif

liblsm_la_SOURCES = lsm.h        \
                    lsmInt.h     \
                    lsm_ckpt.c   \
                    lsm_file.c   \
                    lsm_log.c    \
                    lsm_main.c   \
                    lsm_mem.c    \
                    lsm_mutex.c  \
                    lsm_shared.c \
                    lsm_sorted.c \
                    lsm_str.c    \
                    lsm_tree.c   \
                    lsm_varint.c \
                    $(os_src)

if MINGW
liblsm_la_CFLAGS = -DNDEBUG -DLSM_MUTEX_WIN32
else
liblsm_la_CFLAGS = -DNDEBUG -DLSM_MUTEX_PTHREADS
endif

liblsm_la_LDFLAGS = -static

noinst_LTLIBRARIES = liblsm.la
