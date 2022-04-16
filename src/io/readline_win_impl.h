/*!
 * readline_win_impl.h - readline for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Readline
 */

int
btc_readline(char *line, size_t size, const char *name, int echo) {
  (void)line;
  (void)size;
  (void)name;
  (void)echo;
  return 0;
}
