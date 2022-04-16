/*!
 * readline_unix_impl.h - readline for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/*
 * Helpers
 */

static int
set_raw_mode(FILE *stream, int value) {
  static struct termios orig_termios;
  static int has_orig = 0;
  int fd = fileno(stream);
  struct termios tmp;

  if (fd < 0)
    return 0;

  if (has_orig == 0) {
    if (tcgetattr(fd, &orig_termios) != 0)
      return 0;

    has_orig = 1;
  }

  tmp = orig_termios;

  if (value) {
    tmp.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    tmp.c_oflag |= (ONLCR);
    tmp.c_cflag |= (CS8);
    tmp.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    tmp.c_cc[VMIN] = 1;
    tmp.c_cc[VTIME] = 0;
  }

  return tcsetattr(fd, TCSADRAIN, &tmp) == 0;
}

/*
 * Readline
 */

int
btc_readline(char *line, size_t size, const char *name, int echo) {
  static int stdin_tty = 0;
  static int stdout_tty = 0;
  static int has_ttys = 0;
  size_t pos = 0;
  char *ptr;

  if (has_ttys == 0) {
    stdin_tty = isatty(fileno(stdin));
    stdout_tty = isatty(fileno(stdout));
    has_ttys = 1;
  }

  if (size < 2)
    return 0;

  if (!stdin_tty) {
    if (fgets(line, size, stdin) == NULL)
      return 0;

    pos = strlen(line);
    goto done;
  }

  if (!set_raw_mode(stdin, 1))
    return 0;

  if (stdout_tty) {
    fprintf(stdout, "Enter %s: ", name);
    fflush(stdout);
  }

  for (;;) {
    int ch = getchar();

    if (ch == EOF)
      break;

    switch (ch) {
      case '\x03': /* ^C */
      case '\x04': /* ^D */
      case '\x1c': /* ^\ */
      case '\r': {
        if (stdout_tty) {
          fputs("\r\n", stdout);
          fflush(stdout);
        }

        set_raw_mode(stdin, 0);

        goto done;
      }

      case '\x7f': { /* ^? */
        if (pos > 0) {
          pos--;

          if (echo && stdout_tty) {
            fputs("\x1b[1D \x1b[1D", stdout);
            fflush(stdout);
          }
        }

        break;
      }

      default: {
        if (ch < ' ' || ch > '~')
          break;

        if (pos < size - 1) {
          line[pos++] = ch;

          if (echo && stdout_tty) {
            fputc(ch, stdout);
            fflush(stdout);
          }
        }

        break;
      }
    }
  }

done:
  while (pos > 0 && line[pos - 1] <= ' ')
    pos--;

  line[pos] = '\0';

  ptr = line;

  while (*ptr && *ptr <= ' ') {
    ptr++;
    pos--;
  }

  if (ptr != line)
    memmove(line, ptr, pos + 1);

  return 1;
}
