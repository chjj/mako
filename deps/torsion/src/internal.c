/*!
 * internal.c - internal utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <limits.h>
#ifdef TORSION_DEBUG
#  include <stdio.h>
#endif
#include <stdlib.h>
#include "internal.h"

/*
 * Helpers
 */

TORSION_NORETURN void
torsion__assert_fail(const char *file, int line, const char *expr) {
  /* LCOV_EXCL_START */
#if defined(TORSION_DEBUG)
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
#else
  (void)file;
  (void)line;
  (void)expr;
#endif
  abort();
  /* LCOV_EXCL_STOP */
}

TORSION_NORETURN void
torsion__abort(void) {
  abort(); /* LCOV_EXCL_LINE */
}

/*
 * Character Transcoding
 */

/* Abuse compiler expression folding to create
 * a conversion table for the execution character
 * set.
 *
 * Credit goes to gnulib for this idea.
 */

#define XX(xx) (       \
    (xx) == '\0' ?   0 \
  : (xx) == '\a' ?   7 \
  : (xx) == '\b' ?   8 \
  : (xx) == '\t' ?   9 \
  : (xx) == '\n' ?  10 \
  : (xx) == '\v' ?  11 \
  : (xx) == '\f' ?  12 \
  : (xx) == '\r' ?  13 \
  : (xx) == ' '  ?  32 \
  : (xx) == '!'  ?  33 \
  : (xx) == '"'  ?  34 \
  : (xx) == '#'  ?  35 \
  : (xx) == '$'  ?  36 \
  : (xx) == '%'  ?  37 \
  : (xx) == '&'  ?  38 \
  : (xx) == '\'' ?  39 \
  : (xx) == '('  ?  40 \
  : (xx) == ')'  ?  41 \
  : (xx) == '*'  ?  42 \
  : (xx) == '+'  ?  43 \
  : (xx) == ','  ?  44 \
  : (xx) == '-'  ?  45 \
  : (xx) == '.'  ?  46 \
  : (xx) == '/'  ?  47 \
  : (xx) == '0'  ?  48 \
  : (xx) == '1'  ?  49 \
  : (xx) == '2'  ?  50 \
  : (xx) == '3'  ?  51 \
  : (xx) == '4'  ?  52 \
  : (xx) == '5'  ?  53 \
  : (xx) == '6'  ?  54 \
  : (xx) == '7'  ?  55 \
  : (xx) == '8'  ?  56 \
  : (xx) == '9'  ?  57 \
  : (xx) == ':'  ?  58 \
  : (xx) == ';'  ?  59 \
  : (xx) == '<'  ?  60 \
  : (xx) == '='  ?  61 \
  : (xx) == '>'  ?  62 \
  : (xx) == '?'  ?  63 \
  : (xx) == '@'  ?  64 \
  : (xx) == 'A'  ?  65 \
  : (xx) == 'B'  ?  66 \
  : (xx) == 'C'  ?  67 \
  : (xx) == 'D'  ?  68 \
  : (xx) == 'E'  ?  69 \
  : (xx) == 'F'  ?  70 \
  : (xx) == 'G'  ?  71 \
  : (xx) == 'H'  ?  72 \
  : (xx) == 'I'  ?  73 \
  : (xx) == 'J'  ?  74 \
  : (xx) == 'K'  ?  75 \
  : (xx) == 'L'  ?  76 \
  : (xx) == 'M'  ?  77 \
  : (xx) == 'N'  ?  78 \
  : (xx) == 'O'  ?  79 \
  : (xx) == 'P'  ?  80 \
  : (xx) == 'Q'  ?  81 \
  : (xx) == 'R'  ?  82 \
  : (xx) == 'S'  ?  83 \
  : (xx) == 'T'  ?  84 \
  : (xx) == 'U'  ?  85 \
  : (xx) == 'V'  ?  86 \
  : (xx) == 'W'  ?  87 \
  : (xx) == 'X'  ?  88 \
  : (xx) == 'Y'  ?  89 \
  : (xx) == 'Z'  ?  90 \
  : (xx) == '['  ?  91 \
  : (xx) == '\\' ?  92 \
  : (xx) == ']'  ?  93 \
  : (xx) == '^'  ?  94 \
  : (xx) == '_'  ?  95 \
  : (xx) == '`'  ?  96 \
  : (xx) == 'a'  ?  97 \
  : (xx) == 'b'  ?  98 \
  : (xx) == 'c'  ?  99 \
  : (xx) == 'd'  ? 100 \
  : (xx) == 'e'  ? 101 \
  : (xx) == 'f'  ? 102 \
  : (xx) == 'g'  ? 103 \
  : (xx) == 'h'  ? 104 \
  : (xx) == 'i'  ? 105 \
  : (xx) == 'j'  ? 106 \
  : (xx) == 'k'  ? 107 \
  : (xx) == 'l'  ? 108 \
  : (xx) == 'm'  ? 109 \
  : (xx) == 'n'  ? 110 \
  : (xx) == 'o'  ? 111 \
  : (xx) == 'p'  ? 112 \
  : (xx) == 'q'  ? 113 \
  : (xx) == 'r'  ? 114 \
  : (xx) == 's'  ? 115 \
  : (xx) == 't'  ? 116 \
  : (xx) == 'u'  ? 117 \
  : (xx) == 'v'  ? 118 \
  : (xx) == 'w'  ? 119 \
  : (xx) == 'x'  ? 120 \
  : (xx) == 'y'  ? 121 \
  : (xx) == 'z'  ? 122 \
  : (xx) == '{'  ? 123 \
  : (xx) == '|'  ? 124 \
  : (xx) == '}'  ? 125 \
  : (xx) == '~'  ? 126 \
  :                127 \
)

/*
 * Native->ASCII Map
 */

const int torsion__ascii[256] = {
  XX(0x00), XX(0x01), XX(0x02), XX(0x03),
  XX(0x04), XX(0x05), XX(0x06), XX(0x07),
  XX(0x08), XX(0x09), XX(0x0a), XX(0x0b),
  XX(0x0c), XX(0x0d), XX(0x0e), XX(0x0f),
  XX(0x10), XX(0x11), XX(0x12), XX(0x13),
  XX(0x14), XX(0x15), XX(0x16), XX(0x17),
  XX(0x18), XX(0x19), XX(0x1a), XX(0x1b),
  XX(0x1c), XX(0x1d), XX(0x1e), XX(0x1f),
  XX(0x20), XX(0x21), XX(0x22), XX(0x23),
  XX(0x24), XX(0x25), XX(0x26), XX(0x27),
  XX(0x28), XX(0x29), XX(0x2a), XX(0x2b),
  XX(0x2c), XX(0x2d), XX(0x2e), XX(0x2f),
  XX(0x30), XX(0x31), XX(0x32), XX(0x33),
  XX(0x34), XX(0x35), XX(0x36), XX(0x37),
  XX(0x38), XX(0x39), XX(0x3a), XX(0x3b),
  XX(0x3c), XX(0x3d), XX(0x3e), XX(0x3f),
  XX(0x40), XX(0x41), XX(0x42), XX(0x43),
  XX(0x44), XX(0x45), XX(0x46), XX(0x47),
  XX(0x48), XX(0x49), XX(0x4a), XX(0x4b),
  XX(0x4c), XX(0x4d), XX(0x4e), XX(0x4f),
  XX(0x50), XX(0x51), XX(0x52), XX(0x53),
  XX(0x54), XX(0x55), XX(0x56), XX(0x57),
  XX(0x58), XX(0x59), XX(0x5a), XX(0x5b),
  XX(0x5c), XX(0x5d), XX(0x5e), XX(0x5f),
  XX(0x60), XX(0x61), XX(0x62), XX(0x63),
  XX(0x64), XX(0x65), XX(0x66), XX(0x67),
  XX(0x68), XX(0x69), XX(0x6a), XX(0x6b),
  XX(0x6c), XX(0x6d), XX(0x6e), XX(0x6f),
  XX(0x70), XX(0x71), XX(0x72), XX(0x73),
  XX(0x74), XX(0x75), XX(0x76), XX(0x77),
  XX(0x78), XX(0x79), XX(0x7a), XX(0x7b),
  XX(0x7c), XX(0x7d), XX(0x7e), XX(0x7f),
#if CHAR_MIN >= 0
  XX(0x80), XX(0x81), XX(0x82), XX(0x83),
  XX(0x84), XX(0x85), XX(0x86), XX(0x87),
  XX(0x88), XX(0x89), XX(0x8a), XX(0x8b),
  XX(0x8c), XX(0x8d), XX(0x8e), XX(0x8f),
  XX(0x90), XX(0x91), XX(0x92), XX(0x93),
  XX(0x94), XX(0x95), XX(0x96), XX(0x97),
  XX(0x98), XX(0x99), XX(0x9a), XX(0x9b),
  XX(0x9c), XX(0x9d), XX(0x9e), XX(0x9f),
  XX(0xa0), XX(0xa1), XX(0xa2), XX(0xa3),
  XX(0xa4), XX(0xa5), XX(0xa6), XX(0xa7),
  XX(0xa8), XX(0xa9), XX(0xaa), XX(0xab),
  XX(0xac), XX(0xad), XX(0xae), XX(0xaf),
  XX(0xb0), XX(0xb1), XX(0xb2), XX(0xb3),
  XX(0xb4), XX(0xb5), XX(0xb6), XX(0xb7),
  XX(0xb8), XX(0xb9), XX(0xba), XX(0xbb),
  XX(0xbc), XX(0xbd), XX(0xbe), XX(0xbf),
  XX(0xc0), XX(0xc1), XX(0xc2), XX(0xc3),
  XX(0xc4), XX(0xc5), XX(0xc6), XX(0xc7),
  XX(0xc8), XX(0xc9), XX(0xca), XX(0xcb),
  XX(0xcc), XX(0xcd), XX(0xce), XX(0xcf),
  XX(0xd0), XX(0xd1), XX(0xd2), XX(0xd3),
  XX(0xd4), XX(0xd5), XX(0xd6), XX(0xd7),
  XX(0xd8), XX(0xd9), XX(0xda), XX(0xdb),
  XX(0xdc), XX(0xdd), XX(0xde), XX(0xdf),
  XX(0xe0), XX(0xe1), XX(0xe2), XX(0xe3),
  XX(0xe4), XX(0xe5), XX(0xe6), XX(0xe7),
  XX(0xe8), XX(0xe9), XX(0xea), XX(0xeb),
  XX(0xec), XX(0xed), XX(0xee), XX(0xef),
  XX(0xf0), XX(0xf1), XX(0xf2), XX(0xf3),
  XX(0xf4), XX(0xf5), XX(0xf6), XX(0xf7),
  XX(0xf8), XX(0xf9), XX(0xfa), XX(0xfb),
  XX(0xfc), XX(0xfd), XX(0xfe), XX(0xff)
#else
  XX(-0x80), XX(-0x7f), XX(-0x7e), XX(-0x7d),
  XX(-0x7c), XX(-0x7b), XX(-0x7a), XX(-0x79),
  XX(-0x78), XX(-0x77), XX(-0x76), XX(-0x75),
  XX(-0x74), XX(-0x73), XX(-0x72), XX(-0x71),
  XX(-0x70), XX(-0x6f), XX(-0x6e), XX(-0x6d),
  XX(-0x6c), XX(-0x6b), XX(-0x6a), XX(-0x69),
  XX(-0x68), XX(-0x67), XX(-0x66), XX(-0x65),
  XX(-0x64), XX(-0x63), XX(-0x62), XX(-0x61),
  XX(-0x60), XX(-0x5f), XX(-0x5e), XX(-0x5d),
  XX(-0x5c), XX(-0x5b), XX(-0x5a), XX(-0x59),
  XX(-0x58), XX(-0x57), XX(-0x56), XX(-0x55),
  XX(-0x54), XX(-0x53), XX(-0x52), XX(-0x51),
  XX(-0x50), XX(-0x4f), XX(-0x4e), XX(-0x4d),
  XX(-0x4c), XX(-0x4b), XX(-0x4a), XX(-0x49),
  XX(-0x48), XX(-0x47), XX(-0x46), XX(-0x45),
  XX(-0x44), XX(-0x43), XX(-0x42), XX(-0x41),
  XX(-0x40), XX(-0x3f), XX(-0x3e), XX(-0x3d),
  XX(-0x3c), XX(-0x3b), XX(-0x3a), XX(-0x39),
  XX(-0x38), XX(-0x37), XX(-0x36), XX(-0x35),
  XX(-0x34), XX(-0x33), XX(-0x32), XX(-0x31),
  XX(-0x30), XX(-0x2f), XX(-0x2e), XX(-0x2d),
  XX(-0x2c), XX(-0x2b), XX(-0x2a), XX(-0x29),
  XX(-0x28), XX(-0x27), XX(-0x26), XX(-0x25),
  XX(-0x24), XX(-0x23), XX(-0x22), XX(-0x21),
  XX(-0x20), XX(-0x1f), XX(-0x1e), XX(-0x1d),
  XX(-0x1c), XX(-0x1b), XX(-0x1a), XX(-0x19),
  XX(-0x18), XX(-0x17), XX(-0x16), XX(-0x15),
  XX(-0x14), XX(-0x13), XX(-0x12), XX(-0x11),
  XX(-0x10), XX(-0x0f), XX(-0x0e), XX(-0x0d),
  XX(-0x0c), XX(-0x0b), XX(-0x0a), XX(-0x09),
  XX(-0x08), XX(-0x07), XX(-0x06), XX(-0x05),
  XX(-0x04), XX(-0x03), XX(-0x02), XX(-0x01)
#endif
};

/*
 * ASCII->Native Map
 */

const int torsion__native[256] = {
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\a',
  '\b', '\t', '\n', '\v', '\f', '\r', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
   ' ',  '!',  '"',  '#',  '$',  '%',  '&', '\'',
   '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
   '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
   '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
   '@',  'A',  'B',  'C',  'D',  'E',  'F',  'G',
   'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
   'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
   'X',  'Y',  'Z',  '[', '\\',  ']',  '^',  '_',
   '`',  'a',  'b',  'c',  'd',  'e',  'f',  'g',
   'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
   'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
   'x',  'y',  'z',  '{',  '|',  '}',  '~', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'
};

#undef XX
