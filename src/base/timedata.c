/*!
 * timedata.c - timedata for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <base/timedata.h>
#include <mako/util.h>
#include "../impl.h"
#include "../internal.h"

/*
 * Prototypes
 */

static size_t
binary_insert(int64_t *samples, size_t length, int64_t sample);

/*
 * Time Data
 */

DEFINE_OBJECT(btc_timedata, SCOPE_EXTERN)

void
btc_timedata_init(btc_timedata_t *td) {
  memset(td, 0, sizeof(*td));
}

void
btc_timedata_clear(btc_timedata_t *td) {
  btc_timedata_init(td);
}

void
btc_timedata_copy(btc_timedata_t *z, const btc_timedata_t *x) {
  *z = *x;
}

int
btc_timedata_add(btc_timedata_t *td, int64_t ts) {
  int64_t sample;
  int ret = 1;

  if (td->length == lengthof(td->samples))
    return 1;

  sample = ts - btc_now();

  td->length = binary_insert(td->samples, td->length, sample);

  if (td->length >= 5 && td->length % 2 == 1) {
    int64_t median = td->samples[td->length >> 1];

    if (BTC_ABS(median) >= 70 * 60) {
      if (!td->checked) {
        int match = 0;
        size_t i;

        for (i = 0; i < td->length; i++) {
          int64_t offset = td->samples[i];

          if (offset != 0 && BTC_ABS(offset) < 5 * 60) {
            match = 1;
            break;
          }
        }

        if (!match) {
          td->checked = 1;
          ret = 0;
        }
      }

      median = 0;
    }

    td->offset = median;
  }

  return ret;
}

int64_t
btc_timedata_now(const btc_timedata_t *td) {
  if (td == NULL)
    return btc_now();

  return btc_now() + td->offset;
}

int64_t
btc_timedata_adjust(const btc_timedata_t *td, int64_t ts) {
  return ts + td->offset;
}

int64_t
btc_timedata_local(const btc_timedata_t *td, int64_t ts) {
  return ts - td->offset;
}

/*
 * Helpers
 */

static size_t
binary_insert(int64_t *samples, size_t length, int64_t sample) {
  int start = 0;
  int end = (int)length - 1;
  int64_t cmp;
  int i, pos;

  while (start <= end) {
    pos = (start + end) >> 1;
    cmp = samples[pos] - sample;

    if (cmp == 0) {
      start = pos;
      break;
    }

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  for (i = (int)length; i != start; i--)
    samples[i] = samples[i - 1];

  samples[start] = sample;

  return length + 1;
}
