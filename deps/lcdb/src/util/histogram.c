/*!
 * histogram.c - histogram for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <stdio.h>
#include <math.h>

#include "histogram.h"

/*
 * Constants
 */

static const double bucket_limit[NUM_BUCKETS] = {
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    12,
    14,
    16,
    18,
    20,
    25,
    30,
    35,
    40,
    45,
    50,
    60,
    70,
    80,
    90,
    100,
    120,
    140,
    160,
    180,
    200,
    250,
    300,
    350,
    400,
    450,
    500,
    600,
    700,
    800,
    900,
    1000,
    1200,
    1400,
    1600,
    1800,
    2000,
    2500,
    3000,
    3500,
    4000,
    4500,
    5000,
    6000,
    7000,
    8000,
    9000,
    10000,
    12000,
    14000,
    16000,
    18000,
    20000,
    25000,
    30000,
    35000,
    40000,
    45000,
    50000,
    60000,
    70000,
    80000,
    90000,
    100000,
    120000,
    140000,
    160000,
    180000,
    200000,
    250000,
    300000,
    350000,
    400000,
    450000,
    500000,
    600000,
    700000,
    800000,
    900000,
    1000000,
    1200000,
    1400000,
    1600000,
    1800000,
    2000000,
    2500000,
    3000000,
    3500000,
    4000000,
    4500000,
    5000000,
    6000000,
    7000000,
    8000000,
    9000000,
    10000000,
    12000000,
    14000000,
    16000000,
    18000000,
    20000000,
    25000000,
    30000000,
    35000000,
    40000000,
    45000000,
    50000000,
    60000000,
    70000000,
    80000000,
    90000000,
    100000000,
    120000000,
    140000000,
    160000000,
    180000000,
    200000000,
    250000000,
    300000000,
    350000000,
    400000000,
    450000000,
    500000000,
    600000000,
    700000000,
    800000000,
    900000000,
    1000000000,
    1200000000,
    1400000000,
    1600000000,
    1800000000,
    2000000000,
    2500000000.0,
    3000000000.0,
    3500000000.0,
    4000000000.0,
    4500000000.0,
    5000000000.0,
    6000000000.0,
    7000000000.0,
    8000000000.0,
    9000000000.0,
    1e200,
};

/*
 * Histogram
 */

void
histogram_init(histogram_t *h) {
  int i;

  h->min = bucket_limit[NUM_BUCKETS - 1];
  h->max = 0;
  h->num = 0;
  h->sum = 0;
  h->sum_squares = 0;

  for (i = 0; i < NUM_BUCKETS; i++)
    h->buckets[i] = 0;
}

void
histogram_add(histogram_t *h, double value) {
  /* Linear search is fast enough for our usage in db_bench. */
  int b = 0;

  while (b < NUM_BUCKETS - 1 && bucket_limit[b] <= value)
    b++;

  h->buckets[b] += 1.0;

  if (h->min > value)
    h->min = value;

  if (h->max < value)
    h->max = value;

  h->num++;
  h->sum += value;
  h->sum_squares += (value * value);
}

void
histogram_merge(histogram_t *z, const histogram_t *x) {
  int b;

  if (x->min < z->min)
    z->min = x->min;

  if (x->max > z->max)
    z->max = x->max;

  z->num += x->num;
  z->sum += x->sum;
  z->sum_squares += x->sum_squares;

  for (b = 0; b < NUM_BUCKETS; b++)
    z->buckets[b] += x->buckets[b];
}

static double
histogram_percentile(const histogram_t *h, double p) {
  double threshold = h->num * (p / 100.0);
  double sum = 0;
  int b;

  for (b = 0; b < NUM_BUCKETS; b++) {
    sum += h->buckets[b];

    if (sum >= threshold) {
      /* Scale linearly within this bucket. */
      double left_point = (b == 0) ? 0 : bucket_limit[b - 1];
      double right_point = bucket_limit[b];
      double left_sum = sum - h->buckets[b];
      double right_sum = sum;
      double pos = (threshold - left_sum) / (right_sum - left_sum);
      double r = left_point + (right_point - left_point) * pos;

      if (r < h->min)
        r = h->min;

      if (r > h->max)
        r = h->max;

      return r;
    }
  }

  return h->max;
}

static double
histogram_median(const histogram_t *h) {
  return histogram_percentile(h, 50.0);
}

static double
histogram_average(const histogram_t *h) {
  if (h->num == 0.0)
    return 0;

  return h->sum / h->num;
}

static double
histogram_standard_deviation(const histogram_t *h) {
  double variance;

  if (h->num == 0.0)
    return 0;

  variance = (h->sum_squares * h->num - h->sum * h->sum) / (h->num * h->num);

  return sqrt(variance);
}

char *
histogram_string(const histogram_t *h, char *buf) {
  double mult = 100.0 / h->num;
  double sum = 0;
  char *zp = buf;
  int b, marks;

  zp += sprintf(zp, "Count: %.0f  Average: %.4f  StdDev: %.2f\n",
                    h->num, histogram_average(h),
                    histogram_standard_deviation(h));

  zp += sprintf(zp, "Min: %.4f  Median: %.4f  Max: %.4f\n",
                    (h->num == 0.0 ? 0.0 : h->min),
                    histogram_median(h), h->max);

  zp += sprintf(zp,
    "------------------------------------------------------\n");

  for (b = 0; b < NUM_BUCKETS; b++) {
    if (h->buckets[b] <= 0.0)
      continue;

    sum += h->buckets[b];

    zp += sprintf(zp, "[ %7.0f, %7.0f ) %7.0f %7.3f%% %7.3f%% ",
                      ((b == 0) ? 0.0 : bucket_limit[b - 1]),  /* left */
                      bucket_limit[b],                         /* right */
                      h->buckets[b],                           /* count */
                      mult * h->buckets[b],                    /* percentage */
                      mult * sum); /* cumulative percentage */

    /* Add hash marks based on percentage; 20 marks for 100%. */
    marks = (int)(20 * (h->buckets[b] / h->num) + 0.5);

    while (marks--)
      *zp++ = '#';

    *zp++ = '\n';
  }

  *zp = '\0';

  return buf;
}
