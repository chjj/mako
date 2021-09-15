/*!
 * db.c - leveldb wrapper for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdio.h>
#include <leveldb/c.h>
#include <node/db.h>
#include "../internal.h"

/*
 * Types
 */

struct btc_db_s {
  leveldb_options_t *options;
  leveldb_readoptions_t *read_options;
  leveldb_writeoptions_t *write_options;
  leveldb_t *level;
};

struct btc_batch_s {
  leveldb_writebatch_t *wb;
};

struct btc_iter_s {
  leveldb_t *level;
  leveldb_readoptions_t *options;
  const leveldb_snapshot_t *snapshot;
  leveldb_iterator_t *it;
};

/*
 * Database
 */

struct btc_db_s *
btc_db_create(void) {
  leveldb_options_t *options = leveldb_options_create();
  leveldb_cache_t *cache = leveldb_cache_create_lru(8 << 20);
  leveldb_filterpolicy_t *bloom = leveldb_filterpolicy_create_bloom(10);
  leveldb_readoptions_t *read_options = leveldb_readoptions_create();
  leveldb_writeoptions_t *write_options = leveldb_writeoptions_create();
  struct btc_db_s *db = (struct btc_db_s *)malloc(sizeof(struct btc_db_s *));

  CHECK(db != NULL);

  leveldb_options_set_create_if_missing(options, 1);
  leveldb_options_set_error_if_exists(options, 0);
  leveldb_options_set_compression(options, leveldb_snappy_compression);
  leveldb_options_set_cache(options, cache);
  leveldb_options_set_write_buffer_size(options, 4 << 20);
  leveldb_options_set_block_size(options, 4096);
  leveldb_options_set_max_open_files(options, 1000);
  leveldb_options_set_block_restart_interval(options, 16);
  leveldb_options_set_max_file_size(options, 2 << 20);
  leveldb_options_set_filter_policy(options, bloom);
  leveldb_options_set_paranoid_checks(options, 0);

  leveldb_readoptions_set_verify_checksums(read_options, 0);
  leveldb_readoptions_set_fill_cache(read_options, 1);

  leveldb_writeoptions_set_sync(write_options, 0);

  db->options = options;
  db->read_options = read_options;
  db->write_options = write_options;
  db->level = NULL;

  return db;
}

int
btc_db_open(struct btc_db_s *db, const char *path, size_t map_size) {
  char *err = NULL;

  (void)map_size;

  db->level = leveldb_open(db->options, path, &err);

  if (err != NULL) {
    CHECK(db->level == NULL);

    fprintf(stderr, "leveldb_open: %s\n", err);

    free(err);

    return 0;
  }

  CHECK(db->level != NULL);

  return 1;
}

void
btc_db_close(struct btc_db_s *db) {
  leveldb_close(db->level);
  db->level = NULL;
}

void
btc_db_destroy(struct btc_db_s *db) {
  if (db->level != NULL)
    leveldb_close(db->level);

  leveldb_options_destroy(db->options);
  leveldb_readoptions_destroy(db->read_options);
  leveldb_writeoptions_destroy(db->write_options);

  free(db);
}

int
btc_db_get(struct btc_db_s *db, unsigned char **val, size_t *vlen,
                                const unsigned char *key, size_t klen) {
  char *err = NULL;

  *val = (unsigned char *)leveldb_get(db->level,
                                      db->read_options,
                                      (const char *)key,
                                      klen,
                                      vlen,
                                      &err);

  if (err != NULL) {
    fprintf(stderr, "leveldb_get: %s\n", err);
    free(err);
    return 0;
  }

  return *val != NULL;
}

int
btc_db_put(struct btc_db_s *db, const unsigned char *key, size_t klen,
                                const unsigned char *val, size_t vlen) {
  char *err = NULL;

  leveldb_put(db->level, db->write_options,
              (const char *)key, klen,
              (const char *)val, vlen,
              &err);

  if (err != NULL) {
    fprintf(stderr, "leveldb_put: %s\n", err);
    free(err);
    return 0;
  }

  return 1;
}

int
btc_db_del(struct btc_db_s *db, const unsigned char *key, size_t klen) {
  char *err = NULL;

  leveldb_delete(db->level, db->write_options,
                 (const char *)key, klen,
                 &err);

  if (err != NULL) {
    fprintf(stderr, "leveldb_delete: %s\n", err);
    free(err);
    return 0;
  }

  return 1;
}

int
btc_db_write(struct btc_db_s *db, struct btc_batch_s *bat) {
  char *err = NULL;

  leveldb_write(db->level, db->write_options, bat->wb, &err);

  if (err != NULL) {
    fprintf(stderr, "leveldb_write: %s\n", err);
    free(err);
    return 0;
  }

  return 1;
}

/*
 * Batch
 */

struct btc_batch_s *
btc_batch_create(struct btc_db_s *db) {
  struct btc_batch_s *bat =
    (struct btc_batch_s *)malloc(sizeof(struct btc_batch_s));

  (void)db;

  CHECK(bat != NULL);

  bat->wb = leveldb_writebatch_create();

  return bat;
}

void
btc_batch_destroy(struct btc_batch_s *bat) {
  leveldb_writebatch_destroy(bat->wb);
  free(bat);
}

void
btc_batch_put(struct btc_batch_s *bat, const unsigned char *key, size_t klen,
                                       const unsigned char *val, size_t vlen) {
  leveldb_writebatch_put(bat->wb, (const char *)key, klen,
                                  (const char *)val, vlen);
}

void
btc_batch_del(struct btc_batch_s *bat, const unsigned char *key, size_t klen) {
  leveldb_writebatch_delete(bat->wb, (const char *)key, klen);
}

/*
 * Iterator
 */

struct btc_iter_s *
btc_iter_create(struct btc_db_s *db, int use_snapshot) {
  struct btc_iter_s *iter =
    (struct btc_iter_s *)malloc(sizeof(struct btc_iter_s));

  CHECK(iter != NULL);

  iter->level = db->level;
  iter->options = leveldb_readoptions_create();
  iter->snapshot = NULL;

  leveldb_readoptions_set_verify_checksums(iter->options, 0);
  leveldb_readoptions_set_fill_cache(iter->options, 0);

  if (use_snapshot) {
    iter->snapshot = leveldb_create_snapshot(db->level);
    leveldb_readoptions_set_snapshot(iter->options, iter->snapshot);
  }

  iter->it = leveldb_create_iterator(db->level, iter->options);

  return iter;
}

void
btc_iter_destroy(struct btc_iter_s *iter) {
  leveldb_iter_destroy(iter->it);

  if (iter->snapshot != NULL)
    leveldb_release_snapshot(iter->level, iter->snapshot);

  leveldb_readoptions_destroy(iter->options);

  free(iter);
}

int
btc_iter_valid(const struct btc_iter_s *iter) {
  return leveldb_iter_valid(iter->it);
}

void
btc_iter_seek_first(struct btc_iter_s *iter) {
  leveldb_iter_seek_to_first(iter->it);
}

void
btc_iter_seek_last(struct btc_iter_s *iter) {
  leveldb_iter_seek_to_last(iter->it);
}

void
btc_iter_seek(struct btc_iter_s *iter, const unsigned char *key, size_t klen) {
  leveldb_iter_seek(iter->it, (const char *)key, klen);
}

void
btc_iter_next(struct btc_iter_s *iter) {
  leveldb_iter_next(iter->it);
}

void
btc_iter_prev(struct btc_iter_s *iter) {
  leveldb_iter_prev(iter->it);
}

const unsigned char *
btc_iter_key(const struct btc_iter_s *iter, size_t *klen) {
  return (const unsigned char *)leveldb_iter_key(iter->it, klen);
}

const unsigned char *
btc_iter_val(const struct btc_iter_s *iter, size_t *vlen) {
  return (const unsigned char *)leveldb_iter_value(iter->it, vlen);
}

int
btc_iter_check(const struct btc_iter_s *iter) {
  char *err = NULL;

  leveldb_iter_get_error(iter->it, &err);

  if (err != NULL) {
    fprintf(stderr, "leveldb_iter_get_error: %s\n", err);
    free(err);
    return 0;
  }

  return 1;
}

/*
 * Util
 */

void
btc_db_free(void *ptr) {
  leveldb_free(ptr);
}
