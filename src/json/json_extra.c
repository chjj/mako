/*!
 * json_extra.c - extra json functions for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <string.h>
#include <satoshi/json.h>

/*
 * JSON Extras
 */

static json_object_entry *
json_object_find(const json_value *obj, const char *name) {
  const json_object_entry *entry;
  unsigned int i;

  if (obj->type != json_object)
    return NULL;

  for (i = 0; i < obj->u.object.length; i++) {
    entry = &obj->u.object.values[i];

    if (strcmp(entry->name, name) == 0)
      return (json_object_entry *)entry;
  }

  return NULL;
}

json_value *
json_object_get(const json_value *obj, const char *name) {
  json_object_entry *entry = json_object_find(obj, name);

  if (entry == NULL)
    return NULL;

  return entry->value;
}

json_value *
json_object_remove(json_value *obj, const char *name) {
  json_object_entry *entry = json_object_find(obj, name);
  json_value *value, *sentinel;

  if (entry == NULL)
    return NULL;

  value = entry->value;

  sentinel = json_null_new();
  sentinel->parent = value->parent;

  value->parent = NULL;

  entry->value = sentinel;

  return value;
}

json_char *
json_encode(json_value *value) {
  /* Note: json_measure includes the null terminator. */
  size_t len = json_measure(value);
  json_char *buf = malloc(len * sizeof(json_char));

  if (buf == NULL)
    abort(); /* LCOV_EXCL_LINE */

  json_serialize(buf, value);

  return buf;
}

json_char *
json_encode_ex(json_value *value, json_serialize_opts opts) {
  /* Note: json_measure includes the null terminator. */
  size_t len = json_measure_ex(value, opts);
  json_char *buf = malloc(len * sizeof(json_char));

  if (buf == NULL)
    abort(); /* LCOV_EXCL_LINE */

  json_serialize_ex(buf, value, opts);

  return buf;
}

json_value *
json_decode(const json_char *json, size_t length) {
  json_settings settings;

  memset(&settings, 0, sizeof(settings));

  settings.value_extra = json_builder_extra;

  return json_parse_ex(&settings, json, length, NULL);
}

json_value *
json_decode_ex(json_settings *settings,
               const json_char *json,
               size_t length,
               char *error_buf) {
  settings->value_extra = json_builder_extra;
  return json_parse_ex(settings, json, length, error_buf);
}

void
json_print(json_value *value, int (*json_puts)(const char *)) {
  char *buf = json_encode(value);

  json_puts(buf);
  free(buf);
}

void
json_print_ex(json_value *value,
              int (*json_puts)(const char *),
              json_serialize_opts opts) {
  char *buf = json_encode_ex(value, opts);

  json_puts(buf);
  free(buf);
}
