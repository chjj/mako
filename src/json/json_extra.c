/*!
 * json_extra.c - extra json functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <mako/json.h>

/*
 * JSON Extras
 */

int
json_boolean_get(int *z, const json_value *obj) {
  if (obj->type == json_integer) {
    if (obj->u.integer != 0 && obj->u.integer != 1)
      return 0;

    *z = obj->u.integer;

    return 1;
  }

  if (obj->type == json_boolean) {
    *z = obj->u.boolean;
    return 1;
  }

  return 0;
}

int
json_signed_get(int *z, const json_value *obj) {
  if (obj->type == json_integer) {
    if (obj->u.integer < (INT_MIN / 2))
      return 0;

    if (obj->u.integer > (INT_MAX / 2))
      return 0;

    *z = obj->u.integer;

    return 1;
  }

  return 0;
}

int
json_unsigned_get(int *z, const json_value *obj) {
  if (obj->type == json_integer) {
    if (obj->u.integer < 0)
      return 0;

    if (obj->u.integer > (INT_MAX / 2))
      return 0;

    *z = obj->u.integer;

    return 1;
  }

  return 0;
}

int
json_uint32_get(uint32_t *z, const json_value *obj) {
  if (obj->type == json_integer) {
    if (obj->u.integer < 0)
      return 0;

    if (obj->u.integer > UINT32_MAX)
      return 0;

    *z = obj->u.integer;

    return 1;
  }

  return 0;
}

int
json_uint64_get(uint64_t *z, const json_value *obj) {
  if (obj->type == json_integer) {
    if (obj->u.integer < 0)
      return 0;

    *z = obj->u.integer;

    return 1;
  }

  return 0;
}

int
json_double_get(double *z, const json_value *obj) {
  if (obj->type == json_double) {
    *z = obj->u.dbl;
    return 1;
  }

  if (obj->type == json_integer) {
    *z = (double)obj->u.integer;
    return 1;
  }

  if (obj->type == json_amount) {
    *z = (double)obj->u.integer / 100000000.0;
    return 1;
  }

  return 0;
}

int
json_string_get(const char **z, const json_value *obj) {
  if (obj->type != json_string)
    return 0;

  if (strlen(obj->u.string.ptr) != obj->u.string.length)
    return 0;

  *z = obj->u.string.ptr;

  return 1;
}

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
json_object_pluck(json_value *obj, const char *name) {
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

  settings.settings = json_enable_amounts;
  settings.value_extra = json_builder_extra;

  return json_parse_ex(&settings, json, length, NULL);
}

json_value *
json_decode_ex(json_settings *settings,
               const json_char *json,
               size_t length,
               char *error_buf) {
  settings->settings |= json_enable_amounts;
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
