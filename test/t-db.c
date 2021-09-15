#include <stddef.h>
#include <string.h>
#include <node/db.h>
#include "tests.h"

int main(void) {
  static const unsigned char key1[] = "foo";
  static const unsigned char key2[] = "bar";
  static const unsigned char key3[] = "baz";
  static const unsigned char val1[] = "one";
  static const unsigned char val2[] = "two";
  static const unsigned char val3[] = "three";
  unsigned char *val;
  size_t vlen;

  btc_db_t *db = btc_db_create();

  ASSERT(btc_db_open(db, "/tmp/btc_db_test", 10 << 20));

  ASSERT(btc_db_put(db, key1, sizeof(key1), val1, sizeof(val1)));
  ASSERT(btc_db_put(db, key2, sizeof(key2), val2, sizeof(val2)));
  ASSERT(btc_db_put(db, key3, sizeof(key3), val3, sizeof(val3)));

  ASSERT(btc_db_get(db, &val, &vlen, key1, sizeof(key1)));
  ASSERT(vlen == sizeof(val1) && memcmp(val, val1, vlen) == 0);

  ASSERT(btc_db_get(db, &val, &vlen, key2, sizeof(key2)));
  ASSERT(vlen == sizeof(val2) && memcmp(val, val2, vlen) == 0);

  ASSERT(btc_db_get(db, &val, &vlen, key3, sizeof(key3)));
  ASSERT(vlen == sizeof(val3) && memcmp(val, val3, vlen) == 0);

  btc_db_close(db);
  btc_db_destroy(db);

  return 0;
}
