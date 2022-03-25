/*!
 * watcom_dns.h - dns fix for open watcom
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <unistd.h>

/*
 * DNS
 */

static uint8_t *
dns_uint8_write(uint8_t *zp, uint8_t x) {
  *zp++ = x;
  return zp;
}

static uint8_t *
dns_uint16_write(uint8_t *zp, uint16_t x) {
  *zp++ = (x >> 8);
  *zp++ = (x >> 0);
  return zp;
}

static int
dns_uint16_read(uint16_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 2)
    return 0;

  *zp = ((uint16_t)(*xp)[0] << 8)
      | ((uint16_t)(*xp)[1] << 0);

  *xp += 2;
  *xn -= 2;

  return 1;
}

static uint8_t *
dns_size_write(uint8_t *zp, size_t x) {
  return dns_uint16_write(zp, x);
}

static int
dns_size_read(size_t *zp, const uint8_t **xp, size_t *xn) {
  uint16_t z;

  if (!dns_uint16_read(&z, xp, xn))
    return 0;

  *zp = z;

  return 1;
}

static int
dns_zraw_read(const uint8_t **zp, size_t zn,
              const uint8_t **xp, size_t *xn) {
  if (*xn < zn)
    return 0;

  *zp = *xp;
  *xp += zn;
  *xn -= zn;

  return 1;
}

static int
dns_skip_read(size_t zn, const uint8_t **xp, size_t *xn) {
  if (*xn < zn)
    return 0;

  *xp += zn;
  *xn -= zn;

  return 1;
}

static int
next_label(char *label, const char **name) {
  int pos = 0;

  while (**name) {
    int ch = **name;

    *name += 1;

    if (ch == '.')
      break;

    if (pos == 63)
      return -1;

    label[pos++] = ch;
  }

  label[pos] = '\0';

  return pos;
}

static int
dns_name_encode(uint8_t *zp, const char *name) {
  char label[64];
  int zn = 0;
  int i, len;

  while ((len = next_label(label, &name))) {
    if (len < 0 || zn + 1 + len > 255)
      return 0;

    zp[zn++] = len;

    for (i = 0; i < len; i++)
      zp[zn++] = label[i];
  }

  while (*name && *name == '.')
    name++;

  if (*name != '\0')
    return 0;

  zp[zn++] = 0x00;

  return zn;
}

static int
dns_name_verify(const char *name) {
  uint8_t zp[256];
  return dns_name_encode(zp, name);
}

static uint8_t *
dns_name_write(uint8_t *zp, const char *name) {
  return zp + dns_name_encode(zp, name);
}

static int
dns_name_read(const uint8_t **xp, size_t *xn, const uint8_t *data) {
  int off = *xp - data;
  int len = off + *xn;
  int nlen = 0;
  int res = 0;
  int ptr = 0;
  int c0, c1;

  for (;;) {
    if (off >= len)
      return 0;

    c0 = data[off++];

    if (c0 == 0x00)
      break;

    switch (c0 & 0xc0) {
      case 0x00: {
        if (c0 > 63)
          return 0;

        off += c0;

        if (off > len)
          return 0;

        nlen += 1 + c0;

        if (nlen > 255)
          return 0;

        break;
      }

      case 0xc0: {
        if (off >= len)
          return 0;

        c1 = data[off++];

        if (ptr == 0)
          res = off;

        if (++ptr > 10)
          return 0;

        off = ((c0 ^ 0xc0) << 8) | c1;

        break;
      }

      default: {
        return 0;
      }
    }
  }

  if (ptr == 0)
    res = off;

  *xp = data + res;
  *xn = len - res;

  return 1;
}

static uint8_t *
dns_msg_write(uint8_t *zp, const char *name) {
  /* Header */
  zp = dns_uint16_write(zp, rand() & 0xffff);
  zp = dns_uint16_write(zp, (1 << 8)); /* RD */
  zp = dns_size_write(zp, 1);
  zp = dns_size_write(zp, 0);
  zp = dns_size_write(zp, 0);
  zp = dns_size_write(zp, 1);

  /* Question */
  zp = dns_name_write(zp, name);
  zp = dns_uint16_write(zp, 1); /* A */
  zp = dns_uint16_write(zp, 1); /* CLASS_IN */

  /* EDNS */
  zp = dns_uint8_write(zp, 0); /* name */
  zp = dns_uint16_write(zp, 41); /* OPT */
  zp = dns_uint16_write(zp, 512); /* class */
  zp = dns_uint8_write(zp, 0); /* ttl [0-8] */
  zp = dns_uint8_write(zp, 0); /* ttl [8-16] */
  zp = dns_uint16_write(zp, 0); /* ttl [16-32] */
  zp = dns_size_write(zp, 0);

  return zp;
}

static int
dns_msg_read(char **zp, const uint8_t **xp, size_t *xn) {
  const uint8_t *sp = *xp;
  size_t i, qdc, anc, rn;
  const uint8_t *rp;
  uint16_t type;
  size_t zn = 0;

  if (!dns_skip_read(4, xp, xn))
    return 0;

  if (!dns_size_read(&qdc, xp, xn))
    return 0;

  if (!dns_size_read(&anc, xp, xn))
    return 0;

  if (!dns_skip_read(4, xp, xn))
    return 0;

  for (i = 0; i < qdc; i++) {
    if (!dns_name_read(xp, xn, sp))
      return 0;

    if (!dns_skip_read(4, xp, xn))
      return 0;
  }

  for (i = 0; i < anc; i++) {
    if (!dns_name_read(xp, xn, sp))
      return 0;

    if (!dns_uint16_read(&type, xp, xn))
      return 0;

    if (!dns_skip_read(6, xp, xn))
      return 0;

    if (!dns_size_read(&rn, xp, xn))
      return 0;

    if (!dns_zraw_read(&rp, rn, xp, xn))
      return 0;

    if (type != 1)
      continue;

    if (rn != 4)
      return 0;

    zp[zn++] = (char *)rp;
  }

  zp[zn] = NULL;

  return 1;
}

static int
dns_resolve(char **addrs, const char *name) {
  socklen_t slen = sizeof(struct sockaddr_in);
  static uint8_t msg[512];
  struct sockaddr_in dst;
  const uint8_t *xp;
  size_t zn, xn;
  uint8_t *zp;
  int fd, rc;

  if (!dns_name_verify(name))
    return 0;

  fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (fd < 0)
    return 0;

  memset(&dst, 0, sizeof(dst));

  dst.sin_family = AF_INET;
  dst.sin_port = htons(53);
  dst.sin_addr.s_addr = htonl(0x01010101);

  zp = dns_msg_write(msg, name);
  zn = zp - msg;

  rc = sendto(fd, msg, zn, 0, (struct sockaddr *)&dst, slen);

  if (rc < 0) {
    close(fd);
    return 0;
  }

  rc = recvfrom(fd, msg, 512, 0, (struct sockaddr *)&dst, &slen);

  if (rc <= 0 || rc > 512) {
    close(fd);
    return 0;
  }

  close(fd);

  xp = msg;
  xn = rc;

  return dns_msg_read(addrs, &xp, &xn);
}

static char *
name_normal(char *zp, const char *xp) {
  int len = 0;

  while (xp[len]) {
    zp[len] = xp[len] | 32;
    len++;
  }

  while (len > 0 && zp[len - 1] == '.')
    len--;

  zp[len] = '\0';

  return zp;
}

static int
name_local(const char *name) {
  char host[256];

  if (strcmp(name, "localhost") == 0)
    return 1;

  if (gethostname(host, sizeof(host)) == -1)
    return 0;

  return strcmp(name, name_normal(host, host)) == 0;
}

static struct hostent *
watcom_gethostbyname(const char *name) {
  static char h_name[256] = {0};
  static char *h_aliases[1] = {NULL};
  static char *h_addr_list[64] = {NULL};
  static struct hostent entry = {h_name,
                                 h_aliases,
                                 AF_INET, 4,
                                 h_addr_list};

  if (strlen(name) + 1 > sizeof(h_name))
    return NULL;

  name_normal(h_name, name);

  if (name_local(h_name)) {
    static char h_addr_local[4] = {127, 0, 0, 1};

    entry.h_addr_list[0] = h_addr_local;
    entry.h_addr_list[1] = NULL;

    return &entry;
  }

  if (!dns_resolve(h_addr_list, name))
    return NULL;

  return &entry;
}

#define gethostbyname watcom_gethostbyname
