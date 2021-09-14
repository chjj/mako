static const unsigned char field_secp256k1_raw[FIELD_SIZE] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
};

#if MP_LIMB_BITS == 64
static const mp_limb_t field_secp256k1_p[REDUCE_LIMBS] = {
  UINT64_C(0xfffffffefffffc2f), UINT64_C(0xffffffffffffffff),
  UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff)
};
#else
static const mp_limb_t field_secp256k1_p[REDUCE_LIMBS] = {
  0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
};
#endif

#if defined(BTC_HAVE_INT128)
static const fe_t field_secp256k1_zero = {
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)
};

static const fe_t field_secp256k1_one = {
  UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)
};

static const fe_t field_secp256k1_two = {
  UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)
};

static const fe_t field_secp256k1_three = {
  UINT64_C(0x0000000000000003), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)
};

static const fe_t field_secp256k1_four = {
  UINT64_C(0x0000000000000004), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)
};

static const fe_t field_secp256k1_mone = {
  UINT64_C(0x000007fefffffc2e), UINT64_C(0x000007ffffffffff),
  UINT64_C(0x000003ffffffffff), UINT64_C(0x000007ffffffffff),
  UINT64_C(0x000007ffffffffff), UINT64_C(0x000003ffffffffff)
};
#else
static const fe_t field_secp256k1_zero = {
  0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const fe_t field_secp256k1_one = {
  0x00000001, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const fe_t field_secp256k1_two = {
  0x00000002, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const fe_t field_secp256k1_three = {
  0x00000003, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const fe_t field_secp256k1_four = {
  0x00000004, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const fe_t field_secp256k1_mone = {
  0x000813e6, 0x0002edc0, 0x0020918a, 0x00039056,
  0x00010147, 0x0016dd7d, 0x00076292, 0x001d4371,
  0x00063c69, 0x002bd3c3, 0x001cb587, 0x000b373c
};
#endif
