#if MP_LIMB_BITS == 64
static const mp_limb_t field_secq256k1_n[SCALAR_LIMBS] = {
  UINT64_C(0xbfd25e8cd0364141), UINT64_C(0xbaaedce6af48a03b),
  UINT64_C(0xfffffffffffffffe), UINT64_C(0xffffffffffffffff)
};

static const mp_limb_t field_secq256k1_nh[SCALAR_LIMBS] = {
  UINT64_C(0xdfe92f46681b20a0), UINT64_C(0x5d576e7357a4501d),
  UINT64_C(0xffffffffffffffff), UINT64_C(0x7fffffffffffffff)
};

static const mp_limb_t field_secq256k1_m[REDUCE_LIMBS - SCALAR_LIMBS + 1] = {
  UINT64_C(0xe697f5e45bcd07c7), UINT64_C(0x9d671cd581c69bc5),
  UINT64_C(0x402da1732fc9bec0), UINT64_C(0x4551231950b75fc4),
  UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
  UINT64_C(0x0000000000000001)
};

static const mp_limb_t field_secq256k1_k = UINT64_C(0x4b0dff665588b13f);

static const mp_limb_t field_secq256k1_r2[SCALAR_LIMBS] = {
  UINT64_C(0x896cf21467d7d140), UINT64_C(0x741496c20e7cf878),
  UINT64_C(0xe697f5e45bcd07c6), UINT64_C(0x9d671cd581c69bc5)
};

#else
static const mp_limb_t field_secq256k1_n[SCALAR_LIMBS] = {
  0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
  0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff
};

static const mp_limb_t field_secq256k1_nh[SCALAR_LIMBS] = {
  0x681b20a0, 0xdfe92f46, 0x57a4501d, 0x5d576e73,
  0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff
};

static const mp_limb_t field_secq256k1_m[REDUCE_LIMBS - SCALAR_LIMBS + 1] = {
  0x81c69bc5, 0x9d671cd5, 0x2fc9bec0, 0x402da173,
  0x50b75fc4, 0x45512319, 0x00000001, 0x00000000,
  0x00000000, 0x00000000, 0x00000001
};

static const mp_limb_t field_secq256k1_k = 0x5588b13f;

static const mp_limb_t field_secq256k1_r2[SCALAR_LIMBS] = {
  0x67d7d140, 0x896cf214, 0x0e7cf878, 0x741496c2,
  0x5bcd07c6, 0xe697f5e4, 0x81c69bc5, 0x9d671cd5
};

#endif
