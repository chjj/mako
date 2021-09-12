/*!
 * entropy.h - entropy sources for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_ENTROPY_H
#define TORSION_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Alias
 */

#define torsion_has_rdrand torsion__has_rdrand
#define torsion_has_rdseed torsion__has_rdseed
#define torsion_rdrand32 torsion__rdrand32
#define torsion_rdseed32 torsion__rdseed32
#define torsion_rdrand64 torsion__rdrand64
#define torsion_rdseed64 torsion__rdseed64
#define torsion_hwrand torsion__hwrand
#define torsion_getpid torsion__getpid
#define torsion_has_sysrand torsion__has_sysrand
#define torsion_sysrand torsion__sysrand

/*
 * Entropy
 */

int
torsion_has_rdrand(void);

int
torsion_has_rdseed(void);

uint32_t
torsion_rdrand32(void);

uint32_t
torsion_rdseed32(void);

uint64_t
torsion_rdrand64(void);

uint64_t
torsion_rdseed64(void);

int
torsion_hwrand(void *dst, size_t size);

long
torsion_getpid(void);

int
torsion_has_sysrand(void);

int
torsion_sysrand(void *dst, size_t size);

#endif /* TORSION_ENTROPY_H */
