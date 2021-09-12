/*!
 * hw.c - hardware entropy for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/CPUID
 *   https://en.wikipedia.org/wiki/RDRAND
 *
 * Windows (x86, x64):
 *   https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
 *   https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=_rdrand32_step
 *   https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=_rdrand64_step
 *   https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=_rdseed32_step
 *   https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=_rdseed64_step
 *
 * Windows (arm64):
 *   https://docs.microsoft.com/en-us/cpp/intrinsics/arm64-intrinsics
 *
 * x86{,-64} (rdtsc, rdrand, rdseed):
 *   https://www.felixcloutier.com/x86/cpuid
 *   https://www.felixcloutier.com/x86/rdrand
 *   https://www.felixcloutier.com/x86/rdseed
 *
 * ARMv8.5-A (cntvct, rndr, rndrrs):
 *   https://developer.arm.com/documentation/dui0068/b/ARM-Instruction-Reference/Miscellaneous-ARM-instructions/MRS
 *   https://developer.arm.com/documentation/ddi0595/2021-03/AArch64-Registers/ID-AA64ISAR0-EL1--AArch64-Instruction-Set-Attribute-Register-0
 *   https://developer.arm.com/documentation/ddi0595/2021-03/AArch64-Registers/RNDR--Random-Number
 *   https://developer.arm.com/documentation/ddi0595/2021-03/AArch64-Registers/RNDRRS--Reseeded-Random-Number
 *
 * POWER9/POWER10 (mftb, darn):
 *   https://openpowerfoundation.org/?resource_lib=power-isa-version-3-0
 *   https://stackoverflow.com/questions/5425506
 *
 * RISC-V (sentropy, pollentropy, rdcycle):
 *   https://github.com/riscv/riscv-isa-manual/releases
 *   https://github.com/riscv/riscv-crypto/releases
 */

/**
 * Hardware Entropy
 *
 * x86{,-64} offers hardware entropy in the form of RDRAND
 * and RDSEED. There are concerns that these instructions may
 * be backdoored in some way. This is not an issue as we only
 * use hardware entropy to supplement our full entropy pool.
 *
 * On POWER9 and POWER10, the `darn` (Deliver A Random Number)
 * instruction is available. We have `torsion_rdrand` as well
 * as `torsion_rdseed` return the output of `darn` if this is
 * the case.
 *
 * ARMv8.5-A provides new system registers (RNDR and RNDRRS)
 * to be used with the MRS instruction. Similar to `darn`, we
 * have `torsion_{rdrand,rdseed}` output the proper values.
 *
 * The very bleeding edge of RISC-V specifies `pollentropy`,
 * a pseudo-instruction which reads from a special `sentropy`
 * register, similar to ARM. We have preliminary support for
 * this. `sentropy` can only be read in machine mode (and
 * optionally supervisor mode) as of right now, but this may
 * change in the future[1] (hopefully).
 *
 * For other hardware, torsion_rdrand and torsion_rdseed are
 * no-ops returning zero. torsion_has_rd{rand,seed} MUST be
 * checked before calling torsion_rd{rand,seed}.
 *
 * [1] https://github.com/riscv/riscv-crypto/issues/90
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "entropy.h"
#include "../internal.h"

/*
 * Options
 */

#undef HAVE_MACHINE /* Define if RISC-V code is in machine mode. */

/*
 * Backend
 */

#undef HAVE_CPUIDEX
#undef HAVE_RDRAND
#undef HAVE_RDRAND32
#undef HAVE_RDRAND64
#undef HAVE_RDSEED
#undef HAVE_RDSEED32
#undef HAVE_RDSEED64
#undef HAVE_ASM_INTEL
#undef HAVE_ASM_X86
#undef HAVE_ASM_X64
#undef HAVE_ASM_ARM64
#undef HAVE_ASM_PPC
#undef HAVE_ASM_PPC32
#undef HAVE_ASM_PPC64
#undef HAVE_ASM_RISCV
#undef HAVE_ASM_RISCV32
#undef HAVE_ASM_RISCV64
#undef HAVE_GETAUXVAL
#undef HAVE_ELF_AUX_INFO
#undef HAVE_POWER_SET
#undef HAVE_AUXVAL

/* Detect intrinsic and ASM support. */
#if defined(TORSION_MSVC)
#  if defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64)
#    if _MSC_VER >= 1600 /* VS 2010 */
#      include <intrin.h> /* __cpuidex */
#      pragma intrinsic(__cpuidex)
#      define HAVE_CPUIDEX
#    endif
#    if _MSC_VER >= 1700 /* VS 2012 */
#      include <immintrin.h> /* _rd{rand,seed}{32,64}_step */
#      define HAVE_RDRAND
#      if defined(_M_AMD64) || defined(_M_X64)
#        define HAVE_RDRAND64
#      else
#        define HAVE_RDRAND32
#      endif
#    endif
#    if _MSC_VER >= 1800 /* VS 2013 */
#      define HAVE_RDSEED
#      if defined(_M_AMD64) || defined(_M_X64)
#        define HAVE_RDSEED64
#      else
#        define HAVE_RDSEED32
#      endif
#    endif
#  endif
#elif defined(TORSION_HAVE_ASM)
#  if defined(__amd64__) || defined(__amd64) \
   || defined(__x86_64__) || defined(__x86_64)
#    define HAVE_ASM_INTEL
#    define HAVE_ASM_X64
#  elif defined(__i386__) || defined(__i386) || defined(i386)
#    define HAVE_ASM_INTEL
#    define HAVE_ASM_X86
#  elif defined(__aarch64__)
#    define HAVE_ASM_ARM64
#  elif defined(__powerpc64__) || (defined(__PPC__) && defined(__64BIT__))
#    define HAVE_ASM_PPC
#    define HAVE_ASM_PPC64
#  elif defined(__powerpc__) || defined(__PPC__)
#    define HAVE_ASM_PPC
#    define HAVE_ASM_PPC32
#  elif defined(__riscv) && defined(__riscv_xlen) && defined(HAVE_MACHINE)
#    if __riscv_xlen == 32
#      define HAVE_ASM_RISCV
#      define HAVE_ASM_RISCV32
#      define riscv_word_t uint32_t
#    elif __riscv_xlen == 64
#      define HAVE_ASM_RISCV
#      define HAVE_ASM_RISCV64
#      define riscv_word_t uint64_t
#    endif
#  endif
#endif

/* Determine step word width. */
#if defined(HAVE_RDRAND64)  \
 || defined(HAVE_ASM_X64)   \
 || defined(HAVE_ASM_ARM64) \
 || defined(HAVE_ASM_PPC64)
#  define step_word_t uint64_t
#  define step_word_size 64
#elif defined(HAVE_ASM_RISCV)
#  define step_word_t uint16_t
#  define step_word_size 16
#else
#  define step_word_t uint32_t
#  define step_word_size 32
#endif

/* Some insanity to detect features at runtime. */
#if defined(HAVE_ASM_ARM64) || defined(HAVE_ASM_PPC)
#  if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 16)
#      include <errno.h> /* errno */
#      include <sys/auxv.h> /* getauxval */
#      define HAVE_GETAUXVAL
#      define HAVE_AUXVAL
#    endif
#  elif defined(__FreeBSD__)
#    include <sys/param.h>
#    if defined(__FreeBSD_version) && __FreeBSD_version >= 1200000 /* 12.0 */
#      include <errno.h> /* errno */
#      include <sys/auxv.h> /* elf_aux_info */
#      define HAVE_ELF_AUX_INFO
#      define HAVE_AUXVAL
#    endif
#  elif defined(HAVE_ASM_PPC) && defined(_AIX53) && !defined(__PASE__)
#    include <sys/systemcfg.h> /* __power_set */
#    if defined(__power_set)
#      define torsion_power_set __power_set
#    else
#      define torsion_power_set(x) (_system_configuration.implementation & (x))
#    endif
#    define HAVE_POWER_SET
#  endif
#  ifdef HAVE_AUXVAL
#    ifndef AT_HWCAP
#      define AT_HWCAP 16
#    endif
#    ifndef AT_HWCAP2
#      define AT_HWCAP2 26
#    endif
#  endif
#endif

/*
 * Auxiliary Value
 */

TORSION_UNUSED static unsigned long
torsion_auxval(unsigned long type) {
#if defined(HAVE_GETAUXVAL)
  int oldno = errno;
  unsigned long val;

  val = getauxval(type);
  errno = oldno;

  return val;
#elif defined(HAVE_ELF_AUX_INFO)
  int oldno = errno;
  unsigned long val;

  if (elf_aux_info(type, &val, sizeof(val)) != 0)
    val = 0;

  errno = oldno;

  return val;
#else
  (void)type;
  return 0;
#endif
}

/*
 * CPUID
 */

TORSION_UNUSED static int
torsion_has_cpuid(void) {
#if defined(HAVE_CPUIDEX)
  return 1;
#elif defined(HAVE_ASM_X86)
  uint32_t ax, bx;

  __asm__ __volatile__ (
    "pushfl\n"
    "pushfl\n"
    "popl %k0\n"
    "movl %k0, %k1\n"
    "xorl $0x200000, %k0\n"
    "pushl %k0\n"
    "popfl\n"
    "pushfl\n"
    "popl %k0\n"
    "popfl\n"
    : "=&r" (ax),
      "=&r" (bx)
    :: "cc"
  );

  return ((ax ^ bx) >> 21) & 1;
#elif defined(HAVE_ASM_X64)
  return 1;
#else
  return 0;
#endif
}

TORSION_UNUSED static void
torsion_cpuid(uint32_t *a,
              uint32_t *b,
              uint32_t *c,
              uint32_t *d,
              uint32_t leaf,
              uint32_t subleaf) {
#if defined(HAVE_CPUIDEX)
  unsigned int regs[4];

  __cpuidex((int *)regs, leaf, subleaf);

  *a = regs[0];
  *b = regs[1];
  *c = regs[2];
  *d = regs[3];
#elif defined(HAVE_ASM_X86)
  if (torsion_has_cpuid()) {
    __asm__ __volatile__ (
      "xchgl %%ebx, %k1\n"
      "cpuid\n"
      "xchgl %%ebx, %k1\n"
      : "=a" (*a), "=&r" (*b), "=c" (*c), "=d" (*d)
      : "0" (leaf), "2" (subleaf)
    );
  } else {
    *a = 0;
    *b = 0;
    *c = 0;
    *d = 0;
  }
#elif defined(HAVE_ASM_X64)
  __asm__ __volatile__ (
    "xchgq %%rbx, %q1\n"
    "cpuid\n"
    "xchgq %%rbx, %q1\n"
    : "=a" (*a), "=&r" (*b), "=c" (*c), "=d" (*d)
    : "0" (leaf), "2" (subleaf)
  );
#else
  (void)leaf;
  (void)subleaf;

  *a = 0;
  *b = 0;
  *c = 0;
  *d = 0;
#endif
}

/*
 * Pause
 */

#if defined(HAVE_RDSEED32)
#  define torsion_pause() _asm { rep nop }
#elif defined(HAVE_RDSEED64)
#  define torsion_pause _mm_pause
#elif defined(HAVE_ASM_X86)
#  define torsion_pause() __asm__ __volatile__ ("rep\n" "nop\n" ::: "memory")
#elif defined(HAVE_ASM_X64)
#  define torsion_pause() __asm__ __volatile__ ("pause\n" ::: "memory")
#elif defined(HAVE_ASM_ARM64)
#  define torsion_pause() __asm__ __volatile__ ("yield\n" ::: "memory")
#elif defined(HAVE_ASM_PPC)
#  define torsion_pause() __asm__ __volatile__ ("or 27, 27, 27\n" ::: "cc", \
                                                                      "memory")
#elif defined(HAVE_ASM_RISCV)
#  define torsion_pause() __asm__ __volatile__ ("wfi\n" ::: "memory")
#else
#  define torsion_pause() do { } while (0)
#endif

/*
 * Feature Testing
 */

int
torsion_has_rdrand(void) {
#if defined(HAVE_ASM_INTEL) && defined(__RDRND__)
  /* Explicitly built with RDRAND support (-mrdrnd). */
  return 1;
#elif defined(HAVE_RDRAND) || defined(HAVE_ASM_INTEL)
  uint32_t eax, ebx, ecx, edx;

  torsion_cpuid(&eax, &ebx, &ecx, &edx, 0, 0);

  if (eax < 1)
    return 0;

  torsion_cpuid(&eax, &ebx, &ecx, &edx, 1, 0);

  return (ecx >> 30) & 1;
#elif defined(HAVE_ASM_ARM64) && defined(__ARM_FEATURE_RNG)
  /* Explicitly built with ARM RNG support (-march=armv8.5-a+rng). */
  return 1;
#elif defined(HAVE_ASM_ARM64) && defined(HAVE_AUXVAL)
  /* Bit 16 = RNG support (HWCAP2_RNG) */
  if ((torsion_auxval(AT_HWCAP2) >> 16) & 1)
    return 1;

  /* Bit 11 = MRS emulation (HWCAP_CPUID) */
  /* https://www.kernel.org/doc/html/latest/arm64/cpu-feature-registers.html */
  if ((torsion_auxval(AT_HWCAP) >> 11) & 1) {
    uint64_t isar0;

    __asm__ __volatile__ (
      "mrs %0, s3_0_c0_c6_0\n" /* ID_AA64ISAR0_EL1 */
      : "=r" (isar0)
    );

    /* Bits 63-60 = RNDR (0b0001) */
    return (isar0 >> 60) >= 1;
  }

  return 0;
#elif defined(HAVE_ASM_PPC) && (defined(_ARCH_PWR9) || defined(_ARCH_PWR10))
  /* Explicitly built for POWER9 (-mcpu=power9 or -mpower9-vector). */
  return 1;
#elif defined(HAVE_ASM_PPC) && defined(HAVE_AUXVAL)
  /* Bit 21 = DARN support (PPC_FEATURE2_DARN) */
  return (torsion_auxval(AT_HWCAP2) >> 21) & 1;
#elif defined(HAVE_ASM_PPC) && defined(HAVE_POWER_SET)
  /* Check for POWER9 or greater. */
  return torsion_power_set(0xffffffffU << 17) != 0;
#else
  return 0;
#endif
}

int
torsion_has_rdseed(void) {
#if defined(HAVE_ASM_INTEL) && defined(__RDSEED__)
  /* Explicitly built with RDSEED support (-mrdseed). */
  return 1;
#elif defined(HAVE_RDSEED) || defined(HAVE_ASM_INTEL)
  uint32_t eax, ebx, ecx, edx;

  torsion_cpuid(&eax, &ebx, &ecx, &edx, 0, 0);

  if (eax < 7)
    return 0;

  torsion_cpuid(&eax, &ebx, &ecx, &edx, 7, 0);

  return (ebx >> 18) & 1;
#elif defined(HAVE_ASM_ARM64)
  return torsion_has_rdrand();
#elif defined(HAVE_ASM_PPC64)
  return torsion_has_rdrand();
#elif defined(HAVE_ASM_RISCV) && defined(__riscv_zkr)
  /* Explicitly built with TRNG support (-march=rv{32,64}ik). */
  return 1;
#elif defined(HAVE_ASM_RISCV)
  riscv_word_t misa;

  __asm__ __volatile__ (
    "csrr %0, 0x301\n" /* MISA */
    : "=r" (misa)
  );

  return (misa >> 10) & 1;
#else
  return 0;
#endif
}

/*
 * Intrinsics
 */

static int
torsion_rdrand_step(step_word_t *z) {
#if defined(HAVE_RDRAND32)
  return _rdrand32_step((unsigned int *)z);
#elif defined(HAVE_RDRAND64)
  return _rdrand64_step(z);
#elif defined(HAVE_ASM_X86)
  uint8_t c;

  __asm__ __volatile__ (
    ".byte 0x0f, 0xc7, 0xf0\n" /* rdrand %eax */
    "setc %b1\n"
    : "=a" (*z), "=q" (c)
    :: "cc"
  );

  return c;
#elif defined(HAVE_ASM_X64)
  uint8_t c;

  __asm__ __volatile__ (
    ".byte 0x48, 0x0f, 0xc7, 0xf0\n" /* rdrand %rax */
    "setc %b1\n"
    : "=a" (*z), "=q" (c)
    :: "cc"
  );

  return c;
#elif defined(HAVE_ASM_ARM64)
  uint32_t c;

  __asm__ __volatile__ (
    "mrs %0, s3_3_c2_c4_0\n" /* RNDR */
    "cset %w1, ne\n"
    : "=r" (*z), "=r" (c)
    :: "cc"
  );

  return c;
#elif defined(HAVE_ASM_PPC32)
  __asm__ __volatile__ (
    ".long (0x7c0005e6 | (%0 << 21))\n" /* darn %0, 0 */
    : "=r" (*z)
  );

  return *z != UINT32_MAX;
#elif defined(HAVE_ASM_PPC64)
  __asm__ __volatile__ (
    ".long (0x7c0105e6 | (%0 << 21))\n" /* darn %0, 1 */
    : "=r" (*z)
  );

  return *z != UINT64_MAX;
#else
  *z = 0;
  return 1;
#endif
}

static int
torsion_rdseed_step(step_word_t *z) {
#if defined(HAVE_RDSEED32)
  return _rdseed32_step((unsigned int *)z);
#elif defined(HAVE_RDSEED64)
  return _rdseed64_step(z);
#elif defined(HAVE_ASM_X86)
  uint8_t c;

  __asm__ __volatile__ (
    ".byte 0x0f, 0xc7, 0xf8\n" /* rdseed %eax */
    "setc %b1\n"
    : "=a" (*z), "=q" (c)
    :: "cc"
  );

  return c;
#elif defined(HAVE_ASM_X64)
  uint8_t c;

  __asm__ __volatile__ (
    ".byte 0x48, 0x0f, 0xc7, 0xf8\n" /* rdseed %rax */
    "setc %b1\n"
    : "=a" (*z), "=q" (c)
    :: "cc"
  );

  return c;
#elif defined(HAVE_ASM_ARM64)
  uint32_t c;

  __asm__ __volatile__ (
    "mrs %0, s3_3_c2_c4_1\n" /* RNDRRS */
    "cset %w1, ne\n"
    : "=r" (*z), "=r" (c)
    :: "cc"
  );

  return c;
#elif defined(HAVE_ASM_PPC64)
  __asm__ __volatile__ (
    ".long (0x7c0205e6 | (%0 << 21))\n" /* darn %0, 2 */
    : "=r" (*z)
  );

  return *z != UINT64_MAX;
#elif defined(HAVE_ASM_RISCV)
  riscv_word_t w;

  __asm__ __volatile__ (
    "csrrs %0, 0xdbf, x0\n" /* SENTROPY */
    : "=r" (w)
  );

  *z = w & 0xffff;

  return ((w >> 30) & 3) == 1; /* ES16 */
#else
  *z = 0;
  return 1;
#endif
}

/*
 * Polling
 */

static step_word_t
torsion_rdrand(void) {
  step_word_t z = 0;
  int i;

  for (i = 0; i < 10; i++) {
    if (torsion_rdrand_step(&z))
      break;
  }

  return z;
}

static step_word_t
torsion_rdseed(void) {
  step_word_t z = 0;

  for (;;) {
    if (torsion_rdseed_step(&z))
      break;

    torsion_pause();
  }

  return z;
}

static int
torsion_rdtest(void) {
  step_word_t z;
  int i;

  for (i = 0; i < 10; i++) {
    if (torsion_rdseed_step(&z))
      return 1;

    torsion_pause();
  }

  return 0;
}

/*
 * RDRAND/RDSEED
 */

uint32_t
torsion_rdrand32(void) {
#if step_word_size == 16
  step_word_t hi = torsion_rdrand();
  step_word_t lo = torsion_rdrand();

  return ((uint32_t)hi << 16) | lo;
#else
  return (uint32_t)torsion_rdrand();
#endif
}

uint32_t
torsion_rdseed32(void) {
#if step_word_size == 16
  step_word_t hi = torsion_rdseed();
  step_word_t lo = torsion_rdseed();

  return ((uint32_t)hi << 16) | lo;
#else
  return (uint32_t)torsion_rdseed();
#endif
}

uint64_t
torsion_rdrand64(void) {
#if step_word_size == 16
  step_word_t a = torsion_rdrand();
  step_word_t b = torsion_rdrand();
  step_word_t c = torsion_rdrand();
  step_word_t d = torsion_rdrand();

  return ((uint64_t)a << 48)
       | ((uint64_t)b << 32)
       | ((uint64_t)c << 16)
       | ((uint64_t)d <<  0);
#elif step_word_size == 32
  step_word_t hi = torsion_rdrand();
  step_word_t lo = torsion_rdrand();

  return ((uint64_t)hi << 32) | lo;
#else
  return torsion_rdrand();
#endif
}

uint64_t
torsion_rdseed64(void) {
#if step_word_size == 16
  step_word_t a = torsion_rdseed();
  step_word_t b = torsion_rdseed();
  step_word_t c = torsion_rdseed();
  step_word_t d = torsion_rdseed();

  return ((uint64_t)a << 48)
       | ((uint64_t)b << 32)
       | ((uint64_t)c << 16)
       | ((uint64_t)d <<  0);
#elif step_word_size == 32
  step_word_t hi = torsion_rdseed();
  step_word_t lo = torsion_rdseed();

  return ((uint64_t)hi << 32) | lo;
#else
  return torsion_rdseed();
#endif
}

/*
 * Hardware Entropy
 */

int
torsion_hwrand(void *dst, size_t size) {
  unsigned char *data = (unsigned char *)dst;
  int has_rdrand = torsion_has_rdrand();
  int has_rdseed = torsion_has_rdseed();
  step_word_t x;
  int i;

  if (!has_rdrand && !has_rdseed)
    goto fail;

  if (has_rdseed && !torsion_rdtest())
    goto fail;

  while (size > 0) {
    if (has_rdseed) {
      x = torsion_rdseed();
    } else {
      x = 0;

      /* Idea from Bitcoin Core: force rdrand to reseed. */
      for (i = 0; i < 1024; i++)
        x ^= torsion_rdrand();
    }

    if (size < sizeof(x)) {
      memcpy(data, &x, size);
      break;
    }

    memcpy(data, &x, sizeof(x));

    data += sizeof(x);
    size -= sizeof(x);
  }

  return 1;
fail:
  if (size > 0)
    memset(dst, 0, size);

  return 0;
}
