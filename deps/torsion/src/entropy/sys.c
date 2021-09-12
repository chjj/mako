/*!
 * sys.c - os/system entropy for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://en.wikipedia.org/wiki//dev/random
 *   https://en.wikipedia.org/wiki/Entropy-supplying_system_calls
 *   https://en.wikipedia.org/wiki/CryptGenRandom
 *
 * Windows:
 *   https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom
 *   https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
 *
 * Linux:
 *   https://man7.org/linux/man-pages/man4/random.4.html
 *   https://man7.org/linux/man-pages/man2/_sysctl.2.html
 *   https://man7.org/linux/man-pages/man2/getrandom.2.html
 *   https://man7.org/linux/man-pages/man3/getentropy.3.html
 *
 * Apple:
 *   https://www.unix.com/man-page/mojave/4/random/
 *   https://www.unix.com/man-page/mojave/2/getentropy/
 *
 * FreeBSD:
 *   https://www.freebsd.org/cgi/man.cgi?random(4)
 *   https://www.freebsd.org/cgi/man.cgi?sysctl(3)
 *   https://www.freebsd.org/cgi/man.cgi?getrandom(2)
 *   https://www.freebsd.org/cgi/man.cgi?getentropy(3)
 *
 * OpenBSD:
 *   https://man.openbsd.org/random.4
 *   https://man.openbsd.org/sysctl.2
 *   https://man.openbsd.org/getentropy.2
 *
 * NetBSD:
 *   https://man.netbsd.org/random.4
 *   https://man.netbsd.org/sysctl.3
 *   https://man.netbsd.org/getrandom.2
 *
 * DragonFly BSD:
 *   https://leaf.dragonflybsd.org/cgi/web-man?command=random&section=4
 *   https://leaf.dragonflybsd.org/cgi/web-man?command=getrandom&section=2
 *
 * Solaris:
 *   https://docs.oracle.com/cd/E36784_01/html/E36884/random-7d.html
 *   https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html
 *   https://docs.oracle.com/cd/E86824_01/html/E54765/getentropy-2.html
 *   https://web.archive.org/web/20000917040238/http://www.cosy.sbg.ac.at/~andi/
 *   https://lists.gnupg.org/pipermail/gnupg-devel/2000-May/016446.html
 *   http://lists.pdxlinux.org/pipermail/plug/2002-March/000846.html
 *
 * Illumos:
 *   https://illumos.org/man/7d/random
 *   https://illumos.org/man/2/getrandom
 *   https://illumos.org/man/3C/getentropy
 *
 * Cygwin:
 *   https://cygwin.com/git/?p=newlib-cygwin.git;a=blob;f=winsup/cygwin/fhandler_random.cc;hb=8050ef2
 *   https://cygwin.com/git/?p=newlib-cygwin.git;a=blob;f=winsup/cygwin/include/sys/random.h;hb=8050ef2
 *   https://cygwin.com/git/?p=newlib-cygwin.git;a=blob;f=newlib/libc/include/sys/unistd.h;hb=8050ef2#l107
 *
 * Hurd:
 *   https://git.savannah.gnu.org/cgit/hurd/hurd.git/tree/trans/random.c?id=98b3390
 *   https://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/sys/random.h;h=0451cf7
 *
 * BSD/OS:
 *   https://svn.apache.org/repos/asf/apr/apr/branches/1.6.x/misc/unix/rand.c
 *
 * HP-UX:
 *   https://nixdoc.net/man-pages/HP-UX/man7/random.7.html
 *   https://nixdoc.net/man-pages/HP-UX/man7/urandom.7.html
 *
 * NonStop (with OSS):
 *   https://support.hpe.com/hpesc/public/docDisplay?docId=c02128688&docLocale=en_US
 *   https://www.ibm.com/docs/en/ibm-mq/8.0?topic=nss-entropy-daemon
 *   http://prngd.sourceforge.net/
 *
 * AIX:
 *   https://www.ibm.com/docs/en/aix/7.1?topic=files-random-urandom-devices
 *
 * IBM i (with PASE):
 *   https://www.ibm.com/docs/pt/i/7.1?topic=pi-whats-new-i-71
 *
 * z/OS:
 *   https://www.ibm.com/docs/en/zos/2.1.0?topic=files-random-number
 *
 * QNX:
 *   http://www.qnx.com/developers/docs/6.3.2/neutrino/utilities/r/random.html
 *
 * Haiku:
 *   https://github.com/haiku/haiku/blob/8f16317/src/add-ons/kernel/bus_managers/random/driver.cpp
 *
 * Minix:
 *   https://wiki.minix3.org/doku.php?id=developersguide:overviewofminixservers
 *
 * Tru64 UNIX:
 *   https://web.archive.org/web/20030927104849/
 *   http://h30097.www3.hp.com/docs/base_doc/DOCUMENTATION/V51B_HTML/MAN/MAN4/0199____.HTM
 *
 * IRIX:
 *   https://irix7.com/techpubs/007-3897-019.pdf
 *
 * Unicos:
 *   https://manualzz.com/doc/9236155/cray-open-software-release-overview-and-installation-guid...
 *   http://prngd.sourceforge.net/
 *
 * SCO OpenServer 5+ / UnixWare 7 / Open UNIX 8:
 *   http://osr507doc.sco.com/cgi-bin/man?mansearchword=prngd&mansection=1&lang=en
 *   http://prngd.sourceforge.net/
 *
 * Redox:
 *   https://gitlab.redox-os.org/redox-os/randd
 *
 * DJGPP:
 *   https://cypherpunks.venona.com/date/1995/12/msg01101.html
 *   https://web.archive.org/web/20200202174514/http://www.rahul.net/dkaufman/index.html
 *
 * VxWorks:
 *   https://docs.windriver.com/bundle/vxworks_7_application_core_os_sr0630-enus/page/CORE/randomNumGenLib.html
 *
 * VMS:
 *   https://vmssoftware.com/about/roadmap/
 *   https://github.com/openssl/openssl/pull/8926
 *
 * Fuchsia:
 *   https://fuchsia.dev/fuchsia-src/reference/syscalls/cprng_draw
 *
 * CloudABI:
 *   https://github.com/NuxiNL/cloudabi/tree/d283c05#cloudabi_sys_random_get
 *   https://github.com/NuxiNL/cloudabi/blob/d283c05/headers/cloudabi_syscalls.h#L193
 *
 * WASI:
 *   https://github.com/WebAssembly/WASI/blob/fc3da39/phases/snapshot/docs.md#:~:text=random_get
 *   https://github.com/WebAssembly/wasi-libc/blob/2b7e73a/libc-bottom-half/headers/public/wasi/api.h#L2201-L2215
 *
 * Emscripten:
 *   https://github.com/emscripten-core/emscripten/blob/32e1d73/system/include/uuid/uuid.h
 *   https://emscripten.org/docs/api_reference/emscripten.h.html#c.EM_JS
 *   https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 *   https://nodejs.org/api/crypto.html#crypto_crypto_randomfillsync_buffer_offset_size
 *   https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random
 *   https://github.com/emscripten-core/emscripten/blob/048f028/system/include/compat/sys/random.h
 *
 * UEFI:
 *   https://uefi.org/specifications
 *   https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf
 *   https://github.com/tianocore/edk2
 *   https://github.com/tianocore/edk2-libc
 *
 * Intel SGX:
 *   https://download.01.org/intel-sgx/
 *   https://download.01.org/intel-sgx/linux-2.6/docs/Intel_SGX_Developer_Reference_Linux_2.6_Open_Source.pdf
 *   https://github.com/intel/linux-sgx
 *
 * Cosmopolitan:
 *   https://justine.lol/cosmopolitan/documentation.html#getrandom
 *   https://github.com/jart/cosmopolitan/blob/5029e20/libc/rand/rand.h#L20
 *   https://github.com/jart/cosmopolitan/blob/5029e20/libc/rand/getrandom.c
 */

/**
 * OS/System Entropy
 *
 * We try to avoid /dev/{,u}random as much as possible. Not
 * only can they behave differenly on different OSes, but they
 * are unreliable in terms of usability. In certain cases, we
 * could be inside a chroot where /dev has not been setup. In
 * other cases, we could get an EMFILE when opening /dev files.
 *
 * To avoid locking ourselves down to a particular build system,
 * we check for features using only the C preprocessor.
 *
 * In the future, we may consider using dlsym(3) to check
 * features at runtime. This would ensure better ABI compat
 * across builds. In select compilers, we could also consider
 * using weak symbols.
 *
 * We try to match the behavior of the getrandom rust library[1].
 * The primary difference involves the fact that we do not call
 * `SecRandomCopyBytes` on iOS as it requires us to link to the
 * Apple Security Framework.
 *
 * Our current entropy backends are as follows...
 *
 * Windows:
 *   Source: BCryptGenRandom
 *   Fallback: RtlGenRandom (SystemFunction036)
 *   Support: RtlGenRandom added in Windows XP (2001).
 *            BCryptGenRandom added in Windows Vista (2007).
 *            BCRYPT_USE_SYSTEM_PREFERRED_RNG added in Windows 7 (2009).
 *
 * Linux:
 *   Source: getrandom(2)
 *   Fallback 1: /dev/urandom (after polling /dev/random)
 *   Fallback 2: _sysctl(2) w/ kern.random.uuid
 *   Support: /dev/{,u}random added in Linux 1.3.30 (1995).
 *            _sysctl(2) added in Linux 1.3.57 (1995).
 *            kern.random.uuid added in Linux 2.3.16 (1999).
 *            _sysctl(2) deprecated in Linux 2.6.24 (2008).
 *            getrandom(2) added in Linux 3.17 (2014).
 *            _sysctl(2) removed in Linux 5.5 (2020).
 *
 * Apple:
 *   Source: getentropy(2)
 *   Fallback: /dev/urandom (identical to /dev/random)
 *   Support: /dev/{,u}random added in OSX 10.1 (2001).
 *            getentropy(2) added in OSX 10.12 (2016).
 *            getentropy(2) added in iOS 10.0 (2016).
 *            getentropy(2) added in tvOS 10.0 (2016).
 *            getentropy(2) added in watchOS 3.0 (2016).
 *
 * FreeBSD:
 *   Source: getrandom(2)
 *   Fallback 1: sysctl(2) w/ kern.arandom
 *   Fallback 2: /dev/urandom (symlink to /dev/random)
 *   Support: /dev/{,u}random added in FreeBSD 2.1.5 (1995).
 *            kern.arandom added in FreeBSD 7.0 (2008).
 *            kern.arandom modernized in FreeBSD 7.1 (2009).
 *            getrandom(2) added in FreeBSD 12.0 (2018).
 *
 * OpenBSD:
 *   Source: getentropy(2)
 *   Fallback 1: sysctl(2) w/ kern.arandom
 *   Fallback 2: /dev/urandom
 *   Support: /dev/{,u}random added in OpenBSD 2.0 (1996).
 *            kern.arandom added in OpenBSD 2.6 (1999).
 *            kern.arandom modernized in OpenBSD 3.8 (2005).
 *            getentropy(2) added in OpenBSD 5.6 (2014).
 *            kern.arandom removed in OpenBSD 6.1 (2017).
 *
 * NetBSD:
 *   Source: getrandom(2)
 *   Fallback 1: sysctl(2) w/ kern.arandom
 *   Fallback 2: /dev/urandom
 *   Support: /dev/{,u}random added in NetBSD 1.3 (1998).
 *            kern.arandom added in NetBSD 2.0 (2004).
 *            kern.arandom modernized in NetBSD 4.0 (2007).
 *            getrandom(2) added in NetBSD 10.0 (2021).
 *
 * DragonFly BSD:
 *   Source: getrandom(2)
 *   Fallback: /dev/urandom
 *   Support: /dev/{,u}random supported since inception (2003).
 *            getrandom(2) added in DragonFly BSD 5.7.1 (2020).
 *
 * Solaris:
 *   Source: getrandom(2)
 *   Fallback 1: getentropy(2)
 *   Fallback 2: /dev/urandom
 *   Support: /dev/random supported for Solaris 2.6 & 7 with SUNWski (~2000).
 *            /dev/{,u}random supported for Solaris 2.6+ with "andirand" (2000).
 *            /dev/{,u}random added in Solaris 8 (patch 112438-01) (2002).
 *            <sys/random.h> added in Solaris 8 (patch 112438-01) (2002).
 *            getrandom(2) added in Solaris 11.3 (2015).
 *            getentropy(2) added in Solaris 11.3 (2015).
 *            Solaris 11.3 support added in Sun Studio 12.5 (5.14) (2016).
 *
 * Illumos:
 *   Source: getentropy(3)
 *   Fallback: /dev/urandom
 *   Support: /dev/{,u}random supported since inception (2010).
 *            <sys/random.h> supported since inception (2010).
 *            getrandom(2) added in Illumos 0.12 (2015).
 *            getentropy(3) added in Illumos 0.12 (2015).
 *            getrandom(2) "made public" in Illumos 0.29 (2018).
 *            getentropy(3) used due to getrandom(2) ABI change.
 *            No Illumos support after Sun Studio 12.1 (5.10) (2009).
 *
 * Cygwin:
 *   Source: getrandom(2)
 *   Fallback: /dev/urandom
 *   Support: /dev/{,u}random added in Cygwin 1.1.2 (2000).
 *            getrandom(2) added in Cygwin 2.7.0 (2017).
 *            getrandom(2) fixed in Cygwin 2.8.0 (2017).
 *
 * Hurd:
 *   Source: getrandom(2)
 *   Fallback: /dev/urandom
 *   Support: /dev/{,u}random added in Hurd 0.6 (2015).
 *            /dev/urandom changed to a symlink in Hurd X (2017).
 *            getrandom(2) added in glibc 2.31 (2019).
 *
 * BSD/OS:
 *   Source: /dev/random
 *   Fallback: none
 *   Support: /dev/random existed since BSD/OS 4.1 (1999).
 *
 * HP-UX:
 *   Source: /dev/urandom
 *   Fallback: none
 *   Support: /dev/{,u}random added in HP-UX 11i v1 (KRNG11i) (2002).
 *
 * NonStop (with OSS):
 *   Source: prngd / amqjkdm0 (IBM MQ 5.3 server)
 *   Fallback: none
 *   Support: prngd or amqjkdm0 socket must be available.
 *
 * AIX:
 *   Source: /dev/random
 *   Fallback: none
 *   Support: /dev/{,u}random added in AIX 5.2 (2002).
 *
 * IBM i (with PASE):
 *   Source: /dev/urandom
 *   Fallback: none
 *   Support: /dev/urandom added in IBM i 7.1 (2010).
 *
 * z/OS:
 *   Source: /dev/urandom
 *   Fallback: none
 *   Support: /dev/{,u}random added in z/OS 1.7 (2005).
 *            ICSF service must be started.
 *
 * QNX:
 *   Source: /dev/random
 *   Fallback: none
 *   Support: /dev/random existed since QNX 6.2.1 (2003).
 *            random service must be started.
 *
 * Haiku:
 *   Source: /dev/urandom (identical to /dev/random)
 *   Fallback: none
 *   Support: /dev/{,u}random added in OpenBeOS (2002).
 *
 * Minix:
 *   Source: /dev/urandom
 *   Fallback: none
 *   Support: /dev/{,u}random added in Minix 3.3.0 (2014).
 *
 * Tru64 UNIX:
 *   Source: /dev/urandom
 *   Fallback: none
 *   Support: /dev/{,u}random added in Tru64 UNIX 5.1B (2002).
 *
 * IRIX:
 *   Source: /dev/urandom
 *   Fallback: none
 *   Support: /dev/{,u}random added in IRIX 6.5.19 (2003).
 *
 * Unicos:
 *   Source: prngd
 *   Fallback: none
 *   Support: prngd socket must be available.
 *
 * SCO OpenServer 5+ / UnixWare 7 / Open UNIX 8:
 *   Source: prngd
 *   Fallback: none
 *   Support: prngd socket must be available.
 *
 * Redox:
 *   Source: rand:
 *   Fallback: none
 *   Support: :rand added in Redox 0.1.0 (ead01ea) (2016).
 *
 * DJGPP:
 *   Source: /dev/urandom$
 *   Fallback: none
 *   Support: Requires NOISE.SYS (1995).
 *
 * VxWorks:
 *   Source: randABytes (after polling randSecure)
 *   Fallback: none
 *   Support: randABytes added in VxWorks 7 (2016).
 *
 * VMS:
 *   Source: SYS$GET_ENTROPY
 *   Fallback: none
 *   Support: SYS$GET_ENTROPY added in OpenVMS 9.2 (2021).
 *
 * Fuchsia:
 *   Source: zx_cprng_draw
 *   Fallback: none
 *   Support: zx_cprng_draw added in ae0f41b (2018).
 *
 * CloudABI:
 *   Source: cloudabi_sys_random_get
 *   Fallback: none
 *   Support: cloudabi_sys_random_get added in CloudABI 0.1 (2016).
 *
 * WASI:
 *   Source: __wasi_random_get
 *   Fallback: none
 *   Support: __wasi_random_get added in wasi_snapshot_preview1 (2019).
 *
 * Emscripten:
 *   Browser:
 *     Source: window.crypto.getRandomValues w/ EM_JS
 *     Fallback 1: getentropy(2)
 *     Fallback 2: uuid_generate(3) (broken for workers)
 *   Node.js
 *     Source: crypto.randomFillSync w/ EM_JS
 *     Fallback 1: getentropy(2)
 *     Fallback 2: uuid_generate(3)
 *   Shell:
 *     Source: Math.random w/ EM_JS
 *     Fallback: none
 *   Support: uuid_generate(3) added in Emscripten 1.8.6 (2014).
 *            EM_JS added in Emscripten 1.37.36 (2018).
 *            getentropy(2) added in Emscripten 2.0.5 (2020).
 *
 * UEFI:
 *   Source: EFI_RNG_PROTOCOL.GetRNG
 *   Fallback: none
 *   Support: EFI_RNG_PROTOCOL specified in UEFI 2.4 (2013).
 *            EFI_RNG_PROTOCOL added in tianocore/edk2#3aa8dc6 (2013).
 *
 * Intel SGX:
 *   Source: sgx_read_rand
 *   Fallback: none
 *   Support: sgx_read_rand specified in SGX <=1.5 (2016).
 *            sgx_read_rand added in intel/linux-sgx#9441de4 (2016).
 *
 * Cosmopolitan:
 *   Source: getrandom(2)
 *   Fallback: none
 *   Support: getrandom(2) added in Cosmopolitan 0.1 (2020).
 *
 * [1] https://docs.rs/getrandom/latest/getrandom/
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "entropy.h"

/*
 * Options
 */

#undef EGD_TEST /* Define to test EGD backend. */

/*
 * Backend
 */

#undef HAVE_BCRYPTGENRANDOM
#undef HAVE_RTLGENRANDOM
#undef HAVE_GETRANDOM
#undef HAVE_SYSCTL_UUID
#undef HAVE_GETENTROPY
#undef HAVE_SYSCTL_ARND
#undef HAVE_RANDABYTES
#undef HAVE_SYS_GET_ENTROPY
#undef HAVE_CPRNG_DRAW
#undef HAVE_SYS_RANDOM_GET
#undef HAVE_WASI_RANDOM_GET
#undef HAVE_SYS_RANDOM_H
#undef HAVE_JS_RANDOM_GET
#undef HAVE_UUID_GENERATE
#undef HAVE_EFI_RNG_PROTOCOL
#undef HAVE_SGX_READ_RAND
#undef DEV_RANDOM_NAME
#undef DEV_RANDOM_POLL
#undef DEV_RANDOM_SELECT
#undef DEV_RANDOM_RETRY
#undef HAVE_EGD
#undef HAVE_GETPID
#undef HAVE_UNKNOWN

#if defined(_EFI_CDEFS_H) /* UEFI */
#  include <Uefi.h> /* EFI_STATUS, EFI_ERROR */
#  include <Library/UefiBootServicesTableLib.h> /* gBS */
#  include <Protocol/Rng.h> /* EFI_RNG_PROTOCOL, gEfiRngProtocolGuid */
#  define HAVE_EFI_RNG_PROTOCOL
#elif defined(_TLIBC_CDECL_) /* Intel SGX */
#  include <sgx_trts.h> /* SGX_SUCCESS, sgx_read_rand */
#  define HAVE_SGX_READ_RAND
#elif defined(__COSMOPOLITAN__)
/* include <cosmopolitan.h> */ /* getrandom (-include cosmopolitan.h) */
/* include <stdlib.h> */ /* getrandom (-isystem libc/isystem) */
#  define HAVE_GETRANDOM
#elif defined(_WIN32)
#  include <windows.h> /* _WIN32_WINNT */
#  if (defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601) /* Windows 7 (2009) */ \
   && (defined(_MSC_VER) && _MSC_VER >= 1600) /* VS 2010 */                    \
   && !defined(__MINGW32__)
#    include <bcrypt.h> /* BCryptGenRandom */
#    pragma comment(lib, "bcrypt.lib")
#    define HAVE_BCRYPTGENRANDOM
#  else /* Windows XP (2001) */
#    define RtlGenRandom SystemFunction036
#    ifdef __cplusplus
extern "C"
#    endif
BOOLEAN NTAPI
RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#    ifndef __MINGW32__
#      pragma comment(lib, "advapi32.lib")
#    endif
#    define HAVE_RTLGENRANDOM
#  endif
#elif defined(EGD_TEST)
#  define HAVE_EGD
#elif defined(__linux__)
#  if !defined(__NEWLIB__) && !defined(__dietlibc__)
#    include <sys/syscall.h> /* SYS_*, __NR_* */
/*   include <unistd.h> */ /* syscall */
#    ifdef __NR_getrandom /* 3.17 (2014) */
#      define getrandom(buf, len, flag) syscall(__NR_getrandom, buf, len, flag)
#      define HAVE_GETRANDOM
#    endif
#    ifdef __NR__sysctl /* 2.3.16 (1999) */
#      define HAVE_SYSCTL_UUID
#    endif
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#  define DEV_RANDOM_POLL
#elif defined(__WATCOMC__) && defined(__LINUX__)
#  define DEV_RANDOM_NAME "/dev/urandom"
#  define DEV_RANDOM_SELECT
#elif defined(__APPLE__) && defined(__MACH__)
#  include <AvailabilityMacros.h>
#  if MAC_OS_X_VERSION_MAX_ALLOWED >= 101200 /* 10.12 (2016) */
#    include <sys/random.h> /* getentropy */
#    ifdef __GNUC__
#      pragma GCC diagnostic ignored "-Waddress"
#    endif
#    define HAVE_GETENTROPY
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#  include <sys/param.h> /* <osreldate.h> prior to 3.0.1 (1998) */
#  if defined(__FreeBSD_version) && __FreeBSD_version >= 1200000 /* 12.0 (2018) */
#    include <sys/random.h> /* getrandom */
#    define HAVE_GETRANDOM
#  endif
#  if defined(__FreeBSD_version) && __FreeBSD_version >= 701000 /* 7.1 (2009) */
#    include <sys/sysctl.h> /* sysctl */
#    if defined(CTL_KERN) && defined(KERN_ARND)
#      define HAVE_SYSCTL_ARND
#    endif
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__OpenBSD__)
#  include <sys/param.h> /* NetBSD prior to 2.0 (1996) */
#  if defined(OpenBSD) && OpenBSD >= 201411 /* 5.6 (2014) */
/*   include <unistd.h> */ /* getentropy */
#    define HAVE_GETENTROPY
#  endif
#  if defined(OpenBSD) && OpenBSD >= 200511 /* 3.8 (2005) */
#    include <sys/sysctl.h> /* sysctl */
#    if defined(CTL_KERN) && defined(KERN_ARND)
#      define HAVE_SYSCTL_ARND
#    endif
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__NetBSD__) || defined(__NetBSD_kernel__)
#  include <sys/param.h> /* NetBSD prior to 1.3C (1998) */
#  if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 1000000000 /* 10.0 (2021) */
#    include <sys/random.h> /* getrandom */
#    define HAVE_GETRANDOM
#  endif
#  if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 400000000 /* 4.0 (2007) */
#    include <sys/sysctl.h> /* sysctl */
#    if defined(CTL_KERN) && defined(KERN_ARND)
#      define HAVE_SYSCTL_ARND
#    endif
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__DragonFly__)
#  include <sys/param.h>
#  if defined(__DragonFly_version) && __DragonFly_version >= 500710 /* 5.7.1 (2020) */
#    include <sys/random.h> /* getrandom */
#    define HAVE_GETRANDOM
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__sun) && defined(__SVR4)
#  include <sys/random.h> /* getrandom, getentropy (solaris) */
/* include <unistd.h> */ /* getentropy (illumos) */
#  ifdef GRND_RANDOM
#    if (defined(__SUNPRO_C) && __SUNPRO_C > 0x5100) \
     || (defined(__SUNPRO_CC) && __SUNPRO_CC > 0x5100) /* 5.10 (2009) */
#      define HAVE_GETRANDOM /* Solaris 11.3 (2015) */
#    else
#      define HAVE_GETENTROPY /* Illumos 0.12 (2015) */
#    endif
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__CYGWIN__)
#  include <cygwin/version.h>
#  if CYGWIN_VERSION_API_MAJOR > 0 || CYGWIN_VERSION_API_MINOR >= 306 /* 2.7.0 (2017) */
#    include <sys/random.h> /* getrandom, getentropy */
#    define HAVE_GETRANDOM
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__gnu_hurd__)
#  if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 31) /* 2.31 (2019) */
#      include <sys/random.h> /* getrandom */
#      define HAVE_GETRANDOM
#    endif
#  endif
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__bsdi__)
#  define DEV_RANDOM_NAME "/dev/random"
#  define DEV_RANDOM_RETRY
#elif defined(__hpux)
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__TANDEM)
#  define HAVE_EGD
#elif defined(__PASE__) /* IBM i disguised as AIX */
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(_AIX)
#  define DEV_RANDOM_NAME "/dev/random"
#elif defined(__MVS__)
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__QNX__)
#  define DEV_RANDOM_NAME "/dev/random"
#elif defined(__HAIKU__)
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__minix)
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__osf__)
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(__sgi)
#  define DEV_RANDOM_NAME "/dev/urandom"
#elif defined(_UNICOS) || defined(_UNICOSMP)
#  define HAVE_EGD
#elif defined(_SCO_DS) || defined(__SCO_VERSION__) || defined(__sysv5__)
#  define HAVE_EGD
#elif defined(__redox__)
#  define DEV_RANDOM_NAME "rand:"
#elif defined(__DJGPP__)
#  define DEV_RANDOM_NAME "/dev/urandom$"
#elif defined(__vxworks) || defined(__DCC__)
#  include <version.h>
#  if defined(_WRS_VXWORKS_MAJOR) && _WRS_VXWORKS_MAJOR >= 7 /* 7 (2016) */
#    include <randomNumGen.h> /* randABytes, randSecure */
#    include <taskLib.h> /* taskDelay */
#    define HAVE_RANDABYTES
#  else
#    define HAVE_UNKNOWN
#  endif
#elif defined(__VMS)
#  if defined(__CRTL_VER) && __CRTL_VER >= 90200000 /* 9.2 (2021) */
#    define __NEW_STARLET 1
#    include <ssdef.h> /* SS$_NORMAL, SS$_RETRY */
#    include <starlet.h> /* sys$get_entropy */
#    include <lib$routines.h> /* lib$signal */
#    ifdef __DECC
#      pragma message disable DOLLARID
#    endif
#    define HAVE_SYS_GET_ENTROPY
#  endif
#elif defined(__Fuchsia__)
#  include <zircon/syscalls.h> /* zx_cprng_draw */
#  define HAVE_CPRNG_DRAW
#elif defined(__CloudABI__)
#  include <cloudabi_syscalls.h> /* cloudabi_sys_random_get */
#  define HAVE_SYS_RANDOM_GET
#elif defined(__wasi__)
#  include <wasi/api.h> /* __wasi_random_get */
#  define HAVE_WASI_RANDOM_GET
#elif defined(__EMSCRIPTEN__)
#  include <emscripten.h> /* EM_JS */
#  ifdef __has_include
#    if __has_include(<sys/random.h>)
#      define HAVE_SYS_RANDOM_H
#    endif
#  endif
#  if defined(EM_JS) && !defined(__wasm64__) /* 1.37.36 (2018) */
#    define HAVE_JS_RANDOM_GET
#  elif defined(HAVE_SYS_RANDOM_H) /* 2.0.5 (2020) */
#    include <sys/random.h> /* getentropy */
#    define HAVE_GETENTROPY
#  else /* 1.8.6 (2014) */
#    include <uuid/uuid.h> /* uuid_generate */
#    define HAVE_UUID_GENERATE
#  endif
#else
#  define HAVE_UNKNOWN
#endif

#if defined(DEV_RANDOM_NAME) || defined(HAVE_EGD)
#  include <sys/types.h> /* ssize_t, pid_t */
#  include <sys/stat.h> /* stat, fstat, S_* */
#  include <fcntl.h> /* open, fcntl, O_*, FD_* */
#  include <unistd.h> /* read, write, close, getpid */
#  ifdef DEV_RANDOM_POLL
#    include <poll.h> /* poll */
#  endif
#  ifdef DEV_RANDOM_SELECT
#    include <sys/time.h> /* select */
#  endif
#  ifdef HAVE_EGD
#    include <sys/socket.h> /* connect, shutdown, sockaddr */
#    if defined(__vxworks) || defined(__DCC__)
#      include <streams/un.h> /* sockaddr_un */
#    else
#      include <sys/un.h> /* sockaddr_un */
#    endif
#  endif
#  ifndef S_ISNAM
#    define S_ISNAM(x) 0
#  endif
#  define HAVE_GETPID
#endif

/*
 * Error Handling
 */

#ifdef DEV_RANDOM_NAME
static int
torsion_retry_open(int fd) {
  if (fd == -1) {
#ifdef EINTR
    if (errno == EINTR)
      return 1;
#endif
  }
  return 0;
}
#endif /* DEV_RANDOM_NAME */

#if defined(HAVE_GETRANDOM) || defined(DEV_RANDOM_NAME) || defined(HAVE_EGD)
static int
torsion_retry_rdwr(int ret) {
  if (ret == -1) {
#ifdef EINTR
    if (errno == EINTR)
      return 1;
#endif
#ifdef EAGAIN
    if (errno == EAGAIN)
      return 1;
#endif
#ifdef EWOULDBLOCK
    if (errno == EWOULDBLOCK)
      return 1;
#endif
  }
  return 0;
}
#endif /* HAVE_GETRANDOM || DEV_RANDOM_NAME || HAVE_EGD */

#ifdef HAVE_EGD
static int
torsion_retry_connect(int ret) {
  if (ret == -1) {
#ifdef EINTR
    if (errno == EINTR)
      return 1;
#endif
#ifdef EINPROGRESS
    if (errno == EINPROGRESS)
      return 1;
#endif
#ifdef EALREADY
    if (errno == EALREADY)
      return 1;
#endif
  }
  return 0;
}
#endif /* HAVE_EGD */

/*
 * Helpers
 */

#ifdef DEV_RANDOM_NAME
static int
torsion_open(const char *name, int flags) {
  int fd;

#ifdef O_CLOEXEC
  fd = open(name, flags | O_CLOEXEC);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = open(name, flags);

#ifdef FD_CLOEXEC
  if (fd != -1) {
    int r = fcntl(fd, F_GETFD);

    if (r != -1)
      fcntl(fd, F_SETFD, r | FD_CLOEXEC);
  }
#endif

  return fd;
}
#endif /* DEV_RANDOM_NAME */

#ifdef HAVE_EGD
static int
torsion_socket(int domain, int type, int protocol) {
  int fd;

#ifdef SOCK_CLOEXEC
  fd = socket(domain, type | SOCK_CLOEXEC, protocol);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = socket(domain, type, protocol);

#ifdef FD_CLOEXEC
  if (fd != -1) {
    int r = fcntl(fd, F_GETFD);

    if (r != -1)
      fcntl(fd, F_SETFD, r | FD_CLOEXEC);
  }
#endif

  return fd;
}
#endif /* HAVE_EGD */

/*
 * Emscripten Entropy
 */

#ifdef HAVE_JS_RANDOM_GET
EM_JS(unsigned short, js_random_get, (unsigned char *dst, unsigned long len), {
  if (ENVIRONMENT_IS_NODE) {
    var crypto = module.require('crypto');
    var buf = Buffer.from(HEAPU8.buffer, dst, len);

    try {
      crypto.randomFillSync(buf, 0, len);
    } catch (e) {
      return 1;
    }

    return 0;
  }

  if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
    var global = ENVIRONMENT_IS_WORKER ? self : window;
    var crypto = global.crypto || global.msCrypto;
    var max = 65536;

    if (!crypto || !crypto.getRandomValues)
      return 1;

    while (len > 0) {
      if (max > len)
        max = len;

      var buf = HEAPU8.subarray(dst, dst + max);

      crypto.getRandomValues(buf);

      dst += max;
      len -= max;
    }

    return 0;
  }

  if (ENVIRONMENT_IS_SHELL) {
    while (len--)
      HEAPU8[dst++] = Math.floor(Math.random() * 0x100);

    return 0;
  }

  return 1;
})
#endif /* HAVE_JS_RANDOM_GET */

/*
 * Syscall Entropy
 */

static int
torsion_callrand(void *dst, size_t size) {
#if defined(HAVE_BCRYPTGENRANDOM)
  unsigned long flags = BCRYPT_USE_SYSTEM_PREFERRED_RNG;
  unsigned char *data = (unsigned char *)dst;
  size_t max = ULONG_MAX;

  while (size > 0) {
    if (max > size)
      max = size;

    if (BCryptGenRandom(NULL, data, max, flags) != 0)
      return 0;

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_RTLGENRANDOM)
  unsigned char *data = (unsigned char *)dst;
  size_t max = ULONG_MAX;

  while (size > 0) {
    if (max > size)
      max = size;

    if (!RtlGenRandom(data, max))
      return 0;

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_GETRANDOM)
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;
  int nread;

  while (size > 0) {
    if (max > size)
      max = size;

    do {
      nread = getrandom(data, max, 0);
    } while (torsion_retry_rdwr(nread));

    if (nread < 0)
      return 0;

    if ((size_t)nread > max)
      abort();

    data += nread;
    size -= nread;
  }

  return 1;
#elif defined(HAVE_GETENTROPY)
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;

#ifdef __APPLE__
  /* Apple uses weak symbols depending on
     the minimum OS version requested. */
  if (getentropy == NULL)
    return 0;
#endif

  while (size > 0) {
    if (max > size)
      max = size;

    if (getentropy(data, max) != 0)
      return 0;

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_SYSCTL_ARND)
  static int name[2] = {CTL_KERN, KERN_ARND};
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;
  size_t nread;

  while (size > 0) {
    if (max > size)
      max = size;

    nread = max;

    if (sysctl(name, 2, data, &nread, NULL, 0) != 0)
      return 0;

    if (nread > max)
      abort();

    data += nread;
    size -= nread;
  }

  return 1;
#elif defined(HAVE_RANDABYTES)
  unsigned char *data = (unsigned char *)dst;
  size_t max = INT_MAX;
  int ret;

  for (;;) {
    ret = randSecure();

    if (ret < 0)
      return 0;

    if (ret > 0)
      break;

    taskDelay(5);
  }

  while (size > 0) {
    if (max > size)
      max = size;

    if (randABytes(data, max) != 0)
      return 0;

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_SYS_GET_ENTROPY)
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;
  int ret;

  while (size > 0) {
    if (max > size)
      max = size;

    do {
      ret = sys$get_entropy(data, max);
    } while (ret == SS$_RETRY);

    if (ret != SS$_NORMAL) {
      lib$signal(ret);
      return 0;
    }

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_CPRNG_DRAW)
  zx_cprng_draw(dst, size);
  return 1;
#elif defined(HAVE_SYS_RANDOM_GET)
  return cloudabi_sys_random_get(dst, size) == 0;
#elif defined(HAVE_WASI_RANDOM_GET)
  return __wasi_random_get((unsigned char *)dst, size) == 0;
#elif defined(HAVE_JS_RANDOM_GET)
  return js_random_get((unsigned char *)dst, size) == 0;
#elif defined(HAVE_UUID_GENERATE)
  unsigned char *data = (unsigned char *)dst;
  unsigned char uuid[16];
  size_t max = 14;

  while (size > 0) {
    if (max > size)
      max = size;

    uuid_generate(uuid);

    uuid[6] = uuid[14];
    uuid[8] = uuid[15];

    memcpy(data, uuid, max);

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_EFI_RNG_PROTOCOL)
  EFI_RNG_PROTOCOL *rng = NULL;
  EFI_STATUS status;

  status = gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID **)&rng);

  if (EFI_ERROR(status) || rng == NULL)
    return 0;

  status = rng->GetRNG(rng, NULL, (UINTN)size, (UINT8 *)dst);

  return !EFI_ERROR(status);
#elif defined(HAVE_SGX_READ_RAND)
  return sgx_read_rand((unsigned char *)dst, size) == SGX_SUCCESS;
#else
  (void)dst;
  (void)size;
  return 0;
#endif
}

/*
 * Device Entropy
 */

#ifdef DEV_RANDOM_NAME
static int
torsion_devrand(void *dst, size_t size, const char *name) {
  unsigned char *data = (unsigned char *)dst;
  size_t max = INT_MAX;
  struct stat st;
  int fd, nread;
#if defined(DEV_RANDOM_POLL) || defined(DEV_RANDOM_SELECT)
  int r;

  if (strcmp(name, "/dev/urandom") == 0) {
    do {
      fd = torsion_open("/dev/random", O_RDONLY);
    } while (torsion_retry_open(fd));

    if (fd < 0)
      return 0;

    if (fstat(fd, &st) != 0)
      goto fail;

    if (!S_ISCHR(st.st_mode) && !S_ISNAM(st.st_mode))
      goto fail;

#if defined(DEV_RANDOM_POLL)
    {
      struct pollfd pfd;

      pfd.fd = fd;
      pfd.events = POLLIN;
      pfd.revents = 0;

      do {
        r = poll(&pfd, 1, -1);
      } while (torsion_retry_rdwr(r));
    }
#else
    if (fd < FD_SETSIZE) {
      fd_set fds;

      FD_ZERO(&fds);
      FD_SET(fd, &fds);

      do {
        r = select(fd + 1, &fds, NULL, NULL, NULL);
      } while (torsion_retry_rdwr(r));
    } else {
      unsigned char c;

      do {
        r = read(fd, &c, 1);
      } while (torsion_retry_rdwr(r));
    }
#endif

    if (r != 1)
      goto fail;

    close(fd);
  }
#endif /* DEV_RANDOM_POLL || DEV_RANDOM_SELECT */

#ifdef DEV_RANDOM_RETRY
retry:
#endif
  do {
    fd = torsion_open(name, O_RDONLY);
  } while (torsion_retry_open(fd));

  if (fd < 0)
    return 0;

  if (fstat(fd, &st) != 0)
    goto fail;

  if (!S_ISCHR(st.st_mode) && !S_ISNAM(st.st_mode))
    goto fail;

  while (size > 0) {
    if (max > size)
      max = size;

    do {
      nread = read(fd, data, max);
    } while (torsion_retry_rdwr(nread));

#ifdef DEV_RANDOM_RETRY
    if (nread == 0) {
      close(fd);
      goto retry;
    }
#endif

    if (nread <= 0)
      break;

    if ((size_t)nread > max)
      abort();

    data += nread;
    size -= nread;
  }

fail:
  close(fd);

  return size == 0;
}
#endif /* DEV_RANDOM_NAME */

/*
 * Random UUID (Linux)
 */

#ifdef HAVE_SYSCTL_UUID
struct torsion__sysctl_args {
  int *name;
  int nlen;
  void *oldval;
  size_t *oldlenp;
  void *newval;
  size_t newlen;
  unsigned long unused[4];
};

static int
torsion_uuidrand(void *dst, size_t size) {
  /* Called if we cannot open /dev/urandom (idea from libuv). */
  static int name[3] = {1, 40, 6}; /* kern.random.uuid */
  unsigned char *data = (unsigned char *)dst;
  struct torsion__sysctl_args args;
  size_t max = 14;
  char uuid[16];
  size_t nread;

  while (size > 0) {
    nread = sizeof(uuid);

    memset(&args, 0, sizeof(args));

    args.name = name;
    args.nlen = 3;
    args.oldval = uuid;
    args.oldlenp = &nread;

    if (syscall(__NR__sysctl, &args) == -1)
      return 0;

    if (nread != sizeof(uuid))
      return 0;

    uuid[6] = uuid[14];
    uuid[8] = uuid[15];

    if (max > size)
      max = size;

    memcpy(data, uuid, max);

    data += max;
    size -= max;
  }

  return 1;
}
#endif /* HAVE_SYSCTL_UUID */

/*
 * EGD Protocol
 */

#ifdef HAVE_EGD
static int
torsion_egdrand(void *dst, size_t size) {
#if defined(EGD_TEST)
  static const char *paths[] = { "/tmp/entropy" };
#else
  static const char *paths[] = { "/var/run/egd-pool",
                                 "/dev/egd-pool",
                                 "/etc/egd-pool",
                                 "/etc/entropy" };
#endif
  unsigned char *data = (unsigned char *)dst;
  struct sockaddr_un addr;
  unsigned char msg[2];
  size_t i, len, left;
  size_t max = 255;
  const char *path;
  int found = 0;
  int ret = 0;
  int r, fd;

#ifdef __TANDEM
  /* According to OpenSSL, the IBM MQ entropy
   * daemon requires unix sockets to be in
   * compatibility mode[1][2]. According to
   * the OSS documentation[3], compatibility
   * mode is the default for AF_UNIX Release 1.
   *
   * Unsure what regular prngd listens on.
   *
   * [1] https://github.com/openssl/openssl/commit/0807370
   * [2] https://github.com/openssl/openssl/blob/0807370/crypto/rand/rand_egd.c#L57
   * [3] http://nonstoptools.com/manuals/OSS-SystemCalls.pdf
   */
  {
    char transport[6] = "$ZPLS";

    socket_transport_name_set(AF_UNIX, transport);
  }
#endif

  fd = torsion_socket(AF_UNIX, SOCK_STREAM, 0);

  if (fd < 0)
    return 0;

  for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    path = paths[i];
    len = strlen(path);

    if (len + 1 > sizeof(addr.sun_path))
      continue;

    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;

    memcpy(addr.sun_path, path, len + 1);

    len += offsetof(struct sockaddr_un, sun_path);

    do {
      r = connect(fd, (struct sockaddr *)&addr, len);
    } while (torsion_retry_connect(r));

#ifdef EISCONN
    if (r == -1 && errno == EISCONN)
      r = 0;
#endif

    if (r == 0) {
      found = 1;
      break;
    }
  }

  if (!found)
    goto fail;

  while (size > 0) {
    if (max > size)
      max = size;

    msg[0] = 1;
    msg[1] = max;

    do {
      r = write(fd, msg, 2);
    } while (torsion_retry_rdwr(r));

    if (r != 2)
      goto fail;

    do {
      r = read(fd, msg, 1);
    } while (torsion_retry_rdwr(r));

    if (r != 1)
      goto fail;

    left = msg[0];

    if (left == 0 || left > max)
      goto fail;

    while (left > 0) {
      do {
        r = read(fd, data, left);
      } while (torsion_retry_rdwr(r));

      if (r <= 0)
        goto fail;

      if ((size_t)r > left)
        abort();

      data += r;
      size -= r;
      left -= r;
    }
  }

  ret = 1;
fail:
#ifdef SHUT_RDWR
  if (found)
    shutdown(fd, SHUT_RDWR);
#endif
  close(fd);
  return ret;
}
#endif /* HAVE_EGD */

/*
 * PID (exposed for a fork-aware RNG)
 */

long
torsion_getpid(void) {
#if defined(HAVE_GETPID)
  return (long)getpid();
#else
  return 0;
#endif
}

/*
 * Unknown Platform
 */

int
torsion_has_sysrand(void) {
#if defined(HAVE_UNKNOWN)
  return 0;
#else
  return 1;
#endif
}

/*
 * System Entropy
 */

int
torsion_sysrand(void *dst, size_t size) {
  int oldno = errno;
  int ret = 1;

  if (size == 0)
    goto done;

  if (torsion_callrand(dst, size))
    goto done;

#ifdef DEV_RANDOM_NAME
  if (torsion_devrand(dst, size, DEV_RANDOM_NAME))
    goto done;
#endif

#ifdef HAVE_SYSCTL_UUID
  if (torsion_uuidrand(dst, size))
    goto done;
#endif

#ifdef HAVE_EGD
  if (torsion_egdrand(dst, size))
    goto done;
#endif

  memset(dst, 0, size);

  ret = 0;
done:
  errno = oldno;
  return ret;
}
