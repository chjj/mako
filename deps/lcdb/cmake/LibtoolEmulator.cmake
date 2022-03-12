# LibtoolEmulator.cmake - libtool versioning for cmake
# Copyright (c) 2021, Christopher Jeffrey (MIT License).
# https://github.com/chjj

# Explanation:
#
# CMake handles shared library versioning information in
# a very generic way. This is in contrast to libtool which
# handles versioning according to the conventions of the
# platform and its linker. It also has a specific scheme
# of [current]:[revision]:[age] which developers have come
# to love and hate.
#
# The CMake way and libtool way are basically incompatible
# with each other. A project which uses -version-info on
# libtool cannot easily switch over to CMake as their build
# system and maintain proper ABI compatibility. This is a
# notorious problem that I have not yet seen a solution for.
#
# This module reimplements the libtool behavior for CMake.
# This allows existing autotools projects to move over to
# CMake and have everything "just work". This file will
# need to be maintained forever to account for new OSes
# added to libtool.
#
# This module exposes three functions to emulate libtool
# behavior, with an API of:
#
# - set_target_version_info(target info)
#   Libtool equivalent: -version-info [info]
#   Example: set_target_version_info(mylib 3:2:1)
#
# - set_target_version_number(target number)
#   Libtool equivalent: -version-number [number]
#   Example: set_target_version_number(mylib 3:2:1)
#
# - set_target_release(target version)
#   Libtool equivalent: -release [version]
#   Example: set_target_release(mylib 2.7)
#
# Note that the final call is hacked in and modifies the
# target's OUTPUT_NAME.
#
# Resources:
#   https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
#   https://autotools.io/libtool/version.html

if(DEFINED __LIBTOOL_EMU)
  return()
endif()

set(__LIBTOOL_EMU 1)

if(CMAKE_C_COMPILER_LOADED)
  include(CheckSymbolExists)
elseif(CMAKE_CXX_COMPILER_LOADED)
  include(CheckCXXSymbolExists)
endif()

#
# Options
#

if(NOT DEFINED LIBTOOL_FORCE_WIN32_SUFFIX)
  set(LIBTOOL_FORCE_WIN32_SUFFIX 0)
endif()

#
# Private Functions
#

function(_libtool_ld_is_gnu result)
  if(CMAKE_C_COMPILER_LOADED)
    set(cc ${CMAKE_C_COMPILER})
  elseif(CMAKE_CXX_COMPILER_LOADED)
    set(cc ${CMAKE_CXX_COMPILER})
  else()
    set(${result} 0 PARENT_SCOPE)
    return()
  endif()

  execute_process(COMMAND ${cc} -Wl,-v /dev/null
                  OUTPUT_VARIABLE stdout
                  ERROR_VARIABLE stderr)

  if("${stdout}" MATCHES "^GNU ld")
    set(${result} 1 PARENT_SCOPE)
  else()
    set(${result} 0 PARENT_SCOPE)
  endif()
endfunction()

function(_libtool_has_elf result)
  if(CMAKE_C_COMPILER_LOADED)
    check_symbol_exists(__ELF__ "" __LIBTOOL_HAS_ELF)
  elseif(CMAKE_CXX_COMPILER_LOADED)
    check_cxx_symbol_exists(__ELF__ "" __LIBTOOL_HAS_ELF)
  else()
    set(${result} 1 PARENT_SCOPE)
    return()
  endif()

  if(__LIBTOOL_HAS_ELF)
    set(${result} 1 PARENT_SCOPE)
  else()
    set(${result} 0 PARENT_SCOPE)
  endif()
endfunction()

function(_libtool_link_options)
  if(COMMAND target_link_options)
    target_link_options(${ARGV})
  else()
    target_link_libraries(${ARGV})
  endif()
endfunction()

function(_libtool_macho_versions target compat_version current_version)
  if(CMAKE_VERSION VERSION_LESS 3.17)
    # Not sure if this will actually override CMake.
    _libtool_link_options(${target} PRIVATE
                          -Wl,-compatibility_version,${compat_version}
                          -Wl,-current_version,${current_version})
  else()
    # Added for this exact reason:
    # https://gitlab.kitware.com/cmake/cmake/-/issues/17652
    set_target_properties(${target} PROPERTIES
                          MACHO_COMPATIBILITY_VERSION ${compat_version}
                          MACHO_CURRENT_VERSION ${current_version})
  endif()
endfunction()

function(_libtool_version_string target verstring)
  if(CMAKE_C_COMPILER_ID MATCHES "^GNU$|^Clang$")
    _libtool_link_options(${target} PRIVATE -Wl,-set_version,${verstring})
  else()
    _libtool_link_options(${target} PRIVATE -set_version ${verstring})
  endif()
endfunction()

function(_libtool_version target scheme info isnum)
  if (NOT info MATCHES "^[0-9]+(:[0-9]+(:[0-9]+)?)?$")
    message(FATAL_ERROR "'${info}' is not valid version information.")
  endif()

  string(REPLACE ":" ";" parts ${info})

  list(GET parts 0 current)
  list(GET parts 1 revision)
  list(GET parts 2 age)

  if(NOT revision)
    set(revision 0)
  endif()

  if(NOT age)
    set(age 0)
  endif()

  set(irix_inc 1)

  # https://github.com/autotools-mirror/libtool/blob/544fc0e/build-aux/ltmain.in#L6898
  if(isnum)
    set(major ${current})
    set(minor ${revision})
    set(patch ${age})

    if(scheme MATCHES "darwin|freebsd-elf|linux|osf|windows")
      math(EXPR current "${major} + ${minor}")
      set(age ${minor})
      set(revision ${patch})
    elseif(scheme MATCHES "freebsd-aout|qnx|sunos")
      set(current ${major})
      set(revision ${minor})
      set(age 0)
    elseif(scheme MATCHES "irix|nonstopux")
      math(EXPR current "${major} + ${minor}")
      set(age ${minor})
      set(revision ${minor})
      set(irix_inc 0)
    endif()
  endif()

  if(age GREATER current)
    message(WARNING "AGE '${age}' is greater than the "
                    "current interface number '${current}'.")
    message(FATAL_ERROR "'${info}' is not valid version information.")
  endif()

  # https://github.com/autotools-mirror/libtool/blob/544fc0e/build-aux/ltmain.in#L6973
  set(major)
  set(version)

  if(scheme STREQUAL "darwin")
    math(EXPR major "${current} - ${age}")
    set(version "${major}.${age}.${revision}")
    math(EXPR compat_version "${current} + 1")
    set(current_version "${compat_version}.${revision}")
    _libtool_macho_versions(${target} ${compat_version} ${current_version})
  elseif(scheme STREQUAL "freebsd-aout")
    set(major ${current})
    set(version "${current}.${revision}")
  elseif(scheme STREQUAL "freebsd-elf")
    math(EXPR major "${current} - ${age}")
    set(version "${major}.${age}.${revision}")
  elseif(scheme MATCHES "irix|nonstopux")
    math(EXPR major "${current} - ${age} + ${irix_inc}")
    set(version "${major}.${revision}")
    set(prefix ${scheme})

    if(prefix STREQUAL "irix")
      set(prefix "sgi")
    endif()

    set(verstring "${prefix}${major}.${revision}")
    set(loop ${revision})

    while(loop GREATER 0)
      math(EXPR iface "${revision} - ${loop}")
      math(EXPR loop "${loop} - 1")
      set(verstring "${prefix}${major}.${iface}:${verstring}")
    endwhile()

    _libtool_version_string(${target} ${verstring})
  elseif(scheme STREQUAL "linux")
    math(EXPR major "${current} - ${age}")
    set(version "${major}.${age}.${revision}")
  elseif(scheme STREQUAL "osf")
    math(EXPR major "${current} - ${age}")
    set(version "${current}.${age}.${revision}")
    set(verstring ${version})
    set(loop ${age})

    while (loop GREATER 0)
      math(EXPR iface "${current} - ${loop}")
      math(EXPR loop "${loop} - 1")
      set(verstring "${verstring}:${iface}.0")
    endwhile()

    set(verstring "${verstring}:${current}.0")

    _libtool_version_string(${target} ${verstring})
  elseif(scheme STREQUAL "qnx")
    set(major ${current})
    set(version ${current})
  elseif(scheme STREQUAL "sco")
    set(major ${current})
    set(version ${current})
  elseif(scheme MATCHES "sunos")
    set(major ${current})
    set(version "${current}.${revision}")
  elseif(scheme STREQUAL "windows")
    math(EXPR major "${current} - ${age}")
    set(version ${major})
  else()
    message(FATAL_ERROR "Invalid versioning scheme.")
  endif()

  if(scheme STREQUAL "darwin")
    set_target_properties(${target} PROPERTIES VERSION ${major}
                                               SOVERSION ${major})
  elseif(scheme STREQUAL "windows")
    # CMake
    #   Cygwin = version suffix + version info
    #   Msys = version suffix + version info
    #   MinGW = version info
    #   Windows = version info
    #   OS/2 = none
    #
    # Libtool
    #   All of the above = version suffix
    #
    # The below call will add: -Wl,--major-image-version,${version}
    #                          -Wl,--minor-image-version,0
    #
    # Or (on Win32):           /VERSION:${version}.0
    #
    # There's no good way to avoid this unfortunately.
    #
    # See also: CMAKE_GNULD_IMAGE_VERSION
    set_target_properties(${target} PROPERTIES VERSION ${version}
                                               SOVERSION ${major})

    # CMake does not add the suffix to mingw or native
    # win32 libraries. We can force it to do this with
    # an ugly hack, but keep it behind a flag for now.
    #
    # See also: CMAKE_SHARED_LIBRARY_NAME_WITH_VERSION
    if(LIBTOOL_FORCE_WIN32_SUFFIX AND NOT CYGWIN AND NOT MSYS)
      get_property(name TARGET ${target} PROPERTY OUTPUT_NAME)
      set_property(TARGET ${target} PROPERTY OUTPUT_NAME "${name}-${version}")
    endif()
  elseif(scheme MATCHES "-aout$")
    set_target_properties(${target} PROPERTIES VERSION ${version}
                                               SOVERSION ${version})
  else()
    set_target_properties(${target} PROPERTIES VERSION ${version}
                                               SOVERSION ${major})
  endif()
endfunction()

# The CMake docs claim that CMAKE_SYSTEM_NAME is simply
# the result of `uname -s`. This is not true. It makes
# the following substitutions:
#
# OS             uname -s           substitution
# ----------------------------------------------
# Windows        [none]             Windows
# Windows CE     [none]             WindowsCE
# Windows Phone  [none]             WindowsPhone
# Windows Store  [none]             WindowsStore
# Android        Linux              Android
# BSD/OS         BSD/OS             BSDOS
# kFreeBSD       GNU/kFreeBSD       kFreeBSD
# Cygwin         CYGWIN_NT-*        CYGWIN
# Msys           MSYS_NT-*          MSYS
# z/OS           OS/390             OS390 (??)
# OS/2           OS/2               OS2 (??)
# Tru64 UNIX     OSF1               Tru64 (??)
# unknown        [falsey value]     UnknownOS
function(_libtool_set_version target info isnum)
  # CMake only officially supports a few platforms, but who knows:
  # we might be on a port, or someone might be cross-compiling with
  # a custom toolchain file, etc.
  #
  # Statements with `??` is where I'm unsure of the uname string.
  #
  # Libtool's `sysv4*` case is particularly hard to check, as it is
  # supposed to cover _any_ off-shoot of sysv4 (config.guess sets
  # this for a bunch of different platforms).
  #
  # Resources:
  #   https://github.com/autotools-mirror/libtool/blob/544fc0e/m4/libtool.m4#L2407
  #   https://github.com/autotools-mirror/autoconf/blob/378351d/build-aux/config.guess#L179
  if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^[Aa]miga[Oo][Ss]$")
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "powerpc")
      # Don't know what type this is. Use linux for now.
      _libtool_version(${target} linux ${info} ${isnum})
    endif()
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Android" OR ANDROID)
    # Android doesn't support versioning.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "BeOS" OR BEOS)
    # BeOS doesn't support versioning.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Bitrig") # OpenBSD
    _libtool_version(${target} sunos-aout ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "BSDOS")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^CRAY") # Unicos
    # None.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "CloudABI")
    # None.
  elseif(CMAKE_SYSTEM_NAME MATCHES "^CYGWIN" OR CYGWIN)
    _libtool_version(${target} windows ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR APPLE OR IOS)
    _libtool_version(${target} darwin ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "dgux")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "DOS$" OR DOS)
    # None.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "DragonFly")
    _libtool_version(${target} freebsd-elf ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "DYNIX/ptx")
    _libtool_version(${target} linux ${info} ${isnum}) # sysv4
  elseif(CMAKE_SYSTEM_NAME STREQUAL "ekkoBSD") # OpenBSD
    _libtool_version(${target} sunos-aout ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    # None.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    if(CMAKE_SYSTEM_VERSION MATCHES "^[23]")
      _libtool_version(${target} freebsd-aout ${info} ${isnum})
    else()
      _libtool_version(${target} freebsd-elf ${info} ${isnum})
    endif()
  elseif(CMAKE_SYSTEM_NAME MATCHES "^GNU")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Haiku" OR HAIKU)
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
    _libtool_version(${target} sunos-elf ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Interix")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^IRIX$|^IRIX64$")
    _libtool_ld_is_gnu(gnu_ld)
    if(gnu_ld)
      _libtool_version(${target} linux ${info} ${isnum})
    else()
      _libtool_version(${target} irix ${info} ${isnum})
    endif()
  elseif(CMAKE_SYSTEM_NAME STREQUAL "kFreeBSD")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "LibertyBSD") # OpenBSD
    _libtool_version(${target} sunos-aout ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "MidnightBSD") # FreeBSD
    _libtool_version(${target} freebsd-elf ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^MINGW" OR MINGW)
    _libtool_version(${target} windows ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Minix")
    # Unknown (possibly sunos-elf a la netbsd).
  elseif(CMAKE_SYSTEM_NAME STREQUAL "MirBSD") # OpenBSD
    _libtool_version(${target} sunos-aout ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "MP-RAS") # ??
    _libtool_version(${target} linux ${info} ${isnum}) # sysv4
  elseif(CMAKE_SYSTEM_NAME MATCHES "^MSYS" OR MSYS)
    _libtool_version(${target} windows ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    _libtool_has_elf(has_elf)
    if(has_elf)
      _libtool_version(${target} sunos-elf ${info} ${isnum})
    else()
      _libtool_version(${target} sunos-aout ${info} ${isnum})
    endif()
  elseif(CMAKE_SYSTEM_NAME STREQUAL "NEWS-OS")
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^NONSTOP_KERNEL$|^NonStop-UX$")
    _libtool_version(${target} nonstopux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    _libtool_version(${target} sunos-aout ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^OS/?2$" OR OS2)
    _libtool_version(${target} windows ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^OS/?390$")
    # Unknown.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "OS400")
    # This is probably PASE. Maybe use `linux` like AIX?
  elseif(CMAKE_SYSTEM_NAME MATCHES "^OSF1$|^Tru64$")
    _libtool_version(${target} osf ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^PW") # PW32
    _libtool_version(${target} windows ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "QNX" OR QNXNTO)
    _libtool_version(${target} qnx ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "rdos")
    # No dynamic linker.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Redox")
    # Unknown.
  elseif(CMAKE_SYSTEM_NAME MATCHES "^ReliantUNIX")
    _libtool_version(${target} linux ${info} ${isnum}) # sysv4
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Rhapsody")
    _libtool_version(${target} darwin ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^riscos$|^RISCOS$")
    # None.
  elseif(CMAKE_SYSTEM_NAME MATCHES "^SCO_SV$|^UnixWare$")
    _libtool_version(${target} sco ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^SINIX")
    _libtool_version(${target} linux ${info} ${isnum}) # sysv4
  elseif(CMAKE_SYSTEM_NAME STREQUAL "SolidBSD") # FreeBSD
    _libtool_version(${target} freebsd-elf ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    if(CMAKE_SYSTEM_VERSION MATCHES "^[0-4]")
      _libtool_version(${target} sunos-aout ${info} ${isnum})
    else()
      _libtool_version(${target} linux ${info} ${isnum})
    endif()
  elseif(CMAKE_SYSTEM_NAME STREQUAL "syllable")
    # Unknown.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "TPF")
    # Cross-compile only. Assume linux.
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "^ULTRIX")
    # None.
  elseif(CMAKE_SYSTEM_NAME MATCHES "^UNICOS")
    # None.
  elseif(CMAKE_SYSTEM_NAME MATCHES "^UNIX_S(ystem_)?V$")
    if(CMAKE_SYSTEM_VERSION MATCHES "^4")
      _libtool_version(${target} linux ${info} ${isnum}) # sysv4
    endif()
  elseif(CMAKE_SYSTEM_NAME STREQUAL "UTS4") ## ??
    _libtool_version(${target} linux ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME MATCHES "VMS$")
    # None.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "VOS")
    _libtool_version(${target} linux ${info} ${isnum}) # sysv4?
  elseif(CMAKE_SYSTEM_NAME STREQUAL "VxWorks")
    # Unknown.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # None.
  elseif(CMAKE_SYSTEM_NAME MATCHES "^Windows" OR WIN32
                                              OR WINCE
                                              OR WINDOWS_PHONE
                                              OR WINDOWS_STORE)
    _libtool_version(${target} windows ${info} ${isnum})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "XENIX")
    # None.
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Zircon" OR FUCHSIA)
    # Probably linux (fuchsia toolchain is gnu-like).
    _libtool_version(${target} linux ${info} ${isnum})
  else()
    # No dynamic linker.
  endif()
endfunction()

#
# Public Functions
#

function(set_target_version_info target info)
  _libtool_set_version(${target} ${info} 0)
endfunction()

function(set_target_version_number target number)
  _libtool_set_version(${target} ${number} 1)
endfunction()

function(set_target_release target version)
  if (NOT version MATCHES "^[0-9]+(\.[0-9]+(\.[0-9]+)?)?$")
    message(FATAL_ERROR "'${version}' is not a valid release number.")
  endif()

  get_property(name TARGET ${target} PROPERTY OUTPUT_NAME)

  string(REGEX REPLACE "-[0-9]+(\.[0-9]+(\.[0-9]+)?)?$" "" name "${name}")

  set_property(TARGET ${target} PROPERTY OUTPUT_NAME "${name}-${version}")
endfunction()
