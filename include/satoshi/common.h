/*!
 * common.h - common definitions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_COMMON_H
#define BTC_COMMON_H

#ifdef BTC_EXPORT
#  if defined(__EMSCRIPTEN__)
#    include <emscripten.h>
#    define BTC_EXTERN EMSCRIPTEN_KEEPALIVE
#  elif defined(__wasm__)
#    define BTC_EXTERN __attribute__((visibility("default")))
#  elif defined(_WIN32)
#    define BTC_EXTERN __declspec(dllexport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define BTC_EXTERN __attribute__((visibility("default")))
#  endif
#endif

#ifndef BTC_EXTERN
#  define BTC_EXTERN struct btc_empty_struct;
#endif

#endif /* BTC_COMMON_H */
