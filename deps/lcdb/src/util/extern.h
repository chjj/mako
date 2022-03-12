/*!
 * extern.h - extern definitions for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_EXTERN_H
#define LDB_EXTERN_H

#ifdef LDB_EXPORT
#  if defined(__EMSCRIPTEN__)
#    include <emscripten.h>
#    define LDB_EXTERN EMSCRIPTEN_KEEPALIVE
#  elif defined(__wasm__)
#    define LDB_EXTERN __attribute__((visibility("default")))
#  elif defined(_WIN32)
#    define LDB_EXTERN __declspec(dllexport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define LDB_EXTERN __attribute__((visibility("default")))
#  endif
#endif

#ifndef LDB_EXTERN
#  define LDB_EXTERN
#endif

#endif /* LDB_EXTERN_H */
