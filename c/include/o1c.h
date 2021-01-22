#ifndef O1C_O1C_H
#define O1C_O1C_H

#include <stdbool.h>
#include <stdint.h>
#include <stdalign.h>

#ifdef __clang__
# if 100 * __clang_major__ + __clang_minor__ > 305
#  define O1C_UNROLL _Pragma("clang loop unroll(full)")
# endif
#endif

#ifndef O1C_UNROLL
# define O1C_UNROLL
#endif

#if defined _MSC_VER
# define O1C_NOINLINE __declspec(noinline)
#else

# include <unistd.h>

# define O1C_NOINLINE __attribute__((noinline))
#endif

#if !defined(__unix__) && (defined(__APPLE__) || defined(__linux__))
#define __unix__ 1
#endif

#include "drbg.h"
#include "util.h"
#include "hash.h"
#include "chacha20.h"
#include "poly1305.h"
#include "xchacha20poly1305.h"
#include "sha512.h"
#include "x25519.h"
#include "ed25519.h"
#include "ristretto255.h"

#endif //O1C_O1C_H
