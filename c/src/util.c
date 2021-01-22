#include "util.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#ifdef _WIN32
# include <windows.h>
# include <wincrypt.h>
#endif

#if !defined(__unix__) && (defined(__APPLE__) || defined(__linux__))
#define __unix__ 1
#endif

#ifdef __OpenBSD__
#define HAVE_EXPLICIT_BZERO 1
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ) && defined(_GNU_SOURCE)
#if __GLIBC_PREREQ(2, 25)
#define HAVE_EXPLICIT_BZERO 1
#endif
#endif

// no-op assembler instruction that compilers supposedly understand to avoid optimizing away
#define BARRIER(X) __asm__("": "+r"(X):)

inline bool
o1c_mem_eq(const void *const fst, const void *const snd, const size_t len) {
    uint8_t *a = (uint8_t *) fst;
    uint8_t *b = (uint8_t *) snd;
    size_t L = (size_t) len;
    BARRIER(a);
    BARRIER(b);
    BARRIER(L);
    unsigned char d = 0U;
    for (size_t i = 0U; i < L; ++i) {
        uint8_t ai = a[i], bi = b[i];
        BARRIER(ai);
        BARRIER(bi);
        d |= ai ^ bi;
    }
    return (d - 1U) >> 8;
}

inline bool
o1c_is_zero(const void *const a_, const size_t len) {
    uint8_t *a = (uint8_t *) a_;
    size_t L = (size_t) len;
    BARRIER(a);
    BARRIER(L);
    unsigned char d = 0U;
    for (size_t i = 0; i < L; ++i) {
        uint8_t ai = a[i];
        BARRIER(ai);
        d |= ai;
    }
    return (d - 1U) >> 8;
}

inline void
o1c_bzero(void *const buf, size_t bytes) {
#if defined(_WIN32)
    SecureZeroMemory(buf, bytes);
#elif defined(HAVE_MEMSET_S)
    memset_s(buf, bytes, 0, bytes);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(buf, bytes);
#else
    uint8_t *b = (uint8_t *) buf;
    BARRIER(b);
    O1C_UNROLL while (bytes--) *b++ = 0;
    BARRIER(b);
#endif
}

long
o1c_hex2bin(uint8_t *const bin, const unsigned long max_bin_len, const char *const hex, const unsigned long hex_len) {
    unsigned long bin_pos = 0U, hex_pos = 0U;
    int ret = 0;
    unsigned char c, c_alpha0, c_alpha, c_num0, c_num, state = 0U;
    uint8_t c_acc = 0U, c_val;
    while (hex_pos < hex_len) {
        c = (unsigned char) hex[hex_pos];
        c_num = c ^ 48U;
        c_num0 = (c_num - 10U) >> 8;
        c_alpha = (c & ~32U) - 55U;
        c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
        if ((c_num0 | c_alpha0) == 0U) {
            break;
        }
        c_val = (uint8_t)((c_num0 & c_num) | (c_alpha0 & c_alpha));
        if (bin_pos >= max_bin_len) {
            ret   = -1;
            errno = ERANGE;
            break;
        }
        if (state == 0U) {
            c_acc = c_val * 16U;
        } else {
            bin[bin_pos++] = c_acc | c_val;
        }
        state = ~state;
        hex_pos++;
    }
    if (state != 0U) {
        hex_pos--;
        errno = EINVAL;
        ret   = -1;
    }
    if (hex_pos != hex_len) {
        errno = EINVAL;
        ret   = -1;
    }
    if (ret != 0) {
        return ret;
    }
    return (long) bin_pos;
}

char *
o1c_bin2hex(char *const hex, const uint8_t *const bin, const unsigned long bytes) {
    size_t i;
    for (i = 0U; i < bytes; ++i) {
        int c = bin[i] & 0xf;
        int b = bin[i] >> 4;
        unsigned int x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
                         (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
    }
    hex[i * 2U] = 0U;
    return hex;
}

/*
given a length L, we compute the padding length L' as:

let E = floor(log2(L))
let S = floor(log2(E)) + 1
let z = E - S
let m = (1 << z) - 1
let L' = (L + m) & ~m

 if you store the pad length encrypted from a separate subkey at the beginning, the rest of the message
 can be padded separately (similarly to SSH)
 */

unsigned long o1c_pad_len(unsigned long unpadded_len) {
    double e = floor(log2((double) unpadded_len));
    double s = floor(log2(e)) + 1;
    unsigned long z = (unsigned long) (e - s);
    unsigned long m = (1 << z) - 1;
    unsigned long padded_len = (unpadded_len + m) & ~m;
    return padded_len - unpadded_len;
}
