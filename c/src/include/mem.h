#ifndef O1C_MEM_H
#define O1C_MEM_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __clang__
# if 100*__clang_major__ + __clang_minor__ > 305
#  define UNROLL _Pragma("clang loop unroll(full)")
# endif
#endif

#ifndef UNROLL
# define UNROLL
#endif

static inline uint32_t
rotl32(const uint32_t x, const int b) {
    return (x << b) | (x >> (32 - b));
}

static inline uint64_t
rotl64(const uint64_t x, const int b) {
    return (x << b) | (x >> (64 - b));
}

static inline uint32_t
rotr32(const uint32_t x, const int b) {
    return (x >> b) | (x << (32 - b));
}

static inline uint64_t
rotr64(const uint64_t x, const int b) {
    return (x >> b) | (x << (64 - b));
}

static inline uint64_t
load64_le(const uint8_t src[8]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] <<  8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
#endif
}

static inline void
store64_le(uint8_t dst[8], uint64_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[7] = (uint8_t) w;
#endif
}

static inline uint32_t
load32_le(const uint8_t src[4]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] <<  8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

static inline void
load32_le_n(uint32_t *dst, const uint8_t *src, size_t n) {
    UNROLL while (n-- > 0) {
        *dst++ = load32_le(src);
        src += sizeof(uint32_t);
    }
}

static inline void
store32_le(uint8_t dst[4], uint32_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

static inline void
store32_le_n(uint8_t *dst, const uint32_t *src, size_t n) {
    UNROLL while (n-- > 0) {
        store32_le(dst, *src++);
        dst += sizeof(uint32_t);
    }
}

static inline uint64_t
load64_be(const uint8_t src[8]) {
#ifdef NATIVE_BIG_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[7];
    w |= (uint64_t) src[6] << 8;
    w |= (uint64_t) src[5] << 16;
    w |= (uint64_t) src[4] << 24;
    w |= (uint64_t) src[3] << 32;
    w |= (uint64_t) src[2] << 40;
    w |= (uint64_t) src[1] << 48;
    w |= (uint64_t) src[0] << 56;
    return w;
#endif
}

static inline void
store64_be(uint8_t dst[8], uint64_t w) {
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[7] = (uint8_t) w;
    w >>= 8;
    dst[6] = (uint8_t) w;
    w >>= 8;
    dst[5] = (uint8_t) w;
    w >>= 8;
    dst[4] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

static inline uint32_t
load32_be(const uint8_t src[4]) {
#ifdef NATIVE_BIG_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[3];
    w |= (uint32_t) src[2] << 8;
    w |= (uint32_t) src[1] << 16;
    w |= (uint32_t) src[0] << 24;
    return w;
#endif
}

static inline void
store32_be(uint8_t dst[4], uint32_t w) {
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[3] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

#endif //O1C_MEM_H
