#ifndef O1C_UTIL_H
#define O1C_UTIL_H

#include <stdbool.h>

#include "o1c_export.h"

#ifdef __cplusplus
extern "C" {
#endif

// Overwrites a buffer with zeros.
O1C_EXPORT void o1c_bzero(void *buf, unsigned long bytes);

// Returns true in constant time if fst and snd have equal byte contents.
O1C_EXPORT bool o1c_mem_eq(const void *fst, const void *snd, unsigned long bytes);

// Returns true in constant time if a is all zeros.
O1C_EXPORT bool o1c_is_zero(const void *buf, unsigned long bytes);

// Converts hex to binary and returns binary length or -1 on error.
O1C_EXPORT long o1c_hex2bin(uint8_t *bin, unsigned long max_bin_len, const char *hex, unsigned long hex_len);

// Converts binary to hex and returns the hex string.
O1C_EXPORT char *o1c_bin2hex(char *hex, const uint8_t *bin, unsigned long bytes);

// Calculates optimal padding length for the given unpadded length.
O1C_EXPORT unsigned long o1c_pad_len(unsigned long unpadded_len);

#ifdef __cplusplus
}
#endif

#endif //O1C_UTIL_H
