#ifndef O1C_DRBG_H
#define O1C_DRBG_H

#include "o1c_export.h"

#ifdef __cplusplus
extern "C" {
#endif

// Fills the provided buffer with random bytes.
O1C_EXPORT void drbg_randombytes(void *buf, unsigned long bytes);

// Reseeds the current DRBG.
O1C_EXPORT void drbg_reseed(void);

// Fills the provided buffer with system-provided external entropy.
O1C_EXPORT void drbg_entropy(void *buf, unsigned long bytes);

#ifdef __cplusplus
}
#endif

#endif //O1C_DRBG_H
