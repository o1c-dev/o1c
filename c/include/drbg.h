#pragma once

#include "o1c_export.h"

// Fills the provided buffer with random bytes.
O1C_EXPORT void drbg_randombytes(void *buf, unsigned long bytes);

// Reseeds the current DRBG.
O1C_EXPORT void drbg_reseed(void);

// Fills the provided buffer with system-provided external entropy.
O1C_EXPORT void drbg_entropy(void *buf, unsigned long bytes);
