#pragma once

#include "o1c_export.h"
#include <stddef.h>

// Fills the provided buffer with random bytes.
O1C_EXPORT void drbg_randombytes(void *buf, size_t bytes);

// Reseeds the current DRBG.
O1C_EXPORT void drbg_reseed(void);

// Fills the provided buffer with system-provided external entropy.
O1C_EXPORT void drbg_entropy(void *buf, size_t bytes);
