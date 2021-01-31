#include <immintrin.h>
#include <string.h>

// https://software.intel.com/content/www/us/en/develop/blogs/the-difference-between-rdrand-and-rdseed.html
static inline void rdseed(uint64_t *seed) {
    while (_rdseed64_step(seed) == 0) /* retry */;
}

void drbg_entropy(void *buf, rsize_t bytes) {
    while (bytes > 8) {
        rdseed((uint64_t *) buf);
        buf += 8;
        bytes -= 8;
    }
    uint64_t seed;
    rdseed(&seed);
    memcpy(buf, &seed, bytes);
}
