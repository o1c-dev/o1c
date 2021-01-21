#include "o1c.h"
#include "blake3.h"

inline void o1c_hash_init(o1c_hash_t ctx) {
    blake3_hasher *state = (blake3_hasher *) ctx->state;
    blake3_hasher_init(state);
}

inline void o1c_hash_key_setup(o1c_hash_t ctx, const uint8_t k[o1c_hash_KEY_BYTES]) {
    blake3_hasher *state = (blake3_hasher *) ctx->state;
    blake3_hasher_init_keyed(state, k);
}

inline void o1c_hash_kdf_setup(o1c_hash_t ctx, const char *context) {
    blake3_hasher *state = (blake3_hasher *) ctx->state;
    blake3_hasher_init_derive_key(state, context);
}

inline void o1c_hash_update(o1c_hash_t ctx, const uint8_t *m, unsigned long bytes) {
    blake3_hasher *state = (blake3_hasher *) ctx->state;
    blake3_hasher_update(state, m, bytes);
}

inline void o1c_hash_final(o1c_hash_t ctx, uint8_t *out, unsigned long out_bytes) {
    blake3_hasher *state = (blake3_hasher *) ctx->state;
    blake3_hasher_finalize(state, out, out_bytes);
}

inline void o1c_hash(uint8_t *out, unsigned long out_bytes, const uint8_t *in, unsigned long in_bytes) {
    o1c_hash_t ctx;
    o1c_hash_init(ctx);
    o1c_hash_update(ctx, in, in_bytes);
    o1c_hash_final(ctx, out, out_bytes);
    o1c_bzero(ctx, sizeof(blake3_hasher));
}


