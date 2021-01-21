#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sodium.h>

#include "test.h"

typedef void (*gen_fn)(FILE *, size_t);

void run_generator(const char *filename, const gen_fn fn) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        die(true, "fopen(%s)", filename);
    }
    fn(file, 256);
    if (fclose(file) != 0) {
        die(true, "fclose(%s)", filename);
    }
}

// Encrypts the test buffer
void gen_chacha20(FILE *file, const size_t max) {
    uint8_t key[crypto_stream_chacha20_ietf_KEYBYTES];
    uint8_t nonce[crypto_stream_chacha20_ietf_NONCEBYTES];
    uint8_t pt[max], ct[max], stream[max];
    init_buf(pt, max);
    char hex[max * 2 + 1];
    char kx[crypto_stream_chacha20_ietf_KEYBYTES * 2 + 1], nx[crypto_stream_chacha20_ietf_NONCEBYTES * 2 + 1];
    fprintf(file, "static const o1c_test_vector data[] = {\n");
    for (size_t len = 1; len <= max; ++len) {
        crypto_stream_chacha20_ietf_keygen(key);
        randombytes_buf(nonce, sizeof nonce);
        fprintf(file, "{%zu,\"%s\",\"%s\",", len, sodium_bin2hex(kx, sizeof kx, key, sizeof key),
                sodium_bin2hex(nx, sizeof nx, nonce, sizeof nonce));
        crypto_stream_chacha20_ietf(stream, len, nonce, key);
        fprintf(file, "\"%s\",", sodium_bin2hex(hex, sizeof hex, stream, len));
        crypto_stream_chacha20_ietf_xor(ct, pt, len, nonce, key);
        fprintf(file, "\"%s\"},\n", sodium_bin2hex(hex, sizeof hex, ct, len));
    }
    fprintf(file, "};\n");
    fflush(file);
}

// Encrypts and authenticates the test buffer
void gen_xchacha20poly1305(FILE *file, const size_t max) {
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint8_t ad[max], pt[max], ct[max + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    char hex[(max + crypto_aead_xchacha20poly1305_ietf_ABYTES) * 2 + 1];
    char kx[crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2 + 1];
    char nx[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES * 2 + 1];
    init_buf(ad, sizeof ad);
    init_buf(pt, sizeof pt);
    fprintf(file, "static const o1c_test_vector data[] = {\n");
    unsigned long long ct_len;
    for (size_t pt_len = 0; pt_len <= max; ++pt_len) {
        for (size_t ad_len = 0; ad_len <= max; ++ad_len) {
            crypto_aead_xchacha20poly1305_ietf_keygen(key);
            randombytes_buf(nonce, sizeof nonce);
            fprintf(file, "{%zu,%zu,\"%s\",\"%s\",", ad_len, pt_len, sodium_bin2hex(kx, sizeof kx, key, sizeof key),
                    sodium_bin2hex(nx, sizeof nx, nonce, sizeof nonce));
            crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &ct_len, pt, pt_len, ad, ad_len, NULL, nonce, key);
            fprintf(file, "\"%s\"},\n", sodium_bin2hex(hex, sizeof hex, ct, ct_len));
        }
    }
    fprintf(file, "};\n");
    fflush(file);
}

// Generates two curve25519 keypairs and their shared secret
void gen_curve25519(FILE *file, const size_t max) {
    uint8_t sa[crypto_scalarmult_curve25519_SCALARBYTES], sb[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t ea[crypto_scalarmult_curve25519_BYTES], eb[crypto_scalarmult_curve25519_BYTES];
    uint8_t product[crypto_scalarmult_curve25519_BYTES];
    char hex[65];
    fprintf(file, "static const o1c_test_vector data[] = {\n");
    for (size_t i = 0; i <= max; ++i) {
        crypto_core_ed25519_scalar_random(sa);
        fprintf(file, "{\"%s\",", sodium_bin2hex(hex, sizeof hex, sa, sizeof sa));
        crypto_core_ed25519_scalar_random(sb);
        fprintf(file, "\"%s\",", sodium_bin2hex(hex, sizeof hex, sb, sizeof sb));
        crypto_scalarmult_curve25519_base(ea, sa);
        fprintf(file, "\"%s\",", sodium_bin2hex(hex, sizeof hex, ea, sizeof ea));
        crypto_scalarmult_curve25519_base(eb, sb);
        fprintf(file, "\"%s\",", sodium_bin2hex(hex, sizeof hex, eb, sizeof eb));
        assert(crypto_scalarmult_curve25519(product, sa, eb) >= 0);
        fprintf(file, "\"%s\"},\n", sodium_bin2hex(hex, sizeof hex, product, sizeof product));
    }
    fprintf(file, "};\n");
    fflush(file);
}

// Generates a ristretto255 keypair, a random hash, a point from the hash, and the product of the point with the scalar
void gen_ristretto255(FILE *file, const size_t max) {
    uint8_t scalar[crypto_scalarmult_ristretto255_SCALARBYTES];
    uint8_t element[crypto_scalarmult_ristretto255_BYTES];
    uint8_t hash[crypto_core_ristretto255_HASHBYTES];
    uint8_t point[crypto_core_ristretto255_BYTES];
    uint8_t product[crypto_scalarmult_ristretto255_BYTES];
    char hex[crypto_core_ristretto255_HASHBYTES * 2 + 1];
    fprintf(file, "static const o1c_test_vector data[] = {\n");
    for (size_t i = 0; i <= max; ++i) {
        crypto_core_ristretto255_scalar_random(scalar);
        fprintf(file, "{\"%s\",", sodium_bin2hex(hex, sizeof hex, scalar, sizeof scalar));
        crypto_scalarmult_ristretto255_base(element, scalar);
        fprintf(file, "\"%s\",", sodium_bin2hex(hex, sizeof hex, element, sizeof element));
        randombytes_buf(hash, sizeof hash);
        fprintf(file, "\"%s\",", sodium_bin2hex(hex, sizeof hex, hash, sizeof hash));
        crypto_core_ristretto255_from_hash(point, hash);
        fprintf(file, "\"%s\",", sodium_bin2hex(hex, sizeof hex, point, sizeof point));
        assert(crypto_scalarmult_ristretto255(product, scalar, point) != -1);
        fprintf(file, "\"%s\"},\n", sodium_bin2hex(hex, sizeof hex, product, sizeof product));
    }
    fprintf(file, "};\n");
    fflush(file);
}

// Generates signatures of the test buffer
void gen_ed25519(FILE *file, const size_t max) {
    uint8_t sig[crypto_sign_ed25519_BYTES];
    uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
    uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
    uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t msg[max];
    init_buf(msg, max);
    char sigx[crypto_sign_ed25519_BYTES * 2 + 1];
    char seedx[crypto_sign_ed25519_SEEDBYTES * 2 + 1];
    char skx[crypto_sign_ed25519_SECRETKEYBYTES * 2 + 1];
    char pkx[crypto_sign_ed25519_PUBLICKEYBYTES * 2 + 1];
    fprintf(file, "static const o1c_test_vector data[] = {\n");
    for (size_t len = 0; len <= max; ++len) {
        randombytes_buf(seed, sizeof seed);
        crypto_sign_ed25519_seed_keypair(pk, sk, seed);
        fprintf(file, "{%zu,\"%s\",\"%s\",\"%s\",", len, sodium_bin2hex(seedx, sizeof seedx, seed, sizeof seed),
                sodium_bin2hex(skx, sizeof skx, sk, sizeof sk), sodium_bin2hex(pkx, sizeof pkx, pk, sizeof pk));
        crypto_sign_ed25519_detached(sig, NULL, msg, len, sk);
        fprintf(file, "\"%s\"},\n", sodium_bin2hex(sigx, sizeof sigx, sig, sizeof sig));
    }
    fprintf(file, "};\n");
    fflush(file);
}

int main(void) {
    run_generator("test_chacha20.txt", gen_chacha20);
    run_generator("test_xchacha20poly1305.txt", gen_xchacha20poly1305);
    run_generator("test_curve25519.txt", gen_curve25519);
    run_generator("test_ristretto255.txt", gen_ristretto255);
    run_generator("test_ed25519.txt", gen_ed25519);
}
