#include <stdint.h>
#include <stdnoreturn.h>
#include <stdlib.h>
#include <string.h>

#include <jni.h>

#include "include/dev_o1c_lib_O1CLib.h"
#include "o1c.h"

static noreturn inline void
jvm_die(JNIEnv *env, const char *msg) {
    (*env)->FatalError(env, msg);
    abort();
}

static inline void *acquire(JNIEnv *env, jarray array) {
    void *data = (*env)->GetPrimitiveArrayCritical(env, array, NULL);
    if (data == NULL) jvm_die(env, "Cannot acquire pointer to JVM byte array");
    return data;
}

static inline void release(JNIEnv *env, jarray array, void *c_array) {
    (*env)->ReleasePrimitiveArrayCritical(env, array, c_array, 0);
}

void Java_dev_o1c_lib_O1CLib_randomBytes(JNIEnv *env, jclass cls, jbyteArray buf) {
    (void) cls;
    jsize bytes = (*env)->GetArrayLength(env, buf);
    jbyte *data = acquire(env, buf);
    drbg_randombytes(data, bytes);
    release(env, buf, data);
}

void Java_dev_o1c_lib_O1CLib_entropyBytes(JNIEnv *env, jclass cls, jbyteArray buf) {
    (void) cls;
    jsize bytes = (*env)->GetArrayLength(env, buf);
    jbyte *data = (*env)->GetPrimitiveArrayCritical(env, buf, NULL);
    if (data == NULL) jvm_die(env, "Cannot acquire buffer");
    drbg_entropy(data, (unsigned long) bytes);
    release(env, buf, data);
}

jint Java_dev_o1c_lib_O1CLib_hashStateSize(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;
    return sizeof(o1c_hash_s);
}

void Java_dev_o1c_lib_O1CLib_hashInit(JNIEnv *env, jclass cls, jbyteArray hashState) {
    (void) cls;
    o1c_hash_s *st = acquire(env, hashState);
    o1c_hash_init(st);
    release(env, hashState, st);
}

void Java_dev_o1c_lib_O1CLib_keyedHashInit(JNIEnv *env, jclass cls, jbyteArray hashState, jbyteArray key) {
    (void) cls;
    o1c_hash_s *st = acquire(env, hashState);
    uint8_t *k = acquire(env, key);
    o1c_hash_key_setup(st, k);
    release(env, key, k);
    release(env, hashState, st);
}

void Java_dev_o1c_lib_O1CLib_kdfHashInit(JNIEnv *env, jclass cls, jbyteArray hashState, jbyteArray context) {
    (void) cls;
    o1c_hash_s *st = acquire(env, hashState);
    char *context_ = acquire(env, context);
    o1c_hash_kdf_setup(st, context_);
    release(env, context, context_);
    release(env, hashState, st);
}

void Java_dev_o1c_lib_O1CLib_hashUpdate(JNIEnv *env, jclass cls, jbyteArray hashState, jbyteArray in, jint offset,
                                        jint length) {
    (void) cls;
    o1c_hash_s *st = acquire(env, hashState);
    uint8_t *m = acquire(env, in);
    o1c_hash_update(st, m + offset, length);
    release(env, in, m);
    release(env, hashState, st);
}

void Java_dev_o1c_lib_O1CLib_hashFinal(JNIEnv *env, jclass cls, jbyteArray hashState, jbyteArray hash, jint offset,
                                       jint length) {
    (void) cls;
    o1c_hash_s *st = acquire(env, hashState);
    uint8_t *h = acquire(env, hash);
    o1c_hash_final(st, h + offset, length);
    release(env, hash, h);
    release(env, hashState, st);
}

void Java_dev_o1c_lib_O1CLib_hash(JNIEnv *env, jclass cls, jbyteArray in, jint offset, jint length, jbyteArray hash,
                                  jint hashOffset, jint hashLength) {
    (void) cls;
    o1c_hash_t ctx;
    o1c_hash_init(ctx);
    uint8_t *m = acquire(env, in);
    o1c_hash_update(ctx, m + offset, length);
    release(env, in, m);
    uint8_t *h = acquire(env, hash);
    o1c_hash_final(ctx, h + hashOffset, hashLength);
    release(env, hash, h);
}

void Java_dev_o1c_lib_O1CLib_keyedHash(JNIEnv *env, jclass cls, jbyteArray key, jbyteArray in, jint offset, jint length,
                                       jbyteArray hash, jint hashOffset, jint hashLength) {
    (void) cls;
    uint8_t *k = acquire(env, key);
    o1c_hash_t ctx;
    o1c_hash_key_setup(ctx, k);
    release(env, key, k);
    uint8_t *m = acquire(env, in);
    o1c_hash_update(ctx, m + offset, length);
    release(env, in, m);
    uint8_t *h = acquire(env, hash);
    o1c_hash_final(ctx, h + hashOffset, hashLength);
    release(env, hash, h);
}

void Java_dev_o1c_lib_O1CLib_scalarFieldBaseMultiply(JNIEnv *env, jclass cls, jbyteArray result, jbyteArray scalar) {
    (void) cls;
    o1c_x25519_scalar_s *n = acquire(env, scalar);
    o1c_x25519_element_s *q = acquire(env, result);
    o1c_x25519_scalar_mul_base(q, n);
    release(env, result, q);
    release(env, scalar, n);
}

void Java_dev_o1c_lib_O1CLib_scalarFieldMultiply(JNIEnv *env, jclass cls, jbyteArray result, jbyteArray scalar,
                                                 jbyteArray fieldElement) {
    (void) cls;
    o1c_x25519_element_s *p = acquire(env, fieldElement);
    o1c_x25519_scalar_s *n = acquire(env, scalar);
    o1c_x25519_element_s *q = acquire(env, result);
    o1c_x25519_scalar_mul(q, n, p);
    release(env, result, q);
    release(env, scalar, n);
    release(env, fieldElement, p);
}

void Java_dev_o1c_lib_O1CLib_generateScalarFieldKeyPair(JNIEnv *env, jclass cls, jbyteArray publicKey,
                                                        jbyteArray privateKey) {
    (void) cls;
    o1c_x25519_element_s *pk = acquire(env, publicKey);
    o1c_x25519_scalar_s *sk = acquire(env, privateKey);
    o1c_x25519_keypair(pk, sk);
    release(env, privateKey, sk);
    release(env, publicKey, pk);
}

void Java_dev_o1c_lib_O1CLib_authenticatedEncrypt(JNIEnv *env, jclass cls, jbyteArray key, jbyteArray nonce,
                                                  jbyteArray context, jbyteArray pt, jint ptOff, jint ptLen,
                                                  jbyteArray ct, jint ctOff, jbyteArray tag, jint tagOff) {
    // TODO: consider exposing multi-part API for AEAD similar to stream/auth/hash APIs
    //  (this will allow minimizing length of time we acquire different arrays from the args for larger messages)
    (void) cls;
    uint8_t *k = acquire(env, key);
    uint8_t *n = acquire(env, nonce);
    uint8_t *ad = acquire(env, context);
    uint8_t *p = acquire(env, pt);
    uint8_t *c = acquire(env, ct);
    uint8_t *t = acquire(env, tag);
    jsize ad_len = (*env)->GetArrayLength(env, context);
    o1c_xchacha20poly1305_encrypt(c + ctOff, t + tagOff, p + ptOff, ptLen, ad, ad_len, n, k);
    release(env, tag, t);
    release(env, ct, c);
    release(env, pt, p);
    release(env, context, ad);
    release(env, nonce, n);
}

jboolean Java_dev_o1c_lib_O1CLib_authenticatedDecrypt(JNIEnv *env, jclass cls, jbyteArray key, jbyteArray nonce,
                                                      jbyteArray context, jbyteArray ct, jint ctOff, jint ctLen,
                                                      jbyteArray tag, jint tagOff, jbyteArray pt, jint ptOff) {
    (void) cls;
    uint8_t *k = acquire(env, key);
    uint8_t *n = acquire(env, nonce);
    uint8_t *ad = acquire(env, context);
    uint8_t *c = acquire(env, ct);
    uint8_t *t = acquire(env, tag);
    uint8_t *p = acquire(env, pt);
    jsize ad_len = (*env)->GetArrayLength(env, context);
    bool ret = o1c_xchacha20poly1305_decrypt(p + ptOff, t + tagOff, c + ctOff, ctLen, ad, ad_len, n, k);
    release(env, pt, p);
    release(env, tag, t);
    release(env, ct, c);
    release(env, context, ad);
    release(env, nonce, n);
    return (jboolean) ret;
}

void Java_dev_o1c_lib_O1CLib_deriveKeyPairFromSeed(JNIEnv *env, jclass cls, jbyteArray publicKey,
                                                   jbyteArray expandedPrivateKey, jbyteArray seed) {
    (void) cls;
    o1c_ed25519_seed_s *s = acquire(env, seed);
    o1c_ed25519_expanded_key_s *sk = acquire(env, expandedPrivateKey);
    o1c_ed25519_expand_key(sk, s);
    release(env, expandedPrivateKey, sk);
    release(env, seed, s);

    o1c_ed25519_public_key_s *pk = acquire(env, publicKey);
    memcpy(pk->v, sk->v + o1c_ed25519_SEED_BYTES, o1c_ed25519_PUBLIC_BYTES);
    release(env, publicKey, pk);
}

void Java_dev_o1c_lib_O1CLib_generateSignKeyPair(JNIEnv *env, jclass cls, jbyteArray publicKey,
                                                 jbyteArray expandedPrivateKey) {
    (void) cls;
    o1c_ed25519_public_key_s *pk = acquire(env, publicKey);
    o1c_ed25519_expanded_key_s *sk = acquire(env, expandedPrivateKey);
    o1c_ed25519_keypair(pk, sk);
    release(env, expandedPrivateKey, sk);
    release(env, publicKey, pk);
}

void Java_dev_o1c_lib_O1CLib_sign(JNIEnv *env, jclass cls, jbyteArray expandedPrivateKey, jbyteArray in, jint offset,
                                  jint length, jbyteArray sig, jint sigOffset) {
    (void) cls;
    o1c_ed25519_expanded_key_s *sk = acquire(env, expandedPrivateKey);
    uint8_t *m = acquire(env, in);
    uint8_t *s = acquire(env, sig);
    o1c_ed25519_sign(s + sigOffset, m + offset, length, sk);
    release(env, sig, s);
    release(env, in, m);
    release(env, expandedPrivateKey, sk);
}

jboolean
Java_dev_o1c_lib_O1CLib_verify(JNIEnv *env, jclass cls, jbyteArray publicKey, jbyteArray in, jint offset, jint length,
                               jbyteArray sig, jint sigOffset) {
    (void) cls;
    o1c_ed25519_public_key_s *pk = acquire(env, publicKey);
    uint8_t *m = acquire(env, in);
    uint8_t *s = acquire(env, sig);
    jboolean ret = o1c_ed25519_verify(s + sigOffset, m + offset, length, pk);
    release(env, sig, s);
    release(env, in, m);
    release(env, publicKey, pk);
    return ret;
}
