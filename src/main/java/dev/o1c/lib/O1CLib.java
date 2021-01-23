/*
 * ISC License
 *
 * Copyright (c) 2021, Matt Sicker
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: ISC
 */

package dev.o1c.lib;

class O1CLib {
    static native void randomBytes(byte[] buf);

    static native void entropyBytes(byte[] buf);

    static native int hashStateSize(); // dependent on runtime arch

    static native void hashInit(byte[] hashState);

    static native void keyedHashInit(byte[] hashState, byte[] key);

    static native void kdfHashInit(byte[] hashState, byte[] context);

    static native void hashUpdate(byte[] hashState, byte[] in, int offset, int length);

    static native void hashFinal(byte[] hashState, byte[] out, int offset, int length);

    // optimized form allowing for stack-allocated hash state
    static native void hash(byte[] in, int offset, int length, byte[] hash, int hashOffset, int hashLength);

    static native void keyedHash(byte[] key, byte[] in, int offset, int length, byte[] out, int outOffset, int outLength);

    static native void scalarFieldBaseMultiply(byte[] result, byte[] scalar);

    static native void scalarFieldMultiply(byte[] result, byte[] scalar, byte[] fieldElement);

    static native void generateScalarFieldKeyPair(byte[] publicKey, byte[] privateKey);

    static native void authenticatedEncrypt(
            byte[] key, byte[] nonce, byte[] context, byte[] pt, int offset, int length, byte[] ct, int ctOffset, byte[] tag,
            int tagOffset);

    static native boolean authenticatedDecrypt(
            byte[] key, byte[] nonce, byte[] context, byte[] ct, int offset, int length, byte[] tag, int tagOffset, byte[] pt,
            int ptOffset);

    static native void deriveKeyPairFromSeed(byte[] publicKey, byte[] expandedPrivateKey, byte[] seed);

    static native void generateSignKeyPair(byte[] publicKey, byte[] expandedPrivateKey);

    static native void sign(byte[] expandedPrivateKey, byte[] in, int offset, int length, byte[] sig, int sigOffset);

    static native boolean verify(byte[] publicKey, byte[] in, int offset, int length, byte[] sig, int sigOffset);
}
