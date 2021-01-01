/*
 * ISC License
 *
 * Copyright (c) 2020, Matt Sicker
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

package dev.o1c.modern.ed448;

import dev.o1c.primitive.SignatureKey;
import dev.o1c.primitive.VerificationKey;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

class Ed448SignatureKey implements SignatureKey {
    private final Signature signature = Ed448.getSignature();
    private final PublicKey publicKey;

    Ed448SignatureKey(@NotNull KeyPair keyPair) {
        publicKey = keyPair.getPublic();
        try {
            signature.initSign(keyPair.getPrivate());
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public int signatureSize() {
        return 114;
    }

    @Override
    public VerificationKey verificationKey() {
        return new Ed448VerificationKey(publicKey);
    }

    @Override
    public void sign(
            byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
        try {
            this.signature.update(message, offset, length);
            this.signature.sign(signature, sigOffset, signatureSize());
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }
}
