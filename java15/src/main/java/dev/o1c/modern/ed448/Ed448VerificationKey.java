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

import dev.o1c.primitive.VerificationKey;
import dev.o1c.spi.InvalidSignatureException;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

class Ed448VerificationKey implements VerificationKey {
    private final Signature signature = Ed448.getSignature();

    Ed448VerificationKey(@NotNull PublicKey publicKey) {
        try {
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public int signatureSize() {
        return 114;
    }

    @Override
    public void verify(
            byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
        try {
            this.signature.update(message, offset, length);
            if (!this.signature.verify(signature, sigOffset, signatureSize())) {
                throw new InvalidSignatureException("Signature mismatch");
            }
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }
}
