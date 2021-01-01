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

package dev.o1c.modern.ed25519;

import cafe.cryptography.ed25519.Ed25519PublicKey;
import cafe.cryptography.ed25519.Ed25519Signature;
import dev.o1c.primitive.VerificationKey;
import dev.o1c.spi.InvalidSignatureException;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Objects;

class Ed25519VerificationKey implements VerificationKey {
    private final Ed25519PublicKey key;

    Ed25519VerificationKey(@NotNull Ed25519PublicKey key) {
        this.key = key;
    }

    @Override
    public int signatureSize() {
        return 64;
    }

    @Override
    public void verify(
            byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
        Ed25519Signature sig =
                Ed25519Signature.fromByteArray(Arrays.copyOfRange(signature, sigOffset, sigOffset + signatureSize()));
        if (!key.verify(message, offset, length, sig)) {
            throw new InvalidSignatureException("Signature mismatch");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof Ed25519VerificationKey))
            return false;
        Ed25519VerificationKey that = (Ed25519VerificationKey) o;
        return key.equals(that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key);
    }
}