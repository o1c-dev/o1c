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

import cafe.cryptography.ed25519.Ed25519ExpandedPrivateKey;
import cafe.cryptography.ed25519.Ed25519PublicKey;
import dev.o1c.primitive.SignatureKey;
import dev.o1c.primitive.VerificationKey;
import org.jetbrains.annotations.NotNull;

class Ed25519SignatureKey implements SignatureKey {
    private final Ed25519ExpandedPrivateKey key;
    private final Ed25519PublicKey publicKey;

    Ed25519SignatureKey(@NotNull Ed25519ExpandedPrivateKey key) {
        this.key = key;
        publicKey = key.derivePublic();
    }

    @Override
    public int signatureSize() {
        return 64;
    }

    @Override
    public VerificationKey verificationKey() {
        return new Ed25519VerificationKey(publicKey);
    }

    @Override
    public void sign(
            byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
        System.arraycopy(key.sign(message, offset, length, publicKey).toByteArray(), 0, signature, sigOffset, signatureSize());
    }
}
