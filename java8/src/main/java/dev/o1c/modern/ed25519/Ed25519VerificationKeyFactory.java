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

import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.ed25519.Ed25519PublicKey;
import dev.o1c.primitive.VerificationKey;
import dev.o1c.primitive.VerificationKeyFactory;
import org.jetbrains.annotations.NotNull;

public class Ed25519VerificationKeyFactory implements VerificationKeyFactory {
    @Override
    public int keySize() {
        return 32;
    }

    @Override
    public VerificationKey parseKey(byte @NotNull [] key) {
        checkKeySize(key.length);
        Ed25519PublicKey publicKey = null;
        try {
            publicKey = Ed25519PublicKey.fromByteArray(key);
        } catch (InvalidEncodingException e) {
            throw new IllegalArgumentException(e);
        }
        return new Ed25519VerificationKey(publicKey);
    }
}
