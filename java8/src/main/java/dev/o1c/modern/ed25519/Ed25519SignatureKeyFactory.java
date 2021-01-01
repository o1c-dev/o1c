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

import cafe.cryptography.ed25519.Ed25519PrivateKey;
import dev.o1c.lwc.gimli.GimliRandomBytesGenerator;
import dev.o1c.primitive.SignatureKey;
import dev.o1c.primitive.SignatureKeyFactory;
import org.jetbrains.annotations.NotNull;

public class Ed25519SignatureKeyFactory implements SignatureKeyFactory {
    @Override
    public int keySize() {
        return 32;
    }

    @Override
    public SignatureKey generateKey() {
        return parseKey(GimliRandomBytesGenerator.getInstance().generateBytes(keySize()));
    }

    @Override
    public SignatureKey parseKey(byte @NotNull [] key) {
        checkKeySize(key.length);
        Ed25519PrivateKey privateKey = Ed25519PrivateKey.fromByteArray(key);
        return new Ed25519SignatureKey(privateKey.expand());
    }
}
