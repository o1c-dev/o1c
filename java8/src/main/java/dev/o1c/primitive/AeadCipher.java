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

package dev.o1c.primitive;

import dev.o1c.lwc.gimli.GimliRandomBytesGenerator;
import org.jetbrains.annotations.NotNull;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public interface AeadCipher {
    int keySize();

    default void checkKeySize(int keySize) {
        if (keySize != keySize()) {
            throw new IllegalArgumentException("Key must be " + keySize() + " bytes but got " + keySize);
        }
    }

    int nonceSize();

    default void checkNonceSize(int nonceSize) {
        if (nonceSize != nonceSize()) {
            throw new IllegalArgumentException("Nonce must be " + nonceSize() + " bytes but got " + nonceSize);
        }
    }

    int tagSize();

    @NotNull String algorithm();

    default @NotNull SecretKey generateKey() {
        // TODO: RNG default based on algorithm
        return new SecretKeySpec(GimliRandomBytesGenerator.getInstance().generateBytes(keySize()), algorithm());
    }

    void encrypt(@NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] out, int outOffset, byte @NotNull [] tag, int tagOffset);

    void decrypt(
            @NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] tag, int tagOffset, byte @NotNull [] out, int outOffset);

}
