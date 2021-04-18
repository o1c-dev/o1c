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

package dev.o1c.impl;

import dev.o1c.SecretKey;
import dev.o1c.impl.blake3.Blake3RandomBytesGenerator;
import dev.o1c.impl.chacha20.XChaCha20Poly1305Cipher;
import dev.o1c.spi.Cipher;
import org.jetbrains.annotations.NotNull;

class DefaultSecretKey implements SecretKey {
    private final Cipher cipher = new XChaCha20Poly1305Cipher();
    private final byte[] key;

    DefaultSecretKey() {
        key = Blake3RandomBytesGenerator.getInstance().generateBytes(cipher.keyLength());
    }

    DefaultSecretKey(byte @NotNull [] key) {
        cipher.checkKeyLength(key.length);
        this.key = key.clone();
    }

    @Override
    public byte @NotNull [] box(byte @NotNull [] data, byte @NotNull [] context) {
        // todo: header data?
        int nonceLength = cipher.nonceLength();
        int length = data.length;
        byte[] secretBox = new byte[length + nonceLength + cipher.tagLength()];
        Blake3RandomBytesGenerator.getInstance().generateBytes(secretBox, 0, nonceLength);
        cipher.init(key, secretBox, context);
        cipher.encrypt(data, 0, length, secretBox, nonceLength, secretBox, nonceLength + length);
        return secretBox;
    }

    @Override
    public byte @NotNull [] openBox(byte @NotNull [] box, byte @NotNull [] context) {
        int nonceLength = cipher.nonceLength();
        byte[] data = new byte[box.length - nonceLength - cipher.tagLength()];
        cipher.init(key, box, context);
        cipher.decrypt(box, nonceLength, data.length, box, nonceLength + data.length, data, 0);
        return data;
    }

    public int nonceLength() {
        return cipher.nonceLength();
    }

    public int tagLength() {
        return cipher.tagLength();
    }
}
