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

package dev.o1c.lwc.xoodyak;

import dev.o1c.primitive.CipherKey;
import dev.o1c.primitive.CipherKeyFactory;
import dev.o1c.primitive.RandomBytesGenerator;
import org.jetbrains.annotations.NotNull;

public class XoodyakCipherKeyFactory implements CipherKeyFactory {
    private final RandomBytesGenerator randomBytesGenerator;

    public XoodyakCipherKeyFactory(RandomBytesGenerator randomBytesGenerator) {
        this.randomBytesGenerator = randomBytesGenerator;
    }

    @Override
    public int keySize() {
        return 16;
    }

    @Override
    public CipherKey generateKey() {
        return parseKey(randomBytesGenerator.generateBytes(keySize()));
    }

    @Override
    public CipherKey parseKey(byte @NotNull [] key) {
        checkKeySize(key.length);
        return new XoodyakCipherKey(key);
    }
}
