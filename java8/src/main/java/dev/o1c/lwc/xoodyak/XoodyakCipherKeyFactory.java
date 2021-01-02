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

package dev.o1c.lwc.xoodyak;

import dev.o1c.spi.CipherKey;
import dev.o1c.spi.CipherKeyFactory;
import org.jetbrains.annotations.NotNull;

public class XoodyakCipherKeyFactory implements CipherKeyFactory {

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public CipherKey generateKey() {
        return parseKey(XoodyakRandomBytesGenerator.getInstance().generateBytes(keyLength()));
    }

    @Override
    public CipherKey parseKey(byte @NotNull [] key) {
        checkKeyLength(key.length);
        return new XoodyakCipherKey(key);
    }
}
