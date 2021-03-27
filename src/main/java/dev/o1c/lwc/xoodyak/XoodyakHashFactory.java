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

import dev.o1c.spi.Hash;
import dev.o1c.spi.HashFactory;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

public class XoodyakHashFactory implements HashFactory {
    @Override
    public @NotNull Hash newHash() {
        return new ExtensibleOutputFunction();
    }

    @Override
    public @NotNull Hash newHash(@Range(from = 0, to = Integer.MAX_VALUE) int hashLength) {
        return new ExtensibleOutputFunction(hashLength);
    }

    @Override
    public @NotNull Hash newKeyedHash(byte @NotNull [] key) {
        return new KeyedHash(key);
    }

    @Override
    public @NotNull Hash newKeyDerivationFunction(byte @NotNull [] context) {
        return new KeyDerivationFunction(context);
    }
}
