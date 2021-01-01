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

import dev.o1c.spi.RandomBytesGenerator;
import dev.o1c.spi.SeedGenerator;
import org.jetbrains.annotations.NotNull;

// https://doi.org/10.6028/NIST.SP.800-90Ar1
// implements an HMAC_DRBG using Xoodyak
public class XoodyakRandomBytesGenerator implements RandomBytesGenerator {
    private static final ThreadLocal<XoodyakRandomBytesGenerator> CURRENT = new ThreadLocal<>();
    private final Xoodyak xoodyak = new Xoodyak();
    private long counter;

    public XoodyakRandomBytesGenerator() {
        reseed();
    }

    private void reseed() {
        byte[] seed = SeedGenerator.getInstance().generateSeed(42);
        xoodyak.initialize(seed);
        counter = 0;
    }

    @Override
    public byte @NotNull [] generateBytes(int nrBytes) {
        byte[] bytes = new byte[nrBytes];
        xoodyak.squeeze(bytes, 0, bytes.length);
        xoodyak.ratchet();
        if (++counter < 0) {
            reseed();
        }
        return bytes;
    }

    public static @NotNull XoodyakRandomBytesGenerator getInstance() {
        if (CURRENT.get() == null) {
            CURRENT.set(new XoodyakRandomBytesGenerator());
        }
        return CURRENT.get();
    }
}
