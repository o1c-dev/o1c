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
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

// https://doi.org/10.6028/NIST.SP.800-90Ar1
// implements an HMAC_DRBG using Xoodyak
public class XoodyakRandomBytesGenerator implements RandomBytesGenerator {
    private static final ThreadLocal<XoodyakRandomBytesGenerator> CURRENT = new ThreadLocal<>();
    private static final int SEED_LENGTH = 42;
    private final Xoodyak xoodyak = new Xoodyak();
    private long counter;
    private final byte[] counterBuf = new byte[Long.BYTES];

    public XoodyakRandomBytesGenerator() {
        reseed();
    }

    private void reseed() {
        byte[] seed = SeedGenerator.getInstance().generateSeed(SEED_LENGTH);
        xoodyak.initialize(seed);
        xoodyak.ratchet();
        counter = 0;
    }

    private void ratchet() {
        if (++counter == 0) {
            reseed();
        } else {
            // trickle in the counter similar to initialize()
            ByteOps.packLongBE(counter, counterBuf, 0);
            int offset = 0;
            for (int i = 0; i < Long.BYTES; i++) {
                if (counterBuf[i] == 0) {
                    offset++;
                }
            }
            xoodyak.absorbAny(Cyclist.DomainConstant.Block, 1, counterBuf, offset, Long.BYTES - offset);
            xoodyak.ratchet();
        }
    }

    @Override
    public void generateBytes(byte @NotNull [] out, int offset, int length) {
        xoodyak.squeeze(out, offset, length);
        ratchet();
    }

    public static @NotNull XoodyakRandomBytesGenerator getInstance() {
        if (CURRENT.get() == null) {
            CURRENT.set(new XoodyakRandomBytesGenerator());
        }
        return CURRENT.get();
    }
}
