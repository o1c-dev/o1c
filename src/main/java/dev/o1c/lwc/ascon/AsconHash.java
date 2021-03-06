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

package dev.o1c.lwc.ascon;

import dev.o1c.spi.Hash;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class AsconHash implements Hash {
    private static final int RATE = 8;
    private static final byte PAD = (byte) 0x80;
    // 0 || rate in bits (1 byte) || # rounds (1 byte) || 0 || || hash size (32-bit)
    private static final long HASH_IV = 64L << 48 | 12L << 40 | 256;
    private static final long XOF_IV = 64L << 48 | 12L << 40;

    private final long[] state = new long[5];
    private final ByteBuffer buffer = ByteBuffer.allocate(RATE);
    private final int hashSize;
    private final long iv;

    public AsconHash() {
        hashSize = 0;
        iv = XOF_IV;
    }

    public AsconHash(int hashSize) {
        this.hashSize = hashSize;
        iv = HASH_IV;
    }

    @Override
    public int hashLength() {
        return hashSize == 0 ? 32 : hashSize;
    }

    @Override
    public void reset() {
        state[0] = iv;
        Arrays.fill(state, 1, 5, 0);
        Ascon.ascon12(state);
        buffer.clear();
    }

    @Override
    public void update(byte b) {
        if (!buffer.put(b).hasRemaining()) {
            buffer.flip();
            state[0] ^= buffer.getLong();
            buffer.clear();
            Ascon.ascon12(state);
        }
    }

    @Override
    public void update(byte @NotNull [] in, int offset, int length) {
        while (length > 0) {
            int ps = Math.min(length, buffer.remaining());
            while (ps-- > 0) {
                buffer.put(in[offset++]);
                length--;
            }
            if (!buffer.hasRemaining()) {
                buffer.flip();
                state[0] ^= buffer.getLong();
                buffer.clear();
                Ascon.ascon12(state);
            }
        }
    }

    @Override
    public void doFinalize(byte @NotNull [] out, int offset, int length) {
        buffer.put(PAD);
        buffer.flip();
        state[0] ^= ByteOps.unpackLongBE(buffer.array(), buffer.arrayOffset(), buffer.remaining());
        buffer.clear();
        while (length >= RATE) {
            Ascon.ascon12(state);
            ByteOps.packLongBE(state[0], out, offset, RATE);
            offset += RATE;
            length -= RATE;
        }
        if (length > 0) {
            Ascon.ascon12(state);
            ByteOps.packLongBE(state[0], out, offset, length);
        }
    }
}
