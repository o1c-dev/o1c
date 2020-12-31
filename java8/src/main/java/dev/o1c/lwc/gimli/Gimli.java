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

package dev.o1c.lwc.gimli;

import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;
import org.jetbrains.annotations.VisibleForTesting;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

class Gimli {
    private static final int ROUND_CONSTANT = 0x9e377900;
    private static final int RATE = 16;
    private static final int STATE_SIZE = 48;

    private final int[] state = new int[STATE_SIZE / Integer.BYTES];

    void permute() {
        for (int round = 24; round > 0; round--) {
            // SP-box
            for (int i = 0; i < 4; i++) {
                int x = Integer.rotateLeft(state[i], 24);
                int y = Integer.rotateLeft(state[i + 4], 9);
                int z = state[i + 8];
                state[i + 8] = x ^ (z << 1) ^ ((y & z) << 2);
                state[i + 4] = y ^ x ^ ((x | z) << 1);
                state[i] = z ^ y ^ ((x & y) << 3);
            }
            // linear layer
            int t;
            switch (round & 3) {
                case 0:
                    // small swao (1032)
                    t = state[0];
                    state[0] = state[1];
                    state[1] = t;
                    t = state[2];
                    state[2] = state[3];
                    state[3] = t;
                    state[0] ^= ROUND_CONSTANT | round;
                    break;

                case 2:
                    // big swap (2031)
                    t = state[0];
                    state[0] = state[2];
                    state[2] = t;
                    t = state[1];
                    state[1] = state[3];
                    state[3] = t;
                    break;

                default:
                    break;
            }
        }
    }

    @VisibleForTesting
    void init(int @NotNull [] state) {
        System.arraycopy(state, 0, this.state, 0, state.length);
    }

    @VisibleForTesting
    int @NotNull [] extract() {
        return state.clone();
    }

    void init(byte @NotNull [] key, byte @NotNull [] nonce) {
        ByteOps.unpackIntsLE(nonce, 0, nonce.length / Integer.BYTES, state, 0);
        ByteOps.unpackIntsLE(key, 0, key.length / Integer.BYTES, state, nonce.length / Integer.BYTES);
        permute();
    }

    void ratchet(long counter) {
        state[0] = (int) counter;
        state[1] = (int) (counter >> Integer.SIZE);
        state[2] = 0;
        state[3] = 0;
        permute();
    }

    void absorb(@Range(from = 0, to = 47) int at, byte v) {
        int d = at / Integer.BYTES;
        int r = at % Integer.BYTES;
        state[d] ^= Byte.toUnsignedInt(v) << r * Byte.SIZE;
    }

    int absorb(@Range(from = 0, to = 11) int at, int v) {
        return state[at] ^= v;
    }

    void absorb(byte @NotNull [] in) {
        absorb(in, 0, in.length);
    }

    void absorb(byte @NotNull [] in, int offset, int length) {
        while (length >= RATE) {
            for (int i = 0; i < RATE / Integer.BYTES; i++) {
                absorb(i, ByteOps.unpackIntLE(in, offset));
                offset += Integer.BYTES;
            }
            length -= RATE;
            permute();
        }
        int nrInts = length / Integer.BYTES;
        for (int i = 0; i < nrInts; i++) {
            absorb(i, ByteOps.unpackIntLE(in, offset));
            offset += Integer.BYTES;
            length -= Integer.BYTES;
        }
        absorb(nrInts, ByteOps.unpackIntLE(in, offset, length));
        absorb(nrInts, 1 << length * Byte.SIZE);
        absorb(47, (byte) 1);
        permute();
    }

    void encrypt(byte @NotNull [] in, int offset, int length, byte @NotNull [] out, int outOffset) {
        while (length >= RATE) {
            for (int i = 0; i < RATE / Integer.BYTES; i++) {
                ByteOps.packIntLE(absorb(i, ByteOps.unpackIntLE(in, offset)), out, outOffset);
                offset += Integer.BYTES;
                outOffset += Integer.BYTES;
            }
            length -= RATE;
            permute();
        }
        int nrInts = length / Integer.BYTES;
        for (int i = 0; i < nrInts; i++) {
            ByteOps.packIntLE(absorb(i, ByteOps.unpackIntLE(in, offset)), out, outOffset);
            offset += Integer.BYTES;
            outOffset += Integer.BYTES;
            length -= Integer.BYTES;
        }
        ByteOps.packIntLE(absorb(nrInts, ByteOps.unpackIntLE(in, offset, length)), out, outOffset, length);
        absorb(nrInts, 1 << length * Byte.SIZE);
        absorb(47, (byte) 1);
    }

    void decrypt(byte @NotNull [] in, int offset, int length, byte @NotNull [] out, int outOffset) {
        while (length >= RATE) {
            for (int i = 0; i < RATE / Integer.BYTES; i++) {
                int ci = ByteOps.unpackIntLE(in, offset);
                ByteOps.packIntLE(state[i] ^ ci, out, outOffset);
                state[i] = ci;
                offset += Integer.BYTES;
                outOffset += Integer.BYTES;
            }
            length -= RATE;
            permute();
        }
        int nrInts = length / Integer.BYTES;
        for (int i = 0; i < nrInts; i++) {
            int ci = ByteOps.unpackIntLE(in, offset);
            ByteOps.packIntLE(state[i] ^ ci, out, outOffset);
            state[i] = ci;
            offset += Integer.BYTES;
            outOffset += Integer.BYTES;
            length -= Integer.BYTES;
        }
        byte[] si = new byte[Integer.BYTES];
        ByteOps.packIntLE(state[nrInts], si, 0);
        for (int i = 0; i < length; i++) {
            out[outOffset++] = (byte) (si[i] ^ in[offset]);
            si[i] = in[offset++];
        }
        si[length] ^= 1;
        state[nrInts] = ByteOps.unpackIntLE(si, 0);
        absorb(47, (byte) 1);
    }

    void squeeze(byte @NotNull [] out) {
        squeeze(out, 0, out.length);
    }

    void squeeze(byte @NotNull [] out, int offset, int length) {
        while (length >= RATE) {
            permute();
            ByteOps.packIntsLE(state, 0, RATE / Integer.BYTES, out, offset);
            offset += RATE;
            length -= RATE;
        }
        if (length > 0) {
            permute();
            int fullInts = length / Integer.BYTES;
            ByteOps.packIntsLE(state, 0, fullInts, out, offset);
            int partialBytes = length % Integer.BYTES;
            ByteOps.packIntLE(state[fullInts], out, offset + fullInts * Integer.BYTES, partialBytes);
        }
    }

    void squeeze(ByteBuffer out) {
        if (out.remaining() % RATE != 0) {
            throw new UnsupportedOperationException("TODO");
        }
        out.order(ByteOrder.LITTLE_ENDIAN);
        while (out.remaining() >= RATE) {
            permute();
            out.putInt(state[0]).putInt(state[1]).putInt(state[2]).putInt(state[3]);
        }
    }

    void reset() {
        Arrays.fill(state, 0);
    }
}
