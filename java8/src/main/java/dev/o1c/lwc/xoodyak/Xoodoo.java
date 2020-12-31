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

import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.util.Arrays;

/**
 * Encapsulates the 3x4x4 Xoodoo permutation and state. Ported from the
 * <a href="https://github.com/XKCP/XKCP/blob/master/lib/low/Xoodoo/ref/Xoodoo-reference.c">reference C implementation</a>.
 *
 * @see <a href="https://github.com/XKCP/XKCP">Xoodoo and Keccak Code Package reference implementations</a>
 * @see <a href="https://github.com/KeccakTeam/Xoodoo/">Xoodoo C++ and Python reference implementations</a>
 */
class Xoodoo {
    private static final int MAX_ROUNDS = 12;
    private static final int ROWS = 3;
    private static final int COLS = 4;
    private static final int LANES = ROWS * COLS;
    private static final int STATE_SIZE = 48;
    private static final int[] ROUND_CONSTANTS = {
            0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014,
            0x00000060, 0x0000002C, 0x00000380, 0x000000F0, 0x000001A0, 0x00000012
    };

    private final byte[] state = new byte[STATE_SIZE];
    private final int[] a = new int[LANES];
    private final int[] b = new int[LANES];
    private final int[] p = new int[COLS];
    private final int[] e = new int[COLS];

    void reset() {
        ByteOps.overwriteWithZeroes(state);
        Arrays.fill(a, 0);
        Arrays.fill(b, 0);
        Arrays.fill(p, 0);
        Arrays.fill(e, 0);
    }

    void permute() {
        ByteOps.unpackIntsLE(state, 0, LANES, a, 0);
        for (int round = 0; round < MAX_ROUNDS; round++) {
            // Theta: Column Parity Mixer
            for (int x = 0; x < COLS; x++) {
                p[x] = 0;
                for (int y = 0; y < ROWS; y++) {
                    p[x] ^= a[x + COLS * y];
                }
            }
            for (int x = 0; x < COLS; x++) {
                int z = (x + 3) % COLS;
                e[x] = Integer.rotateLeft(p[z], 5) ^ Integer.rotateLeft(p[z], 14);
            }
            for (int x = 0; x < COLS; x++) {
                for (int y = 0; y < ROWS; y++) {
                    int z = x + y * COLS;
                    a[z] ^= e[x];
                }
            }

            // Rho-west: plane shift
            for (int x = 0; x < COLS; x++) {
                b[x] = a[x];
                int z = x + COLS;
                b[z] = a[COLS + (x + 3) % COLS];
                z += COLS;
                b[z] = Integer.rotateLeft(a[z], 11);
            }
            System.arraycopy(b, 0, a, 0, LANES);

            // Iota: round constant
            a[0] ^= ROUND_CONSTANTS[round];

            // Chi: non linear layer
            for (int x = 0; x < COLS; x++) {
                for (int y = 0; y < ROWS; y++) {
                    int z0 = y * COLS + x;
                    int z1 = (y + 1) % ROWS * COLS + x;
                    int z2 = (y + 2) % ROWS * COLS + x;
                    b[z0] = a[z0] ^ ~a[z1] & a[z2];
                }
            }
            System.arraycopy(b, 0, a, 0, LANES);

            // Rho-east: plane shift
            for (int x = 0; x < COLS; x++) {
                b[x] = a[x];
                int z = x + COLS;
                b[z] = Integer.rotateLeft(a[z], 1);
                z += COLS;
                b[z] = Integer.rotateLeft(a[(x + 2) % COLS + 2 * COLS], 8);
            }
            System.arraycopy(b, 0, a, 0, LANES);
        }
        Arrays.fill(b, 0);
        Arrays.fill(p, 0);
        Arrays.fill(e, 0);
        // store
        ByteOps.packIntsLE(a, 0, LANES, state, 0);
        Arrays.fill(a, 0);
    }

    void addByte(@Range(from = 0, to = 47) int at, byte v) {
        state[at] ^= v;
    }

    void addBytes(byte @NotNull [] in, int offset, int length) {
        for (int i = 0; i < length; i++) {
            state[i] ^= in[offset + i];
        }
    }

    void extractBytes(byte @NotNull [] out, int offset, int length) {
        System.arraycopy(state, 0, out, offset, length);
    }

    void extractAndAddBytes(byte @NotNull [] in, int offset, int length, byte @NotNull [] out, int outOffset) {
        for (int i = 0; i < length; i++) {
            out[outOffset + i] = (byte) (in[offset + i] ^ state[i]);
        }
    }
}
