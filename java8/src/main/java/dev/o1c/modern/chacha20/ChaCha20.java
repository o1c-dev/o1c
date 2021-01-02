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

package dev.o1c.modern.chacha20;

class ChaCha20 {
    /**
     * Performs an in-place ChaCha20 permutation on the provided state array.
     *
     * @param state length 16 array of internal state decoded from a little endian byte array
     */
    static void permute(int[] state) {
        for (int i = 0; i < 10; i++) {
            columnRound(state);
            diagonalRound(state);
        }
    }

    private static void columnRound(int[] state) {
        quarterRound(state, 0, 4, 8, 12);
        quarterRound(state, 1, 5, 9, 13);
        quarterRound(state, 2, 6, 10, 14);
        quarterRound(state, 3, 7, 11, 15);
    }

    private static void diagonalRound(int[] state) {
        quarterRound(state, 0, 5, 10, 15);
        quarterRound(state, 1, 6, 11, 12);
        quarterRound(state, 2, 7, 8, 13);
        quarterRound(state, 3, 4, 9, 14);
    }

    private static void quarterRound(int[] state, int a, int b, int c, int d) {
        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);

        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);

        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);

        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
    }
}
