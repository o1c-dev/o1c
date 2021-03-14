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

package dev.o1c.impl.chacha20;

import dev.o1c.util.ByteOps;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class ChaCha20 {
    private static final int BLOCK_BYTES = 64;
    private static final int BLOCK_INTS = BLOCK_BYTES / Integer.BYTES;
    private static final int KEY_OFFSET = 4;
    private static final int KEY_BYTES = 32;
    private static final int KEY_INTS = KEY_BYTES / Integer.BYTES;
    private static final int COUNTER_OFFSET = 12;
    private static final int HNONCE_OFFSET = 12;
    private static final int HNONCE_BYTES = 16;
    private static final int HNONCE_INTS = HNONCE_BYTES / Integer.BYTES;
    private static final int NONCE_OFFSET = 13;
    private static final int NONCE_BYTES = 12;
    private static final int NONCE_INTS = NONCE_BYTES / Integer.BYTES;
    private static final int[] ENGINE_STATE_HEADER =
            ByteOps.unpackIntsLE("expand 32-byte k".getBytes(StandardCharsets.US_ASCII), 0, 4);

    private final int[] x = new int[BLOCK_INTS];
    private final int[] engineState = new int[BLOCK_INTS];

    ChaCha20() {
        System.arraycopy(ENGINE_STATE_HEADER, 0, engineState, 0, 4);
    }

    void initKey(byte[] key) {
        ByteOps.unpackIntsLE(key, 0, KEY_INTS, engineState, KEY_OFFSET);
    }

    void initNonce(byte[] nonce) {
        ByteOps.unpackIntsLE(nonce, 0, NONCE_INTS, engineState, NONCE_OFFSET);
    }

    void initCounter(int counter) {
        engineState[COUNTER_OFFSET] = counter;
    }

    // one-shot usage
    void crypt(byte[] in, int offset, int length, byte[] out, int outOffset) {
        while (length > 0) {
            System.arraycopy(engineState, 0, x, 0, BLOCK_INTS);
            permute(x);
            int want = Math.min(BLOCK_BYTES, length);
            for (int i = 0, j = 0; i < want; i += Integer.BYTES, j++) {
                int keyStream = engineState[j] + x[j];
                int take = Math.min(Integer.BYTES, length);
                int input = ByteOps.unpackIntLE(in, offset, take);
                int output = keyStream ^ input;
                ByteOps.packIntLE(output, out, outOffset, take);
                offset += take;
                outOffset += take;
                length -= take;
            }
            engineState[COUNTER_OFFSET]++;
        }
    }

    byte[] polyKey() {
        byte[] block = new byte[BLOCK_BYTES];
        initCounter(0);
        crypt(block, 0, block.length, block, 0);
        return Arrays.copyOf(block, KEY_BYTES);
    }

    byte[] hKey(byte[] nonce) {
        ByteOps.unpackIntsLE(nonce, 0, HNONCE_INTS, engineState, HNONCE_OFFSET);
        System.arraycopy(engineState, 0, x, 0, BLOCK_INTS);
        permute(x);
        byte[] hKey = new byte[KEY_BYTES];
        ByteOps.packIntsLE(x, 0, 4, hKey, 0);
        ByteOps.packIntsLE(x, 12, 4, hKey, 16);
        return hKey;
    }

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
