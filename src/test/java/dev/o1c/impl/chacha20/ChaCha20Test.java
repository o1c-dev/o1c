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
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class ChaCha20Test {
    private static final String PLAINTEXT =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    private static final byte[] CIPHERTEXT =
            ByteOps.fromHex("6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81" +
                    "e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b" +
                    "f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57" +
                    "16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8" +
                    "07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e" +
                    "52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36" +
                    "5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42" +
                    "87 4d");

    @Test
    void standardTest() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
        ChaCha20 chaCha20 = new ChaCha20();
        chaCha20.initKey(key);
        chaCha20.initNonce(nonce);
        chaCha20.initCounter(1);
        byte[] plaintext = PLAINTEXT.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length];
        chaCha20.crypt(plaintext, 0, plaintext.length, ciphertext, 0);
        assertArrayEquals(CIPHERTEXT, ciphertext);

        chaCha20.initCounter(1);
        byte[] decrypted = new byte[plaintext.length];
        chaCha20.crypt(ciphertext, 0, ciphertext.length, decrypted, 0);
        assertArrayEquals(plaintext, decrypted);
    }
}
