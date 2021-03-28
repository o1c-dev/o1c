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

import dev.o1c.spi.Cipher;
import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class ChaCha20Poly1305CipherTest {
    @Test
    void standardTest() {
        byte[] plaintext =
                "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                        .getBytes(StandardCharsets.US_ASCII);
        byte[] aad = ByteOps.fromHex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
        byte[] key = ByteOps.fromHex("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f" +
                "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
        byte[] nonce = ByteOps.fromHex("07 00 00 00 40 41 42 43 44 45 46 47");
        byte[] ciphertext = ByteOps.fromHex("d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2" +
                "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6" +
                "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b" +
                "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36" +
                "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58" +
                "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc" +
                "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b" +
                "61 16");
        byte[] tag = ByteOps.fromHex("1ae10b594f09e26a7e902ecbd0600691");

        Cipher cipher = new ChaCha20Poly1305Cipher();
        cipher.init(key, nonce, aad);
        byte[] actualCiphertext = new byte[ciphertext.length];
        byte[] actualTag = new byte[tag.length];
        cipher.encrypt(plaintext, 0, plaintext.length, actualCiphertext, 0, actualTag, 0);
        assertArrayEquals(ciphertext, actualCiphertext);
        assertArrayEquals(tag, actualTag);

        byte[] actualPlaintext = new byte[plaintext.length];
        cipher.init(key, nonce, aad);
        cipher.decrypt(ciphertext,0, ciphertext.length, tag, 0, actualPlaintext, 0);
        assertArrayEquals(plaintext, actualPlaintext);
    }
}
