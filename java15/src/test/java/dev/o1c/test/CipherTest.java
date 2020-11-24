/*
 * Copyright 2020 Matt Sicker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.o1c.test;

import dev.o1c.spi.Cipher;
import dev.o1c.spi.CipherFactory;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

abstract class CipherTest {
    abstract CipherFactory getCipherFactory();

    // https://tools.ietf.org/html/rfc7539#section-2.8.2

    @Test
    void rfc7539() {
        byte[] plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, " +
                "sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
        byte[] aad = Hex.decode("50515253c0c1c2c3c4c5c6c7");
        byte[] key = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = Hex.decode("070000004041424344454647");
        byte[] expectedCiphertext = Hex.decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116");
        byte[] expectedTag = Hex.decode("1ae10b594f09e26a7e902ecbd0600691");

        Cipher cipher = getCipherFactory().create();

        byte[] ciphertext = cipher.encryptAAD(key, nonce, plaintext, aad);
        assertArrayEquals(expectedCiphertext, Arrays.copyOfRange(ciphertext, 0, expectedCiphertext.length));
        assertArrayEquals(expectedTag, Arrays.copyOfRange(ciphertext, expectedCiphertext.length, ciphertext.length));

        byte[] input = new byte[expectedCiphertext.length + expectedTag.length];
        System.arraycopy(expectedCiphertext, 0, input, 0, expectedCiphertext.length);
        System.arraycopy(expectedTag, 0, input, expectedCiphertext.length, expectedTag.length);
        assertArrayEquals(plaintext, cipher.decryptAAD(key, nonce, input, aad));
    }

}