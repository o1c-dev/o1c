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

package dev.o1c;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class KeyManagerTest {

    private final KeyManager keyManager = KeyManager.getInstance();

    @Test
    void signatureSmokeTest() {
        KeyPair keyPair = keyManager.generateKeyPair();
        for (int i = 0; i < 10; i++) {
            byte[] message = generateTestVector(i);
            assertArrayEquals(message, keyPair.openSignedMessage(keyPair.sign(message)));
        }
    }

    @Test
    void secretBoxSmokeTest() {
        SecretKey key = keyManager.generateSecretKey();
        for (int i = 0; i < 10; i++) {
            byte[] data = generateTestVector(i);
            for (int j = 0; j < 10; j++) {
                byte[] context = generateTestVector(j);
                assertArrayEquals(data, key.openBox(key.box(data, context), context));
            }
        }
    }

    @Test
    void boxSmokeTest() {
        KeyPair alice = keyManager.generateKeyPair();
        KeyPair bob = keyManager.generateKeyPair();
        for (int i = 0; i < 10; i++) {
            byte[] message = generateTestVector(i);
            for (int j = 0; j < 10; j++) {
                byte[] context = generateTestVector(j);
                assertArrayEquals(message, bob.openBox(alice, alice.box(bob, message, context), context));
            }
        }
    }

    @Test
    void sealedBoxSmokeTest() {
        KeyPair alice = keyManager.generateKeyPair();
        KeyPair bob = keyManager.generateKeyPair();
        for (int i = 0; i < 10; i++) {
            byte[] message = generateTestVector(i);
            for (int j = 0; j < 10; j++) {
                byte[] context = generateTestVector(j);
                assertArrayEquals(message, bob.openSealedBox(alice, alice.sealedBox(bob, message, context), context));
            }
        }
    }

    private byte[] generateTestVector(int length) {
        byte[] vector = new byte[length];
        for (int i = 0; i < length; i++) {
            vector[i] = (byte) (i % 111);
        }
        return vector;
    }
}
