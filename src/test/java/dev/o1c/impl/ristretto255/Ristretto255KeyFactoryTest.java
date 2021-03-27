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

package dev.o1c.impl.ristretto255;

import dev.o1c.impl.blake3.Blake3RandomBytesGenerator;
import dev.o1c.spi.KeyFactory;
import dev.o1c.spi.KeyPair;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Ristretto255KeyFactoryTest {

    private final KeyFactory keyFactory = new Ristretto255KeyFactory();
    private final KeyPair alice = keyFactory.generateKey("Alice".getBytes(StandardCharsets.UTF_8));
    private final KeyPair bob = keyFactory.generateKey("Bob".getBytes(StandardCharsets.UTF_8));

    @Test
    void signatureSmokeTest() {
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        byte[] signature = alice.sign(message);
        assertTrue(alice.isValidSignature(signature, message));
        assertFalse(bob.isValidSignature(signature, message));
    }

    @Test
    void keyExchangeSmokeTest() {
        byte[] a2b = alice.exchangeSecret(bob);
        byte[] b2a = bob.exchangeSecret(alice);
        assertArrayEquals(a2b, b2a);
    }

    @Test
    void signcryptSmokeTest() {
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        byte[] context = "Fresh-ground fresh-roasted fresh-brewed coffee".getBytes(StandardCharsets.UTF_8);
        byte[] tag = new byte[16];
        byte[] sig = new byte[64];
        byte[] nonce = Blake3RandomBytesGenerator.getInstance().generateBytes(24);
        byte[] ciphertext = new byte[message.length];
        byte[] plaintext = new byte[message.length];

        alice.signcrypt(bob, nonce, context, message, 0, message.length, ciphertext, 0, tag, 0, sig, 0);
        bob.unsigncrypt(alice, nonce, context, ciphertext, 0, ciphertext.length, tag, 0, sig, 0, plaintext, 0);
        assertArrayEquals(message, plaintext);
    }

    @Test
    void encryptSmokeTest() {
        byte[] message = "Another encryption smoke test".getBytes(StandardCharsets.UTF_8);
        byte[] context = getClass().getName().getBytes(StandardCharsets.UTF_8);
        byte[] nonce = Blake3RandomBytesGenerator.getInstance().generateBytes(24);
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[message.length];
        byte[] plaintext = new byte[message.length];

        alice.encrypt(bob, nonce, context, message, 0, message.length, ciphertext, 0, tag, 0);
        bob.decrypt(alice, nonce, context, ciphertext, 0, ciphertext.length, tag, 0, plaintext, 0);
        assertArrayEquals(message, plaintext);
    }
}
