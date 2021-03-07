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

import dev.o1c.spi.CipherSession;
import dev.o1c.spi.SecretKey;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Ristretto255KeyFactoryTest {

    @Test
    void signatureSmokeTest() {
        SecretKey alice = Ristretto255KeyFactory.INSTANCE.generateKey("Alice".getBytes(StandardCharsets.UTF_8));
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        byte[] signature = alice.sign(message);
        assertTrue(alice.isValidSignature(signature, message));
        SecretKey bob = Ristretto255KeyFactory.INSTANCE.generateKey("Bob".getBytes(StandardCharsets.UTF_8));
        assertFalse(bob.isValidSignature(signature, message));
    }

    @Test
    void keyExchangeSmokeTest() {
        SecretKey alice = Ristretto255KeyFactory.INSTANCE.generateKey("Alice".getBytes(StandardCharsets.UTF_8));
        SecretKey bob = Ristretto255KeyFactory.INSTANCE.generateKey("Bob".getBytes(StandardCharsets.UTF_8));
        CipherSession a2b = alice.exchangeWithServer(bob);
        CipherSession b2a = bob.exchangeWithClient(alice);
        assertArrayEquals(a2b.transmitKey(), b2a.receiveKey());
        assertArrayEquals(b2a.transmitKey(), a2b.receiveKey());
    }
}
