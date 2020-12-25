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
 */

package dev.o1c.test;

import dev.o1c.util.ByteOps;
import dev.o1c.spi.KeyExchange;
import dev.o1c.spi.KeyExchangeFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

abstract class KeyExchangeTest {
    abstract KeyExchangeFactory getX25519();

    abstract KeyExchangeFactory getX448();

    // https://tools.ietf.org/html/rfc7748#section-6.1

    @Test
    void x25519() {
        byte[] alicePrivateKey = ByteOps.fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] alicePublicKey = ByteOps.fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] bobPrivateKey = ByteOps.fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] bobPublicKey = ByteOps.fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] expectedSharedSecret = ByteOps.fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        KeyExchange exchange = getX25519().create();
        assertArrayEquals(expectedSharedSecret, exchange.calculateSharedSecret(alicePrivateKey, bobPublicKey));
        assertArrayEquals(expectedSharedSecret, exchange.calculateSharedSecret(bobPrivateKey, alicePublicKey));
    }

    // https://tools.ietf.org/html/rfc7748#section-6.2

    @Test
    void x448() {
        byte[] alicePrivateKey = ByteOps.fromHex(
                "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        byte[] alicePublicKey = ByteOps.fromHex(
                "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        byte[] bobPrivateKey = ByteOps.fromHex(
                "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        byte[] bobPublicKey = ByteOps.fromHex(
                "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        byte[] expectedSharedSecret = ByteOps.fromHex(
                "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

        KeyExchange exchange = getX448().create();
        assertArrayEquals(expectedSharedSecret, exchange.calculateSharedSecret(alicePrivateKey, bobPublicKey));
        assertArrayEquals(expectedSharedSecret, exchange.calculateSharedSecret(bobPrivateKey, alicePublicKey));
    }
}
