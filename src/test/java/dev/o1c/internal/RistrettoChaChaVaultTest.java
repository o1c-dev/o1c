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

package dev.o1c.internal;

import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@EnabledForJreRange(min = JRE.JAVA_11)
class RistrettoChaChaVaultTest {

    public static final String TEST_MSG = "Ristretto is traditionally a short shot of espresso coffee made with the normal " +
            "amount of ground coffee but extracted with about half the amount of water in the same amount of time by using " +
            "a finer grind. This produces a concentrated shot of coffee per volume. Just pulling a normal shot short will " +
            "produce a weaker shot and is not a Ristretto as some believe.";

    private final RistrettoChaChaVault vault = new RistrettoChaChaVault();

    @Test
    void smokeTest() {
        KeyPair alice = vault.generateKeyPair();
        byte[] aliceId = "Alice".getBytes(StandardCharsets.UTF_8);
        KeyPair bob = vault.generateKeyPair();
        byte[] bobId = "Robert".getBytes(StandardCharsets.UTF_8);
        byte[] context = getClass().getName().getBytes(StandardCharsets.UTF_8);
        byte[] data = TEST_MSG.getBytes(StandardCharsets.UTF_8);
        byte[] sealedData = vault.wrap(alice.getPrivate(), aliceId, bob.getPublic(), bobId, context, data);
        byte[] actual = vault.unwrap(alice.getPublic(), aliceId, bob.getPrivate(), bobId, context, sealedData);
        assertArrayEquals(data, actual);
    }

    @Test
    void compatTest() {
        byte[] aliceKey = ByteOps.fromHex("fa16bd03b12d3ff81713e92fc37eb4bf3275d05aede4bce5396c13c2d2959105");
        KeyPair alice = vault.parsePrivateKey(aliceKey);
        byte[] aliceId = "Alice".getBytes(StandardCharsets.UTF_8);
        byte[] bobKey = ByteOps.fromHex("f984be5f4ae1e412535e2711320c1b9472ebecaaab7cb969db304668456ceb0d");
        KeyPair bob = vault.parsePrivateKey(bobKey);
        byte[] bobId = "Bob".getBytes(StandardCharsets.UTF_8);
        byte[] context = "whole bean".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = ByteOps.fromHex("23f3b76c04b6411d9ef92617eee61a2b9e4f64109c69af2a");
        byte[] mac = ByteOps.fromHex("b77c98aa38655823237d0b716c3c3ebc");
        byte[] sig = ByteOps.fromHex(
                "dca45e571c20dcacd1bdd373474ee593e6c729ac34a6edddbd67ba7c40e33648c0dbc1efd23e5f55041c158d5ca6dc3ed0a3cf871c2e280a6eb8e80dec7a7700");
        byte[] ct = ByteOps.fromHex(
                "9323bc7bd99e4f87b8d4dc4bdb259e50bcb2fae8980e384554b7a0e44cde60558c4d07b385b8d7432b2402276260c1d82838a5999fe46a25ac68f05a5bd32b45622d210e19ef9e0c87b927986aac786e63d80dba642189078df305b818ee7b1b9d3543a0a0bf24303aaf72dccad8282bee826848526447f6f33197dcda4718c9df2db2586198f397c36b687cb9083d05c43cb5c764b33c034af1820290b6af156afc8c882e95d1d16f4241184af8e8ece6e184304647f25ca37c4aef5251152c5c9de20205c217e06d58dae64b845ecf12f885f0a46e9e992d6e8884f105fa71e902564625c93382bd903f3579810ccddfc5b1b2bbc235c4bf5825ec5da487d1a717847087d15ace83fe96ebcbb7178131bd77a66d54398eb5968b8d8044ef2cee5357b4f41597e1e4032033ee9e9fa7185b3c9123c48c54138829526d996a794b7d2e47b58db93d2ea6e8eb90fdea991f7b592fca8ba588f637c41605fb85f26e6f69d15c15b595");
        byte[] sealed = ByteOps.concat(nonce, ct, mac, sig);
        byte[] unsealed = vault.unwrap(alice.getPublic(), aliceId, bob.getPrivate(), bobId, context, sealed);
        assertEquals(TEST_MSG, new String(unsealed, StandardCharsets.UTF_8));
    }
}
