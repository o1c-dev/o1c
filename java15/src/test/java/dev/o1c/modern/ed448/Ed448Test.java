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
 *
 * SPDX-License-Identifier: ISC
 */

package dev.o1c.modern.ed448;

import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class Ed448Test {
    private final Ed448VerificationKeyFactory factory = new Ed448VerificationKeyFactory();

    private static KeyPair parseKeyPair(byte[] privateKey, byte[] publicKey) {
        var keyFactory = Ed448.getKeyFactory();
        var privateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED448, privateKey);
        var key = ByteOps.reverseCopyOf(publicKey);
        var xOdd = (key[0] & 0x80) != 0;
        key[0] &= 0x7f;
        var y = new BigInteger(key);
        var publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED448, new EdECPoint(xOdd, y));
        return assertDoesNotThrow(
                () -> new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec)));
    }

    // https://tools.ietf.org/html/rfc8032#section-7.4

    @Test
    void ed448_emptyMessage() {
        var privateKey = ByteOps.fromHex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3" +
                "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
        var publicKey = ByteOps.fromHex("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778" +
                "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
        var expectedSignature = ByteOps.fromHex("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f" +
                "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a" +
                "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db" +
                "b61149f05a7363268c71d95808ff2e652600");
        var message = new byte[0];

        var signingKey = new Ed448SignatureKey(parseKeyPair(privateKey, publicKey));
        assertArrayEquals(expectedSignature, signingKey.sign(message));
        assertDoesNotThrow(() -> signingKey.verificationKey().verify(message, expectedSignature));
        assertDoesNotThrow(() -> factory.parseKey(publicKey).verify(message, expectedSignature));
    }

    @Test
    void ed448_oneByteMessage() {
        var privateKey = ByteOps.fromHex("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a" +
                "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
        var publicKey = ByteOps.fromHex("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086" +
                "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
        var expectedSignature = ByteOps.fromHex("26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435" +
                "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb" +
                "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f" +
                "f3348ab21aa4adafd1d234441cf807c03a00");
        var message = new byte[] { 0x03 };

        var signingKey = new Ed448SignatureKey(parseKeyPair(privateKey, publicKey));
        assertArrayEquals(expectedSignature, signingKey.sign(message));
        assertDoesNotThrow(() -> signingKey.verificationKey().verify(message, expectedSignature));
        assertDoesNotThrow(() -> factory.parseKey(publicKey).verify(message, expectedSignature));
    }

    @Test
    void ed448_oneThousandTwentyThreeByteMessage() {
        var privateKey = ByteOps.fromHex("""
                872d093780f5d3730df7c212664b37b8
                a0f24f56810daa8382cd4fa3f77634ec
                44dc54f1c2ed9bea86fafb7632d8be19
                9ea165f5ad55dd9ce8""");
        var publicKey = ByteOps.fromHex("""
                a81b2e8a70a5ac94ffdbcc9badfc3feb
                0801f258578bb114ad44ece1ec0e799d
                a08effb81c5d685c0c56f64eecaef8cd
                f11cc38737838cf400""");
        var expectedSignature = ByteOps.fromHex("""
                e301345a41a39a4d72fff8df69c98075
                a0cc082b802fc9b2b6bc503f926b65bd
                df7f4c8f1cb49f6396afc8a70abe6d8a
                ef0db478d4c6b2970076c6a0484fe76d
                76b3a97625d79f1ce240e7c576750d29
                5528286f719b413de9ada3e8eb78ed57
                3603ce30d8bb761785dc30dbc320869e
                1a00""");
        var message = ByteOps.fromHex("""
                6ddf802e1aae4986935f7f981ba3f035
                1d6273c0a0c22c9c0e8339168e675412
                a3debfaf435ed651558007db4384b650
                fcc07e3b586a27a4f7a00ac8a6fec2cd
                86ae4bf1570c41e6a40c931db27b2faa
                15a8cedd52cff7362c4e6e23daec0fbc
                3a79b6806e316efcc7b68119bf46bc76
                a26067a53f296dafdbdc11c77f7777e9
                72660cf4b6a9b369a6665f02e0cc9b6e
                dfad136b4fabe723d2813db3136cfde9
                b6d044322fee2947952e031b73ab5c60
                3349b307bdc27bc6cb8b8bbd7bd32321
                9b8033a581b59eadebb09b3c4f3d2277
                d4f0343624acc817804728b25ab79717
                2b4c5c21a22f9c7839d64300232eb66e
                53f31c723fa37fe387c7d3e50bdf9813
                a30e5bb12cf4cd930c40cfb4e1fc6225
                92a49588794494d56d24ea4b40c89fc0
                596cc9ebb961c8cb10adde976a5d602b
                1c3f85b9b9a001ed3c6a4d3b1437f520
                96cd1956d042a597d561a596ecd3d173
                5a8d570ea0ec27225a2c4aaff26306d1
                526c1af3ca6d9cf5a2c98f47e1c46db9
                a33234cfd4d81f2c98538a09ebe76998
                d0d8fd25997c7d255c6d66ece6fa56f1
                1144950f027795e653008f4bd7ca2dee
                85d8e90f3dc315130ce2a00375a318c7
                c3d97be2c8ce5b6db41a6254ff264fa6
                155baee3b0773c0f497c573f19bb4f42
                40281f0b1f4f7be857a4e59d416c06b4
                c50fa09e1810ddc6b1467baeac5a3668
                d11b6ecaa901440016f389f80acc4db9
                77025e7f5924388c7e340a732e554440
                e76570f8dd71b7d640b3450d1fd5f041
                0a18f9a3494f707c717b79b4bf75c984
                00b096b21653b5d217cf3565c9597456
                f70703497a078763829bc01bb1cbc8fa
                04eadc9a6e3f6699587a9e75c94e5bab
                0036e0b2e711392cff0047d0d6b05bd2
                a588bc109718954259f1d86678a579a3
                120f19cfb2963f177aeb70f2d4844826
                262e51b80271272068ef5b3856fa8535
                aa2a88b2d41f2a0e2fda7624c2850272
                ac4a2f561f8f2f7a318bfd5caf969614
                9e4ac824ad3460538fdc25421beec2cc
                6818162d06bbed0c40a387192349db67
                a118bada6cd5ab0140ee273204f628aa
                d1c135f770279a651e24d8c14d75a605
                9d76b96a6fd857def5e0b354b27ab937
                a5815d16b5fae407ff18222c6d1ed263
                be68c95f32d908bd895cd76207ae7264
                87567f9a67dad79abec316f683b17f2d
                02bf07e0ac8b5bc6162cf94697b3c27c
                d1fea49b27f23ba2901871962506520c
                392da8b6ad0d99f7013fbc06c2c17a56
                9500c8a7696481c1cd33e9b14e40b82e
                79a5f5db82571ba97bae3ad3e0479515
                bb0e2b0f3bfcd1fd33034efc6245eddd
                7ee2086ddae2600d8ca73e214e8c2b0b
                db2b047c6a464a562ed77b73d2d841c4
                b34973551257713b753632efba348169
                abc90a68f42611a40126d7cb21b58695
                568186f7e569d2ff0f9e745d0487dd2e
                b997cafc5abf9dd102e62ff66cba87""");

        var signingKey = new Ed448SignatureKey(parseKeyPair(privateKey, publicKey));
        assertArrayEquals(expectedSignature, signingKey.sign(message));
        assertDoesNotThrow(() -> signingKey.verificationKey().verify(message, expectedSignature));
        assertDoesNotThrow(() -> factory.parseKey(publicKey).verify(message, expectedSignature));
    }
}
