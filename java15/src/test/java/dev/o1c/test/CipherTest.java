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

import dev.o1c.spi.Algorithm;
import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

abstract class CipherTest {

    abstract Cipher getCipher();

    // https://tools.ietf.org/html/rfc7539#section-2.8.2

    @Test
    void rfc7539() throws GeneralSecurityException {
        var plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, " +
                "sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
        var aad = ByteOps.fromHex("50515253c0c1c2c3c4c5c6c7");
        var key = ByteOps.fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        var keySpec = new SecretKeySpec(key, Algorithm.ChaCha20Poly1305.getAlgorithm());
        var nonce = ByteOps.fromHex("070000004041424344454647");
        var paramSpec = new IvParameterSpec(nonce);
        var expectedCiphertext = ByteOps.fromHex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116");
        var expectedTag = ByteOps.fromHex("1ae10b594f09e26a7e902ecbd0600691");

        var cipher = getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
        cipher.updateAAD(aad);
        var ciphertext = cipher.doFinal(plaintext);
        assertArrayEquals(expectedCiphertext, Arrays.copyOfRange(ciphertext, 0, expectedCiphertext.length));
        assertArrayEquals(expectedTag, Arrays.copyOfRange(ciphertext, expectedCiphertext.length, ciphertext.length));

        cipher = getCipher();
        cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
        cipher.updateAAD(aad);
        var actual = new byte[plaintext.length];
        cipher.doFinal(expectedTag, 0, expectedTag.length, actual,
                cipher.update(expectedCiphertext, 0, expectedCiphertext.length, actual));
        assertArrayEquals(plaintext, actual);
    }

}
