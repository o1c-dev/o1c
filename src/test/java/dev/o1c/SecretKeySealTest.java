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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@EnabledForJreRange(min = JRE.JAVA_11)
class SecretKeySealTest {

    private Random random;
    private SecureData.Seal seal;

    @BeforeEach
    void setUp() {
        SecretKey key = SecureData.generateKey();
        seal = SecureData.usingKey(key);
        random = new Random(ByteBuffer.wrap(key.getEncoded()).getLong());
    }

    @Test
    void sealNoContext() {
        byte[] plaintext = new byte[4096];
        random.nextBytes(plaintext);
        assertArrayEquals(plaintext, seal.unseal(seal.seal(plaintext)));
    }

    @Test
    void sealWithContext() {
        byte[] plaintext = new byte[420];
        random.nextBytes(plaintext);
        byte[] context = new byte[42];
        random.nextBytes(context);
        assertArrayEquals(plaintext, seal.unseal(seal.seal(plaintext, context), context));
    }

    @Test
    void tokenSealNoContext() {
        byte[] plaintext = new byte[2043];
        random.nextBytes(plaintext);
        SecureData secureData = seal.tokenSeal(plaintext);
        assertArrayEquals(plaintext, seal.tokenUnseal(secureData.getEncryptedData(), secureData.getToken()));
    }

    @Test
    void tokenSealWithContext() {
        byte[] plaintext = new byte[1023];
        random.nextBytes(plaintext);
        byte[] context = new byte[63];
        random.nextBytes(context);
        SecureData secureData = seal.tokenSeal(plaintext, context);
        assertArrayEquals(plaintext, seal.tokenUnseal(secureData.getEncryptedData(), secureData.getToken(), context));
    }
}
