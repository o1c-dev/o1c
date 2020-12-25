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

package dev.o1c;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class SecretKeySealTest {

    private Random random;
    private SecureData.Seal seal;

    @BeforeEach
    void setUp() {
        var key = SecureData.generateKey();
        seal = SecureData.usingKey(key);
        random = new Random(ByteBuffer.wrap(key.getEncoded()).getLong());
    }

    @Test
    void sealNoContext() {
        var plaintext = new byte[4096];
        random.nextBytes(plaintext);
        assertArrayEquals(plaintext, seal.unseal(seal.seal(plaintext)));
    }

    @Test
    void sealWithContext() {
        var plaintext = new byte[420];
        random.nextBytes(plaintext);
        var context = new byte[42];
        random.nextBytes(context);
        assertArrayEquals(plaintext, seal.unseal(seal.seal(plaintext, context), context));
    }

    @Test
    void tokenSealNoContext() {
        var plaintext = new byte[2043];
        random.nextBytes(plaintext);
        var secureData = seal.tokenSeal(plaintext);
        assertArrayEquals(plaintext, seal.tokenUnseal(secureData.getEncryptedData(), secureData.getToken()));
    }

    @Test
    void tokenSealWithContext() {
        var plaintext = new byte[1023];
        random.nextBytes(plaintext);
        var context = new byte[63];
        random.nextBytes(context);
        var secureData = seal.tokenSeal(plaintext, context);
        assertArrayEquals(plaintext, seal.tokenUnseal(secureData.getEncryptedData(), secureData.getToken(), context));
    }
}
