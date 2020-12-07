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
