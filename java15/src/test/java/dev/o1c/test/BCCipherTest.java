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

package dev.o1c.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.Provider;

import static dev.o1c.spi.Algorithm.ChaCha20Poly1305;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class BCCipherTest extends CipherTest {
    // no need to install in this test since we aren't using string provider names here
    private final Provider provider = new BouncyCastleProvider();

    @Override
    Cipher getCipher() {
        return assertDoesNotThrow(() -> Cipher.getInstance(ChaCha20Poly1305.getAlgorithm(), provider));
    }
}
