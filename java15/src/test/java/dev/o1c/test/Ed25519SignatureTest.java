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

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.SignatureFactory;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.security.Security;

class Ed25519SignatureTest extends SignatureTest {
    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new EdDSASecurityProvider());
    }

    @AfterAll
    static void afterAll() {
        Security.removeProvider(EdDSASecurityProvider.PROVIDER_NAME);
    }

    @Override
    SignatureFactory getEd25519() {
        return Algorithm.Ed25519.getFactory(SignatureFactory.class, EdDSASecurityProvider.PROVIDER_NAME);
    }

    @Override
    SignatureFactory getEd448() {
        throw new UnsupportedOperationException();
    }

    @Override
    boolean isEd448Disabled() {
        return true;
    }
}
