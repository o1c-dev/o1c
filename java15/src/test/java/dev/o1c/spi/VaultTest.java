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

package dev.o1c.spi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class VaultTest {

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    static void afterAll() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    void smokeTest() {
        var vault = new Vault();
        var alice = vault.generateKeyPair();
        var aliceId = "Alice".getBytes(StandardCharsets.UTF_8);
        var bob = vault.generateKeyPair();
        var bobId = "Robert".getBytes(StandardCharsets.UTF_8);
        var context = getClass().getName().getBytes(StandardCharsets.UTF_8);
        var msg = "Ristretto is traditionally a short shot of espresso coffee made with the normal amount of ground coffee " +
                "but extracted with about half the amount of water in the same amount of time by using a finer grind. " +
                "This produces a concentrated shot of coffee per volume. Just pulling a normal shot short will produce a " +
                "weaker shot and is not a Ristretto as some believe.";
        var data = msg.getBytes(StandardCharsets.UTF_8);
        var sealedData = vault.seal(alice.getPrivate(), aliceId, bob.getPublic(), bobId, context, data);
        var actual = vault.unseal(alice.getPublic(), aliceId, bob.getPrivate(), bobId, context, sealedData);
        assertArrayEquals(data, actual);
    }

    @Test
    @Disabled("needs test vectors")
    void compatTest() {
        var vault = new Vault();
        var aliceKey = ByteOps.fromHex("TODO");
        var alice = vault.parsePrivateKey(aliceKey);
        var aliceId = "TODO".getBytes(StandardCharsets.UTF_8);
        var bobKey = ByteOps.fromHex("TODO");
        var bob = vault.parsePrivateKey(bobKey);
        var bobId = "TODO".getBytes(StandardCharsets.UTF_8);
        var context = "TODO".getBytes(StandardCharsets.UTF_8);
        var msg = "Ristretto is traditionally a short shot of espresso coffee made with the normal amount of ground coffee " +
                "but extracted with about half the amount of water in the same amount of time by using a finer grind. " +
                "This produces a concentrated shot of coffee per volume. Just pulling a normal shot short will produce a " +
                "weaker shot and is not a Ristretto as some believe.";
        var sealed = ByteOps.fromHex("TODO");
        var unsealed = vault.unseal(alice.getPublic(), aliceId, bob.getPrivate(), bobId, context, sealed);
        assertEquals(msg, new String(unsealed, StandardCharsets.UTF_8));
    }
}
