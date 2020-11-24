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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface Signature {
    KeyPair newSigningKey();

    byte[] calculateSignature(PrivateKey key, byte[] data);

    boolean verifySignature(PublicKey key, byte[] data, byte[] signature);

    byte[] calculateSignature(byte[] privateKey, byte[] data);

    boolean verifySignature(byte[] publicKey, byte[] data, byte[] signature);
}
