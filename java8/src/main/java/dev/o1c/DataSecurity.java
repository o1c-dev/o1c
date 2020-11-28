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

import dev.o1c.spi.Algorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Objects;

public class DataSecurity {
    public static TokenSeal sealWithKey(byte[] key) {
        Algorithm algorithm = Algorithm.ChaCha20Poly1305;
        if (key.length != algorithm.getKeySize()) {
            throw new IllegalArgumentException(
                    "Keys must be " + algorithm.getKeySize() + " bytes but got " + key.length + " bytes");
        }
        return sealWithKey(new SecretKeySpec(key, algorithm.getAlgorithm()));
    }

    public static TokenSeal sealWithKey(SecretKey key) {
        return new SecretKeySeal(Objects.requireNonNull(key));
    }
}
