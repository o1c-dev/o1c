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

package dev.o1c.bc;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.KeyCodec;

import java.security.Key;
import java.security.KeyFactory;

abstract class CurveCodec<K extends Key> implements KeyCodec<K> {
    private final Algorithm algorithm;
    final KeyFactory keyFactory;

    CurveCodec(Algorithm algorithm, KeyFactory keyFactory) {
        this.algorithm = algorithm;
        this.keyFactory = keyFactory;
    }

    @Override
    public int getKeySize() {
        return algorithm.getKeySize();
    }
}
