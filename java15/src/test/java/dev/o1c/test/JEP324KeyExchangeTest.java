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
import dev.o1c.spi.KeyExchangeFactory;
import dev.o1c.spi.SecurityFactory;

class JEP324KeyExchangeTest extends KeyExchangeTest {
    @Override
    KeyExchangeFactory getX25519() {
        return Algorithm.X25519.getFactory(KeyExchangeFactory.class, "SunEC");
    }

    @Override
    KeyExchangeFactory getX448() {
        return Algorithm.X448.getFactory(KeyExchangeFactory.class, "SunEC");
    }
}
