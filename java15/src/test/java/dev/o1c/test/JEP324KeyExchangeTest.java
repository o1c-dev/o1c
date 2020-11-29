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

import dev.o1c.jep324.Provider;
import dev.o1c.spi.KeyExchangeFactory;

class JEP324KeyExchangeTest extends KeyExchangeTest {
    @Override
    KeyExchangeFactory getX25519() {
        return new Provider.X25519();
    }

    @Override
    KeyExchangeFactory getX448() {
        return new Provider.X448();
    }
}
