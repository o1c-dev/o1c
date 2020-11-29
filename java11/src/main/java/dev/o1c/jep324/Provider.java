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

package dev.o1c.jep324;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.DefaultKeyGenerator;
import dev.o1c.spi.KeyExchangeFactory;

public class Provider {
    public static class X25519Codec extends XDHKeyPairCodec {
        public X25519Codec() {
            super(Algorithm.X25519);
        }
    }

    public static class X25519 extends KeyExchangeFactory {
        public X25519() {
            super(new X25519Codec());
        }
    }

    public static class X448Codec extends XDHKeyPairCodec {
        public X448Codec() {
            super(Algorithm.X448);
        }
    }

    public static class X448 extends KeyExchangeFactory {
        public X448() {
            super(new X448Codec());
        }
    }

    public static class ChaCha20 extends DefaultKeyGenerator {
        public ChaCha20() {
            super("SunJCE");
        }
    }

    private Provider() {
        throw new UnsupportedOperationException();
    }
}
