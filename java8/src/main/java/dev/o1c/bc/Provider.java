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
import dev.o1c.spi.CipherFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Provider {
    public static class ChaCha20Poly1305 extends CipherFactory {
        public ChaCha20Poly1305() {
            // using this static reference to the BC library itself allows us to fail fast if it's not available
            super(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    public static class X25519 extends BouncyCastleKeyExchangeFactory {
        public X25519() {
            super(new CurveAlgorithm(Algorithm.X25519));
        }
    }

    public static class X448 extends BouncyCastleKeyExchangeFactory {
        public X448() {
            super(new CurveAlgorithm(Algorithm.X448));
        }
    }

    public static class Ed25519 extends BouncyCastleSignatureFactory {
        public Ed25519() {
            super(new CurveAlgorithm(Algorithm.Ed25519));
        }
    }

    public static class Ed448 extends BouncyCastleSignatureFactory {
        public Ed448() {
            super(new CurveAlgorithm(Algorithm.Ed448));
        }
    }
}
