/*
 * ISC License
 *
 * Copyright (c) 2020, Matt Sicker
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: ISC
 */

package dev.o1c.bc;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.DefaultKeyGenerator;
import dev.o1c.spi.KeyExchangeFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Provider {
    public static class X25519Codec extends BouncyCastleKeyPairCodec {
        public X25519Codec() {
            super(Algorithm.X25519);
        }
    }

    public static class X25519 extends KeyExchangeFactory {
        public X25519() {
            super(new X25519Codec());
        }
    }

    public static class X448Codec extends BouncyCastleKeyPairCodec {
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
            super(BouncyCastleProvider.PROVIDER_NAME);
        }
    }
}
