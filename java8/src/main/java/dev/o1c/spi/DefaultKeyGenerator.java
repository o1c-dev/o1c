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
 */

package dev.o1c.spi;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

public class DefaultKeyGenerator implements KeyGenerator {
    private final javax.crypto.KeyGenerator keyGenerator;

    protected DefaultKeyGenerator(String provider) {
        try {
            keyGenerator = javax.crypto.KeyGenerator.getInstance("ChaCha20", provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    public SecretKey generateKey() {
        return keyGenerator.generateKey();
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.ChaCha20Poly1305;
    }

    @Override
    public Provider getProvider() {
        return keyGenerator.getProvider();
    }
}
