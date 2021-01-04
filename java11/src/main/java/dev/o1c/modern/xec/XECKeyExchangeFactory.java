/*
 * ISC License
 *
 * Copyright (c) 2021, Matt Sicker
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

package dev.o1c.modern.xec;

import dev.o1c.spi.ExchangeKey;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyExchangeFactory;
import org.jetbrains.annotations.NotNull;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;

public class XECKeyExchangeFactory implements KeyExchangeFactory {
    private final NamedParameterSpec curve;
    private final int keyLength;
    private final KeyPairGenerator keyPairGenerator;
    private final KeyFactory keyFactory;

    public XECKeyExchangeFactory(@NotNull NamedParameterSpec curve) {
        this.curve = curve;
        switch (curve.getName()) {
            case "X25519":
                keyLength = 32;
                break;

            case "X448":
                keyLength = 56;
                break;

            default:
                throw new IllegalArgumentException("Curve must be X25519 or X448");
        }
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(curve.getName());
            keyFactory = KeyFactory.getInstance(curve.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    public int keyLength() {
        return keyLength;
    }

    @Override
    public @NotNull ExchangeKey generateExchangeKey() {
        var keyPair = keyPairGenerator.generateKeyPair();
        try {
            var agreement = KeyAgreement.getInstance(curve.getName());
            agreement.init(keyPair.getPrivate());
            return new XECExchangeKey(curve, keyFactory, agreement);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    public @NotNull ExchangeKey parseExchangeKey(byte @NotNull [] privateKey) {
        var keySpec = new XECPrivateKeySpec(curve, privateKey);
        try {
            var key = keyFactory.generatePrivate(keySpec);
            var agreement = KeyAgreement.getInstance(curve.getName());
            agreement.init(key);
            return new XECExchangeKey(curve, keyFactory, agreement);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        } catch (InvalidKeyException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
