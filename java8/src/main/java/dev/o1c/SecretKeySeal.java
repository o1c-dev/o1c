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

package dev.o1c;

import dev.o1c.spi.InvalidSealException;
import dev.o1c.spi.Vault;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Objects;

class SecretKeySeal implements SecureData.Seal {
    private final Vault vault = Vault.getInstance();
    private final SecretKey key;

    SecretKeySeal(SecretKey key) {
        this.key = key;
    }

    @Override
    public byte[] seal(byte[] data, byte[] context) {
        Objects.requireNonNull(data);
        if (context == null) {
            context = new byte[0];
        }
        return vault.seal(key, context, data);
    }

    @Override
    public byte[] unseal(byte[] sealedData, byte[] context) {
        Objects.requireNonNull(sealedData);
        if (context == null) {
            context = new byte[0];
        }
        return vault.unseal(key, context, sealedData);
    }

    @Override
    public SecureData tokenSeal(byte[] data, byte[] context) {
        Objects.requireNonNull(data);
        if (context == null) {
            context = new byte[0];
        }
        byte[] sealedData = vault.seal(key, context, data);
        byte[] encryptedData = Arrays.copyOfRange(sealedData, vault.getNonceSize(), vault.getNonceSize() + data.length);
        byte[] token = Arrays.copyOf(sealedData, vault.getNonceSize() + vault.getTagSize());
        System.arraycopy(sealedData, sealedData.length - vault.getTagSize(), token, vault.getNonceSize(), vault.getTagSize());
        return new SecureData(encryptedData, token);
    }

    @Override
    public byte[] tokenUnseal(byte[] encryptedData, byte[] token, byte[] context) {
        Objects.requireNonNull(encryptedData);
        Objects.requireNonNull(token);
        if (context == null) {
            context = new byte[0];
        }
        int tokenSize = vault.getNonceSize() + vault.getTagSize();
        if (token.length != tokenSize) {
            throw new InvalidSealException("Token size must be " + tokenSize + " bytes");
        }
        byte[] sealedData = new byte[encryptedData.length + token.length];
        System.arraycopy(token, 0, sealedData, 0, vault.getNonceSize());
        System.arraycopy(encryptedData, 0, sealedData, vault.getNonceSize(), encryptedData.length);
        System.arraycopy(token, vault.getNonceSize(), sealedData, vault.getNonceSize() + encryptedData.length,
                vault.getTagSize());
        return vault.unseal(key, context, sealedData);
    }
}