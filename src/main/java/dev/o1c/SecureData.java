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

package dev.o1c;

import dev.o1c.spi.Vault;

import javax.crypto.SecretKey;
import java.util.Objects;

public final class SecureData {
    private final byte[] encryptedData;
    private final byte[] token;

    public SecureData(byte[] encryptedData, byte[] token) {
        this.encryptedData = Objects.requireNonNull(encryptedData);
        this.token = Objects.requireNonNull(token);
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getToken() {
        return token;
    }

    public static SecretKey generateKey() {
        return Vault.getInstance().generateSecretKey();
    }

    public static Seal usingKey(SecretKey key) {
        return new SecretKeySeal(Objects.requireNonNull(key));
    }

    public interface Seal {
        byte[] seal(byte[] data, byte[] context);

        default byte[] seal(byte[] data) {
            return seal(data, null);
        }

        byte[] unseal(byte[] sealedData, byte[] context);

        default byte[] unseal(byte[] sealedData) {
            return unseal(sealedData, null);
        }

        SecureData tokenSeal(byte[] data, byte[] context);

        default SecureData tokenSeal(byte[] data) {
            return tokenSeal(data, null);
        }

        byte[] tokenUnseal(byte[] encryptedData, byte[] token, byte[] context);

        default byte[] tokenUnseal(byte[] encryptedData, byte[] token) {
            return tokenUnseal(encryptedData, token, null);
        }
    }
}
