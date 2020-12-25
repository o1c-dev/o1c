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

import dev.o1c.O1CException;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

public interface Vault {
    KeyPair generateKeyPair();

    SecretKey generateSecretKey();

    byte[] seal(SecretKey secretKey, byte[] context, byte[] data);

    byte[] unseal(SecretKey secretKey, byte[] context, byte[] sealedData);

    byte[] wrap(PrivateKey senderKey, byte[] senderId, PublicKey recipientKey, byte[] recipientId, byte[] context, byte[] data);

    byte[] unwrap(
            PublicKey senderKey, byte[] senderId, PrivateKey recipientKey, byte[] recipientId, byte[] context,
            byte[] wrappedData);

    int getTagSize();

    int getNonceSize();

    int getSigSize();

    static Vault getInstance() {
        Iterator<Vault> iterator = ServiceLoader.load(Vault.class).iterator();
        InvalidProviderException error = null;
        while (iterator.hasNext()) {
            try {
                return iterator.next();
            } catch (ServiceConfigurationError e) {
                if (error == null) {
                    error = new InvalidProviderException("Could not load any vault providers");
                }
                error.addSuppressed(e.getCause() instanceof O1CException ? e.getCause() : e);
            }
        }
        throw error == null ? new InvalidProviderException("No vault providers available") : error;
    }
}
