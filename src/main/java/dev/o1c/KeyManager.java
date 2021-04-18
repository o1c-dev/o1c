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

import dev.o1c.spi.InvalidProviderException;
import org.jetbrains.annotations.NotNull;

import java.util.ServiceLoader;

/**
 * Central management of cryptographic keys.
 */
public interface KeyManager {

    /**
     * Obtains an instance of the default KeyManager service.
     *
     * @return default KeyManager
     */
    static KeyManager getInstance() {
        for (KeyManager keyManager : ServiceLoader.load(KeyManager.class)) {
            return keyManager;
        }
        throw new InvalidProviderException("No KeyManager services found");
    }

    /**
     * Generates a fresh keypair. A keypair consists of a private key and its corresponding public key. These
     * are used for {@linkplain KeyPair#sign(byte[]) message signing},
     * {@linkplain KeyPair#box(PublicKey, byte[], byte[]) authenticated public key encryption (box)},
     * {@linkplain KeyPair#sealedBox(PublicKey, byte[], byte[]) authenticated public key signcryption (sealed box)},
     * and their dual methods.
     *
     * @return fresh keypair
     */
    @NotNull KeyPair generateKeyPair();

    /**
     * Generates a fresh secret key. A secret key is used for
     * {@linkplain SecretKey#box(byte[], byte[]) authenticated encryption (secret box)}.
     *
     * @return fresh secret key
     */
    @NotNull SecretKey generateSecretKey();

    /**
     * Parses secret key data.
     *
     * @param secretKey secret key data
     * @return parsed secret key
     * @throws dev.o1c.spi.InvalidKeyException if provided key is not valid
     */
    @NotNull SecretKey parseSecretKey(byte @NotNull [] secretKey);

    /**
     * Parses public key data. A public key is used for
     * {@linkplain PublicKey#openSignedMessage(byte[]) verifying signed messages} and as the sender or recipient
     * parameter in various public key cryptography methods.
     *
     * @param publicKey public key data
     * @return parsed public key
     * @throws dev.o1c.spi.InvalidKeyException if provided key is not valid
     */
    @NotNull PublicKey parsePublicKey(byte @NotNull [] publicKey);

    /**
     * Parses private key data and generates its corresponding public key.
     *
     * @param privateKey private key data
     * @return parsed private key and its corresponding public key
     * @throws dev.o1c.spi.InvalidKeyException if provided key is not valid
     */
    @NotNull KeyPair parsePrivateKey(byte @NotNull [] privateKey);

}
