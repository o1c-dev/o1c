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

package dev.o1c.spi;

import org.jetbrains.annotations.NotNull;

/**
 * Provides confidentiality and integrity to data using authenticated encryption. A cipher must first be
 * {@linkplain #init(byte[], byte[], byte[]) initialized with a key, nonce, and context} to perform an
 * encryption or decryption operation. For each secret key, a nonce must only be used once to encrypt data.
 * For example, if a nonce uses an incrementing counter, then care must be taken to ensure nonce checkpoints are
 * journaled to prevent nonce reuse in case of failure scenarios. Use of a randomly generated nonce is useful when
 * an incrementing nonce counter is infeasible and should use extended-nonce ciphers. Contextual data are additional
 * authenticated data used during encryption to provide a sort of type information or context to distinguish different
 * data streams to help prevent data bugs. Another use case for contextual data is to maintain a cipher session by
 * authenticating previous session state into future encrypted messages.
 */
public interface Cipher {

    /**
     * Returns the length of secret keys in bytes used by this cipher.
     */
    int keyLength();

    /**
     * Checks the provided key length and throws an {@link InvalidKeyException} if the length is incorrect.
     */
    default void checkKeyLength(int keyLength) {
        if (keyLength != keyLength()) {
            throw new InvalidKeyException("Key must be " + keyLength() + " bytes but got " + keyLength);
        }
    }

    /**
     * Returns the expected length of a nonce in bytes.
     */
    int nonceLength();

    /**
     * Checks the provided nonce length and throws an {@link IllegalArgumentException} if the length is incorrect.
     */
    default void checkNonceLength(int nonceLength) {
        if (nonceLength != nonceLength()) {
            throw new IllegalArgumentException("Nonce must be " + nonceLength() + " bytes but got " + nonceLength);
        }
    }

    /**
     * Initializes this cipher with the provided secret key, nonce, and context. Keys are usually derived from
     * {@link Hash} output.
     *
     * @param key     secret key
     * @param nonce   nonce
     * @param context contextual data to authenticate with this cipher that is not encrypted/decrypted (can be 0-length)
     */
    void init(byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context);

    /**
     * Returns the length of authentication tags in bytes.
     */
    int tagLength();

    /**
     * Encrypts the provided plaintext slice into the provide ciphertext output array offset and writes the
     * authentication tag of the ciphertext into the tag offset.
     *
     * @param plaintext  input buffer to encrypt
     * @param ptOffset   where to begin reading the plaintext
     * @param ptLength   how many bytes to encrypt
     * @param ciphertext output array to write encrypted bytes to
     * @param ctOffset   where to begin writing the ciphertext
     * @param tag        output array to write authentication tag to
     * @param tagOffset  where to begin writing the authentication tag
     */
    void encrypt(
            byte @NotNull [] plaintext, int ptOffset, int ptLength,
            byte @NotNull [] ciphertext, int ctOffset,
            byte @NotNull [] tag, int tagOffset);

    /**
     * Encrypts the provided plaintext and returns the ciphertext and authentication tag appended.
     *
     * @param plaintext input data to encrypt
     * @return ciphertext plus authentication tag
     */
    default byte @NotNull [] encrypt(byte @NotNull [] plaintext) {
        byte[] ciphertext = new byte[plaintext.length + tagLength()];
        encrypt(plaintext, 0, plaintext.length, ciphertext, 0, ciphertext, plaintext.length);
        return ciphertext;
    }

    /**
     * Encrypts the provided plaintext using the provided key, nonce, and context.
     *
     * @param key       secret key
     * @param nonce     nonce
     * @param context   contextual data to authenticate but not encrypt (can be 0-length)
     * @param plaintext input data to encrypt
     * @return ciphertext plus authentication tag
     */
    default byte @NotNull [] encrypt(
            byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] plaintext) {
        init(key, nonce, context);
        return encrypt(plaintext);
    }

    /**
     * Decrypts the provided ciphertext slice and tag offset into the provided plaintext offset.
     *
     * @param ciphertext input buffer to decrypt
     * @param ctOffset   where to begin reading the ciphertext
     * @param ctLength   how many bytes to decrypt
     * @param tag        authentication tag buffer
     * @param tagOffset  offset into the tag buffer where the tag begins
     * @param plaintext  output buffer to write plaintext
     * @param ptOffset   where to begin writing plaintext
     * @throws InvalidAuthenticationTagException if authentication tag is invalid
     */
    void decrypt(
            byte @NotNull [] ciphertext, int ctOffset, int ctLength,
            byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset);

    /**
     * Decrypts the provided ciphertext and authentication tag, returning the plaintext.
     *
     * @param ciphertext ciphertext and tag to decrypt
     * @return the decrypted plaintext data
     * @throws InvalidAuthenticationTagException if authentication tag is invalid
     */
    default byte @NotNull [] decrypt(byte @NotNull [] ciphertext) {
        if (ciphertext.length < tagLength()) {
            throw new InvalidAuthenticationTagException("Invalid ciphertext");
        }
        byte[] plaintext = new byte[ciphertext.length - tagLength()];
        decrypt(ciphertext, 0, plaintext.length, ciphertext, plaintext.length, plaintext, 0);
        return plaintext;
    }

    /**
     * Decrypts the provided ciphertext and authentication tag using the provided key, nonce, and context.
     *
     * @param key        secret key
     * @param nonce      nonce
     * @param context    contextual data used to authenticate the ciphertext
     * @param ciphertext ciphertext and authentication tag to decrypt
     * @return the decrypted plaintext data
     * @throws InvalidAuthenticationTagException if authentication tag is invalid
     */
    default byte @NotNull [] decrypt(
            byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] ciphertext) {
        init(key, nonce, context);
        return decrypt(ciphertext);
    }

}
