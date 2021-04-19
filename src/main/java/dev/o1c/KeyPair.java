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

import org.jetbrains.annotations.NotNull;

/**
 * Contains the private and public parts of a keypair used for public key cryptography. These operations are
 * simplified into higher level concepts that handle all the low level primitive details.
 *
 * <h2>Signed Message</h2>
 * Messages can be {@linkplain #sign(byte[]) signed} which wraps a message with a signature that can be
 * {@linkplain #openSignedMessage(byte[]) verified} by the public part of this keypair.
 *
 * <h2>Box</h2>
 * Messages can be put in a confidential {@linkplain #box(PublicKey, byte[], byte[]) box} which encrypts the message
 * such that only the recipient can {@linkplain #openBox(PublicKey, byte[], byte[]) open} it. This box is wrapped with
 * a nonce and an authentication tag which allow the recipient to verify the authenticity of the box before opening it.
 *
 * <h2>Sealed Box</h2>
 * Messages can be put in a confidential {@linkplain #sealedBox(PublicKey, byte[], byte[]) sealed box} with
 * non-repudiation by the sender. A sealed box is essentially a signed and encrypted message.
 */
public interface KeyPair extends PublicKey {

    /**
     * Secures a binary message in the provided context into a box that can only be
     * {@linkplain #openBox(PublicKey, byte[], byte[]) opened} by the recipient.
     *
     * @param recipient who can open the box
     * @param message   arbitrary binary message to encrypt into box
     * @param context   contextual metadata identifying where or for what purpose the box is being used
     * @return box containing encrypted message that can be decrypted by the recipient
     * @throws dev.o1c.spi.InvalidKeyException if the recipient key is incompatible with this keypair
     */
    byte @NotNull [] box(@NotNull PublicKey recipient, byte @NotNull [] message, byte @NotNull [] context);

    /**
     * Opens a box encrypted by the provided sender in the provided context.
     *
     * @param sender  who sent the box
     * @param box     box data to open
     * @param context contextual metadata used when the box was created
     * @return original message in the box if valid
     * @throws dev.o1c.spi.InvalidKeyException               if the sender key is incompatible with this keypair
     * @throws dev.o1c.spi.InvalidAuthenticationTagException if the box is inauthentic (an invalid tag)
     */
    byte @NotNull [] openBox(@NotNull PublicKey sender, byte @NotNull [] box, byte @NotNull [] context);

    /**
     * Signs a message and returns the message wrapped with a signature which can be
     * {@linkplain #openSignedMessage(byte[]) verified} by the public part of this key by others.
     *
     * @param message arbitrary message data to wrap with a signature from this keypair
     * @return signed message
     */
    byte @NotNull [] sign(byte @NotNull [] message);

    /**
     * Secures a binary message in the provided context into a sealed box that can only be
     * {@linkplain #openSealedBox(PublicKey, byte[], byte[]) opened} by the recipient and can be
     * {@linkplain #validateSealedBox(PublicKey, byte[], byte[]) validated} by others. This combines encryption
     * and signing into a single signcryption operation.
     *
     * @param recipient who can open the sealed box
     * @param message   arbitrary binary message to signcrypt into sealed box
     * @param context   contextual metadata identifying where or for what purpose the sealed box is being used
     * @return sealed box containing signcrypted message that can be verified by others and can only be decrypted
     * by the recipient
     * @throws dev.o1c.spi.InvalidKeyException if the recipient key is incompatible with this keypair
     */
    byte @NotNull [] sealedBox(@NotNull PublicKey recipient, byte @NotNull [] message, byte @NotNull [] context);

    /**
     * Opens a sealed box in the provided context by the given sender and returns the original message contents if
     * the box seal is {@linkplain #validateSealedBox(PublicKey, byte[], byte[]) authentic}.
     *
     * @param sender    who created the sealed box
     * @param sealedBox sealed box data to open
     * @param context   original context the sealed box was created in
     * @return the original message contents if the sealed box is authentic
     * @throws dev.o1c.spi.InvalidSignatureException         if the seal is broken (an invalid signature)
     * @throws dev.o1c.spi.InvalidAuthenticationTagException if the box is inauthentic (an invalid tag)
     */
    byte @NotNull [] openSealedBox(@NotNull PublicKey sender, byte @NotNull [] sealedBox, byte @NotNull [] context);

}
