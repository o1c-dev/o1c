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

package dev.o1c.impl.chacha20;

import dev.o1c.spi.CipherKey;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.BufferOverflowException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

// https://tools.ietf.org/html/rfc8439
// https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03
public class XChaCha20Poly1305CipherKey implements CipherKey {
    private static final int[] ENGINE_STATE_HEADER =
            ByteOps.unpackIntsLE("expand 32-byte k".getBytes(StandardCharsets.US_ASCII), 0, 4);

    private final int[] initialState;

    public XChaCha20Poly1305CipherKey(byte @NotNull [] key) {
        if (key.length != 32) {
            throw new InvalidKeyException("Keys must be 32 bytes");
        }
        initialState = Arrays.copyOf(ENGINE_STATE_HEADER, 16);
        ByteOps.unpackIntsLE(key, 0, 8, initialState, 4);
    }

    @Override
    public int nonceLength() {
        return 24;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] out,
            int outOffset, byte @NotNull [] tag, int tagOffset) {
        checkNonceLength(nonce.length);
        Cipher cipher = init(false, nonce);
        cipher.updateAAD(context);
        try {
            cipher.update(in, offset, length, out, outOffset);
            cipher.doFinal(tag, tagOffset);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        } catch (ShortBufferException e) {
            throw new BufferOverflowException();
        }
    }

    @Override
    public void decrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] tag,
            int tagOffset, byte @NotNull [] out, int outOffset) {
        checkNonceLength(nonce.length);
        Cipher cipher = init(true, nonce);
        cipher.updateAAD(context);
        try {
            cipher.doFinal(tag, tagOffset, tagLength(), out,
                    outOffset + cipher.update(in, offset, length, out, outOffset));
        } catch (ShortBufferException e) {
            throw new BufferOverflowException();
        } catch (AEADBadTagException e) {
            throw new InvalidAuthenticationTagException(e.getMessage());
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        }
    }

    private Cipher init(boolean decrypt, byte[] nonce) {
        Cipher cipher = getChaCha20Poly1305();
        int[] state = initialState.clone();
        ByteOps.unpackIntsLE(nonce, 0, 4, state, 12);
        ChaCha20.permute(state);
        byte[] subkey = new byte[32];
        ByteOps.packIntsLE(state, 0, 4, subkey, 0);
        ByteOps.packIntsLE(state, 12, 4, subkey, 16);
        SecretKey secretKey = new SecretKeySpec(subkey, "XChaCha20");
        byte[] subNonce = new byte[12];
        System.arraycopy(nonce, 16, subNonce, 4, 8);
        IvParameterSpec iv = new IvParameterSpec(subNonce);
        try {
            cipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, secretKey, iv);
        } catch (java.security.InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
        return cipher;
    }

    private static Cipher getChaCha20Poly1305() {
        try {
            return Cipher.getInstance("ChaCha20-Poly1305");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new InvalidProviderException(e);
        }
    }
}
