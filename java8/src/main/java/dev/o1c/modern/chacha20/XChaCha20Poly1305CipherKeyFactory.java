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

package dev.o1c.modern.chacha20;

import dev.o1c.spi.CipherKey;
import dev.o1c.spi.CipherKeyFactory;
import dev.o1c.spi.InvalidAuthenticationTagException;
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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

// https://tools.ietf.org/html/rfc8439
// https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03
public class XChaCha20Poly1305CipherKeyFactory implements CipherKeyFactory {
    private final SecureRandom secureRandom;

    public XChaCha20Poly1305CipherKeyFactory() {
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    public XChaCha20Poly1305CipherKeyFactory(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public CipherKey generateKey() {
        byte[] key = new byte[keyLength()];
        secureRandom.nextBytes(key);
        return new CipherKeyImpl(key);
    }

    @Override
    public CipherKey parseKey(byte @NotNull [] key) {
        checkKeyLength(key.length);
        return new CipherKeyImpl(key.clone());
    }

    private static class CipherKeyImpl implements CipherKey {
        private static final int[] ENGINE_STATE_HEADER =
                ByteOps.unpackIntsLE("expand 32-byte k".getBytes(StandardCharsets.US_ASCII), 0, 4);

        private final int[] initialState;

        private CipherKeyImpl(byte[] key) {
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
                byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length,
                byte @NotNull [] out, int outOffset, byte @NotNull [] tag, int tagOffset) {
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
                byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length,
                byte @NotNull [] tag, int tagOffset, byte @NotNull [] out, int outOffset) {
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
            chaChaBlock(state);
            byte[] subkey = new byte[32];
            ByteOps.packIntsLE(state, 0, 4, subkey, 0);
            ByteOps.packIntsLE(state, 12, 4, subkey, 16);
            SecretKey secretKey = new SecretKeySpec(subkey, "XChaCha20");
            byte[] subNonce = new byte[12];
            System.arraycopy(nonce, 16, subNonce, 4, 8);
            IvParameterSpec iv = new IvParameterSpec(subNonce);
            try {
                cipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, secretKey, iv);
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                throw new IllegalStateException(e);
            }
            return cipher;
        }

        private static void chaChaBlock(int[] state) {
            for (int i = 0; i < 10; i++) {
                columnRound(state);
                diagonalRound(state);
            }
        }

        private static void columnRound(int[] state) {
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);
        }

        private static void diagonalRound(int[] state) {
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }

        private static void quarterRound(int[] state, int a, int b, int c, int d) {
            state[a] += state[b];
            state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);

            state[c] += state[d];
            state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);

            state[a] += state[b];
            state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);

            state[c] += state[d];
            state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
        }

        private static Cipher getChaCha20Poly1305() {
            try {
                return Cipher.getInstance("ChaCha20-Poly1305");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new InvalidProviderException(e);
            }
        }
    }
}
