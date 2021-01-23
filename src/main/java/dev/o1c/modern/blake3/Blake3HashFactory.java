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

package dev.o1c.modern.blake3;

import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.HashFactory;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

/**
 * Produces {@link CryptoHash} instances using the <a href="https://github.com/BLAKE3-team/BLAKE3">BLAKE3 hash function</a>.
 */
public class Blake3HashFactory implements HashFactory {
    /**
     * Creates a fresh BLAKE3 hasher in hash mode.
     *
     * @return new hasher
     */
    @Override
    public @NotNull CryptoHash init() {
        return new Blake3CryptoHash(Constants.IV, 0);
    }

    /**
     * Creates a fresh BLAKE3 hasher in hash mode using the specified default output hash length.
     *
     * @param hashLength default hash length to use in {@link CryptoHash#finish()}
     * @return new hasher
     */
    @Override
    public @NotNull CryptoHash init(int hashLength) {
        return new Blake3CryptoHash(Constants.IV, 0, hashLength);
    }

    /**
     * Creates a fresh BLAKE3 hasher in keyed mode using the provided secret key.
     *
     * @param key 32-byte secret key
     * @return new hasher using the provided key
     */
    @Override
    public @NotNull CryptoHash init(byte @NotNull [] key) {
        return new Blake3CryptoHash(ByteOps.unpackIntsLE(key, 0, 8), Constants.KEYED_HASH);
    }

    /**
     * Creates a fresh BLAKE3 hasher in key derivation mode using the provided context data.
     *
     * @param context initial data to derive keys from such as a master key or some unique identifier
     * @return new hasher for performing key derivation
     */
    @Override
    public @NotNull CryptoHash initKDF(byte @NotNull [] context) {
        Blake3CryptoHash ctxHasher = new Blake3CryptoHash(Constants.IV, Constants.DERIVE_KEY_CONTEXT);
        ctxHasher.inputData(context, 0, context.length);
        byte[] key = new byte[Constants.KEY_LEN];
        ctxHasher.outputHash(key, 0, Constants.KEY_LEN);
        return new Blake3CryptoHash(ByteOps.unpackIntsLE(key, 0, 8), Constants.DERIVE_KEY_MATERIAL);
    }
}
