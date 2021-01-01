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

package dev.o1c.lwc.xoodyak;

import org.jetbrains.annotations.NotNull;

/**
 * Implements the <a href="https://keccak.team/files/Xoodyak-doc1.1.pdf">cyclist mode of operation</a> for implementing
 * cryptographic primitives based on permutations such as Xoodoo. Ported from the
 * <a href="https://github.com/XKCP/XKCP/blob/master/lib/high/Xoodyak/Cyclist.inc">reference C implementation</a>.
 * <p>
 * A Cyclist instance is first {@linkplain #initialize(byte[], byte[], byte[]) initialized} which determines whether it
 * operates in hashed mode or keyed mode. If an optional key id is specified, it is combined with the key. If a counter is
 * specified, it is absorbed in a trickled way. If none of the parameters are provided, then the instance is in hashed mode.
 * In either mode, {@link #squeeze(byte[], int, int)} and {@link #absorb(byte[], int, int)} may be called, while the remaining
 * methods {@link #encrypt(byte[], int, int, byte[], int)}, {@link #decrypt(byte[], int, int, byte[], int)},
 * {@link #squeezeKey(byte[], int, int)}, and {@link #ratchet()} are only available in keyed mode.
 * </p>
 * <p>
 * As explained in the linked PDF: <q>The state of a Cyclist object will depend on the sequence of calls to it and on its
 * inputs. More precisely, the intention is that any output depends on the sequence of all input strings and of all input
 * calls so far, and that any two subsequent output strings are in different domains. It does not only depend on the
 * concatenation of input strings, but also on their boundaries without ambiguity</q>.
 * </p>
 *
 * @see <a href="https://github.com/XKCP/XKCP">Xoodoo and Keccak Code Package reference implementations</a>
 * @see <a href="https://github.com/KeccakTeam/Xoodoo/">Xoodoo C++ and Python reference implementations</a>
 */
public abstract class Cyclist {
    private static final int RATCHET_SIZE = 16;
    protected static final byte[] EMPTY = new byte[0];
    protected Mode mode;

    /**
     * Initializes this to hashed mode.
     */
    public void initialize() {
        initialize(EMPTY);
    }

    /**
     * Initializes this using the provided key in keyed mode if non-empty or hashed mode otherwise.
     *
     * @param key secret key to use for subsequent operations
     */
    public void initialize(byte @NotNull [] key) {
        initialize(key, EMPTY, EMPTY);
    }

    /**
     * Initializes this instance with an optional key, key id, and counter. If a non-empty key is provided, then this instance
     * is set to keyed mode.
     * <p>
     * In scenarios where an attacker wants to break <i>any</i> device or key from a (possibly large) set of <i>u</i> keys
     * rather than a <i>specific</i> device or key, the security of this system can degrade by up to log<sub>2</sub>(<i>u</i>).
     * To fix this, two options are available: the key size <i>&kappa;</i> can be extended by log<sub>2</sub>(<i>u</i>) bits,
     * or an identifier string that is globally unique within the set of <i>u</i> keys can be provided while maintaining the
     * original key length <i>&kappa;.</i>
     * </p>
     * <p>
     * In scenarios where protection against power analysis attacks or variants is required, the counter buffer can be encoded
     * using a fixed base <i>2 &le; b &le; 256</i> using big endian ordering of the digits. This buffer is absorbed one digit
     * at a time which allows for incremental caching of permutation states.
     * </p>
     * <p>
     * In scenarios where protection against power analysis attacks is <i>not</i> required, if the id value is a globally unique
     * nonce, then it can be specified here during initialization. Otherwise, a nonce should be specified in a subsequent
     * call to {@link #absorb(byte[], int, int)}.
     * </p>
     *
     * @param key     secret key to use when using keyed mode or an empty array for hashed mode
     * @param id      key id to include in initialization for keyed mode; can be empty
     * @param counter counter string
     */
    public abstract void initialize(byte @NotNull [] key, byte @NotNull [] id, byte @NotNull [] counter);

    /**
     * Absorbs the provided buffer at the {@linkplain #absorbRate() absorb rate}.
     *
     * @param X      input buffer to absorb from
     * @param offset where in the buffer to start absorbing from
     * @param length how many bytes to absorb
     */
    public void absorb(byte @NotNull [] X, int offset, int length) {
        absorbAny(DomainConstant.Absorb, absorbRate(), X, offset, length);
    }

    /**
     * Produces a arbitrary number of output bytes which depend on the bytes absorbed so far.
     *
     * @param Y      output buffer to squeeze to
     * @param offset where in the buffer to squeeze to
     * @param length how many bytes to squeeze
     */
    public void squeeze(byte @NotNull [] Y, int offset, int length) {
        squeezeAny(DomainConstant.Squeeze, Y, offset, length);
    }

    /**
     * Enciphers and absorbs the provided plaintext buffer into the provided ciphertext output buffer.
     *
     * @param pt       input plaintext buffer
     * @param offset   where in the plaintext buffer to encipher from
     * @param length   how many bytes to encipher
     * @param ct       output ciphertext buffer
     * @param ctOffset where in the ciphertext buffer to encipher to
     */
    public void encrypt(byte @NotNull [] pt, int offset, int length, byte @NotNull [] ct, int ctOffset) {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        crypt(false, pt, offset, length, ct, ctOffset);
    }

    /**
     * Deciphers the provided ciphertext buffer into the provided plaintext output buffer and absorbs the plaintext.
     *
     * @param ct       input ciphertext buffer
     * @param offset   where in the ciphertext buffer to decipher from
     * @param length   how many bytes to decipher
     * @param pt       output plaintext buffer
     * @param ptOffset where in the plaintext buffer to decipher to
     */
    public void decrypt(byte @NotNull [] ct, int offset, int length, byte @NotNull [] pt, int ptOffset) {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        crypt(true, ct, offset, length, pt, ptOffset);
    }

    /**
     * Produces an arbitrary length key similarly to {@link #squeeze(byte[], int, int)} but in a separate domain for performing
     * key derivation.
     *
     * @param key    output key buffer
     * @param offset where to write key bytes
     * @param length how many bytes to write
     */
    public void squeezeKey(byte @NotNull [] key, int offset, int length) {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        squeezeAny(DomainConstant.SqueezeKey, key, offset, length);
    }

    /**
     * Transforms internal state in an irreversible way to ensure forward secrecy.
     */
    public void ratchet() {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        byte[] buffer = new byte[RATCHET_SIZE];
        // Squeeze then absorb is the same as overwriting with zeros
        squeezeAny(DomainConstant.Ratchet, buffer, 0, buffer.length);
        absorbAny(DomainConstant.Block, absorbRate(), buffer, 0, buffer.length);
    }

    /**
     * @return the number of bytes that can be absorbed between permutations
     */
    protected abstract int absorbRate();

    protected abstract void absorbAny(@NotNull DomainConstant d, int r, byte @NotNull [] Xi, int offset, int length);

    protected abstract void absorbKey(byte @NotNull [] key, byte @NotNull [] id, byte @NotNull [] counter);

    protected abstract void crypt(
            boolean decrypt, byte @NotNull [] in, int offset, int length, byte @NotNull [] out, int outOffset);

    protected abstract void squeezeAny(@NotNull DomainConstant u, byte @NotNull [] Y, int offset, int length);

    protected abstract void down(@NotNull DomainConstant d, byte @NotNull [] Xi, int offset, int length);

    protected abstract void up(@NotNull DomainConstant u, byte @NotNull [] Yi, int offset, int length);

    /**
     * Frame bytes used during squeezing and absorbing to mark what domain the operation is being used in so that a
     * process history is properly maintained.
     */
    protected enum DomainConstant {
        Block(0x00),
        AbsorbKey(0x02),
        Absorb(0x03),
        Ratchet(0x10),
        SqueezeKey(0x20),
        Squeeze(0x40),
        Crypt(0x80);

        private final byte value;

        DomainConstant(int unsignedValue) {
            value = (byte) unsignedValue;
        }

        public byte value() {
            return value;
        }
    }

    protected enum Phase {
        Down, Up
    }

    protected enum Mode {
        Hashed, Keyed
    }
}
