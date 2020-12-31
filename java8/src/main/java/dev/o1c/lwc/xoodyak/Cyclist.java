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
 *
 * SPDX-License-Identifier: ISC
 */

package dev.o1c.lwc.xoodyak;

import org.jetbrains.annotations.NotNull;

/**
 * Implements the <a href="https://keccak.team/files/Xoodyak-doc1.1.pdf">cyclist mode of operation</a> for implementing
 * cryptographic primitives based on permutations such as Xoodooo. Ported from the
 * <a href="https://github.com/XKCP/XKCP/blob/master/lib/high/Xoodyak/Cyclist.inc">reference C implementation</a>.
 *
 * @see <a href="https://github.com/XKCP/XKCP">Xoodoo and Keccak Code Package reference implementations</a>
 * @see <a href="https://github.com/KeccakTeam/Xoodoo/">Xoodoo C++ and Python reference implementations</a>
 */
public abstract class Cyclist {
    private static final int RATCHET_SIZE = 16;
    protected static final byte[] EMPTY = new byte[0];
    protected Mode mode;

    public void initialize() {
        initialize(EMPTY);
    }

    public void initialize(byte @NotNull [] key) {
        initialize(key, EMPTY, EMPTY);
    }

    public abstract void initialize(byte @NotNull [] key, byte @NotNull [] id, byte @NotNull [] counter);

    public void absorb(byte @NotNull [] X, int offset, int length) {
        absorbAny(DomainConstant.Absorb, absorbRate(), X, offset, length);
    }

    public void encrypt(byte @NotNull [] pt, int offset, int length, byte @NotNull [] ct, int ctOffset) {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        crypt(false, pt, offset, length, ct, ctOffset);
    }

    public void decrypt(byte @NotNull [] ct, int offset, int length, byte @NotNull [] pt, int ptOffset) {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        crypt(true, ct, offset, length, pt, ptOffset);
    }

    public void squeeze(byte @NotNull [] Y, int offset, int length) {
        squeezeAny(DomainConstant.Squeeze, Y, offset, length);
    }

    public void squeezeKey(byte @NotNull [] key, int offset, int length) {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        squeezeAny(DomainConstant.SqueezeKey, key, offset, length);
    }

    public void ratchet() {
        if (mode != Mode.Keyed) {
            throw new IllegalStateException("No key initialized");
        }
        byte[] buffer = new byte[RATCHET_SIZE];
        // Squeeze then absorb is the same as overwriting with zeros
        squeezeAny(DomainConstant.Ratchet, buffer, 0, buffer.length);
        absorbAny(DomainConstant.Zero, absorbRate(), buffer, 0, buffer.length);
    }

    protected abstract int absorbRate();

    protected abstract void absorbAny(@NotNull DomainConstant d, int r, byte @NotNull [] Xi, int offset, int length);

    protected abstract void absorbKey(byte @NotNull [] key, byte @NotNull [] id, byte @NotNull [] counter);

    protected abstract void crypt(
            boolean decrypt, byte @NotNull [] in, int offset, int length, byte @NotNull [] out, int outOffset);

    protected abstract void squeezeAny(@NotNull DomainConstant u, byte @NotNull [] Y, int offset, int length);

    protected abstract void down(@NotNull DomainConstant d, byte @NotNull [] Xi, int offset, int length);

    protected abstract void up(@NotNull DomainConstant u, byte @NotNull [] Yi, int offset, int length);

    protected enum DomainConstant {
        Zero(0x00),
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
