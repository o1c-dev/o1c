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

import java.nio.ByteBuffer;

/**
 * Provides a cyclist mode of operation using the Xoodoo permutation known as Xoodyak.
 *
 * @see <a href="https://github.com/XKCP/XKCP">Xoodoo and Keccak Code Package reference implementations</a>
 * @see <a href="https://github.com/KeccakTeam/Xoodoo/">Xoodoo C++ and Python reference implementations</a>
 */
class Xoodyak extends Cyclist {
    private static final int STATE_SIZE = 48;
    private static final int HASH_RATE = 16;
    // note that kin rate needs 2 bytes for domain values for marking state transitions
    private static final int KEY_IN_RATE = 44;
    private static final int KEY_OUT_RATE = 24;
    private static final byte[] EMPTY = new byte[0];

    private final Xoodoo xoodoo = new Xoodoo();
    private Phase phase;
    private int absorbRate;
    private int squeezeRate;

    @Override
    public void initialize(byte @NotNull [] key, byte @NotNull [] id, byte @NotNull [] counter) {
        xoodoo.reset();
        phase = Phase.Up;
        mode = Mode.Hashed;
        absorbRate = HASH_RATE;
        squeezeRate = HASH_RATE;
        if (key.length != 0) {
            absorbKey(key, id, counter);
        }
    }

    @Override
    protected int absorbRate() {
        return absorbRate;
    }

    @Override
    protected void absorbAny(@NotNull DomainConstant d, int r, byte @NotNull [] Xi, int offset, int length) {
        do {
            if (phase != Phase.Up) {
                up(DomainConstant.Block, EMPTY, 0, 0);
            }
            int splitLen = Math.min(r, length);
            down(d, Xi, offset, splitLen);
            d = DomainConstant.Block;
            length -= splitLen;
            offset += splitLen;
        } while (length > 0);
    }

    @Override
    protected void absorbKey(byte @NotNull [] key, byte @NotNull [] id, byte @NotNull [] counter) {
        if (mode != Mode.Hashed) {
            throw new IllegalStateException("Key already initialized");
        }
        if (key.length + id.length >= KEY_IN_RATE) {
            throw new IllegalArgumentException("Key and id must not exceed 43 bytes");
        }
        absorbRate = KEY_IN_RATE;
        squeezeRate = KEY_OUT_RATE;
        mode = Mode.Keyed;
        if (key.length != 0) {
            ByteBuffer bb = ByteBuffer.allocate(absorbRate);
            bb.put(key).put(id).put((byte) id.length).flip();
            absorbAny(DomainConstant.AbsorbKey, absorbRate, bb.array(), bb.arrayOffset(), bb.remaining());
            if (counter.length != 0) {
                absorbAny(DomainConstant.Block, 1, counter, 0, counter.length);
            }
        }
    }

    @Override
    protected void crypt(boolean decrypt, byte @NotNull [] in, int offset, int length, byte @NotNull [] out, int outOffset) {
        // already enforced by encrypt and decrypt
        assert squeezeRate == KEY_OUT_RATE;

        byte[] p = new byte[squeezeRate];
        DomainConstant constant = DomainConstant.Crypt;
        do {
            int splitLen = Math.min(squeezeRate, length);
            if (!decrypt) {
                System.arraycopy(in, offset, p, 0, splitLen);
            }
            up(constant, EMPTY, 0, 0);
            xoodoo.extractAndAddBytes(in, offset, splitLen, out, outOffset);
            if (decrypt) {
                down(DomainConstant.Block, out, outOffset, splitLen);
            } else {
                down(DomainConstant.Block, p, 0, splitLen);
            }
            constant = DomainConstant.Block;
            offset += splitLen;
            outOffset += splitLen;
            length -= splitLen;
        } while (length > 0);
    }

    @Override
    protected void squeezeAny(@NotNull DomainConstant u, byte @NotNull [] Y, int offset, int length) {
        int splitLen = Math.min(squeezeRate, length);
        up(u, Y, offset, splitLen);
        offset += splitLen;
        length -= splitLen;
        while (length > 0) {
            down(DomainConstant.Block, EMPTY, 0, 0);
            splitLen = Math.min(squeezeRate, length);
            up(DomainConstant.Block, Y, offset, splitLen);
            offset += splitLen;
            length -= splitLen;
        }
    }

    @Override
    protected void down(@NotNull DomainConstant d, byte @NotNull [] Xi, int offset, int length) {
        phase = Phase.Down;
        xoodoo.addBytes(Xi, offset, length);
        xoodoo.addByte(length, (byte) 0x01);
        xoodoo.addByte(STATE_SIZE - 1, mode == Mode.Hashed ? (byte) (d.value() & 0x01) : d.value());
    }

    @Override
    protected void up(@NotNull DomainConstant u, byte @NotNull [] Yi, int offset, int length) {
        phase = Phase.Up;
        if (mode != Mode.Hashed) {
            xoodoo.addByte(STATE_SIZE - 1, u.value());
        }
        xoodoo.permute();
        xoodoo.extractBytes(Yi, offset, length);
    }
}
