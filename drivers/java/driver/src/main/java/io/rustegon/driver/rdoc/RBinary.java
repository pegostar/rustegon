// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * A {@code binary} value: a subtype and bytes (data-model.md §2, type tag 0x07).
 *
 * <p>Subtypes: {@link #GENERIC} (0), {@link #UUID} (4, exactly 16 bytes) and user-defined
 * 0x80–0xFF; the others are reserved and rejected. A plain {@code byte[]} written into a
 * document becomes a generic binary; documents read back always hold {@code RBinary}.
 *
 * @param subtype the subtype byte (0–255)
 * @param data the bytes (defensively copied in and out)
 */
public record RBinary(int subtype, byte[] data) {
    /** Generic binary subtype. */
    public static final int GENERIC = 0;
    /** UUID binary subtype (16 bytes). */
    public static final int UUID = 4;
    /** First user-defined subtype. */
    public static final int USER_MIN = 0x80;
    private static final int UUID_LEN = 16;

    /**
     * Validates and copies.
     *
     * @param subtype the subtype byte (0–255)
     * @param data the bytes
     * @throws RDocException for a reserved subtype or a UUID binary that is not 16 bytes
     */
    public RBinary {
        check(subtype, data.length);
        data = data.clone();
    }

    /**
     * A generic binary.
     *
     * @param data the bytes (copied)
     * @return the value
     */
    public static RBinary of(byte[] data) {
        return new RBinary(GENERIC, data);
    }

    static void check(int subtype, int length) {
        if (subtype < 0 || subtype > 0xFF) {
            throw RDocException.invalid("binary subtype must be a byte");
        }
        if (subtype == UUID && length != UUID_LEN) {
            throw RDocException.invalid("binary subtype 4 (uuid) needs 16 bytes");
        }
        if (subtype != GENERIC && subtype != UUID && subtype < USER_MIN) {
            throw RDocException.invalid("reserved binary subtype");
        }
    }

    /**
     * The bytes.
     *
     * @return a copy of the bytes
     */
    @Override
    public byte[] data() {
        return data.clone();
    }

    byte[] raw() {
        return data;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RBinary b && subtype == b.subtype && Arrays.equals(data, b.data);
    }

    @Override
    public int hashCode() {
        return 31 * subtype + Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "RBinary[subtype=" + subtype + ", length=" + data.length + ", data="
                + HexFormat.of().formatHex(data, 0, Math.min(data.length, 32))
                + (data.length > 32 ? "…" : "") + "]";
    }
}
