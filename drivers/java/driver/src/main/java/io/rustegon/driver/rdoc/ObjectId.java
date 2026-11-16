// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A 12-byte object identifier (data-model.md §2, type {@code objectId}, FR-DOC-002).
 *
 * <p>Layout, big endian so that ids sort by creation second: 4 bytes Unix seconds, 5 bytes chosen
 * at random once per process, 3 bytes counter starting at a random value. Immutable; ordered by
 * unsigned byte comparison (the server's order).
 */
public final class ObjectId implements Comparable<ObjectId> {
    /** Number of bytes of an object id. */
    public static final int LENGTH = 12;
    private static final HexFormat HEX = HexFormat.of();
    private static final int COUNTER_MASK = 0x00FF_FFFF;
    private static final byte[] PROCESS = new byte[5];
    // Uniqueness only needs every getAndIncrement to return a distinct value; the counter
    // publishes no other memory, so no ordering beyond the atomic update is required.
    private static final AtomicInteger COUNTER;

    static {
        SecureRandom random = new SecureRandom();
        random.nextBytes(PROCESS);
        COUNTER = new AtomicInteger(random.nextInt() & COUNTER_MASK);
    }

    private final byte[] bytes;

    private ObjectId(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Generates a new id from the current time, the process value and the counter. Ids are
     * unique as long as fewer than 2^24 are generated per second in one process.
     *
     * @return a new id
     */
    public static ObjectId get() {
        // Seconds wrap modulo 2^32 (year 2106), as on the server: a uniqueness aid, not a
        // timestamp of record.
        long seconds = Math.max(0, System.currentTimeMillis() / 1000) & 0xFFFF_FFFFL;
        int count = COUNTER.getAndIncrement() & COUNTER_MASK;
        byte[] b = new byte[LENGTH];
        b[0] = (byte) (seconds >>> 24);
        b[1] = (byte) (seconds >>> 16);
        b[2] = (byte) (seconds >>> 8);
        b[3] = (byte) seconds;
        System.arraycopy(PROCESS, 0, b, 4, PROCESS.length);
        b[9] = (byte) (count >>> 16);
        b[10] = (byte) (count >>> 8);
        b[11] = (byte) count;
        return new ObjectId(b);
    }

    /**
     * An id from its 12 bytes.
     *
     * @param bytes exactly 12 bytes (copied)
     * @return the id
     * @throws IllegalArgumentException if {@code bytes} is not 12 bytes long
     */
    public static ObjectId of(byte[] bytes) {
        if (bytes.length != LENGTH) {
            throw new IllegalArgumentException("an objectId has 12 bytes");
        }
        return new ObjectId(bytes.clone());
    }

    /**
     * Parses 24 hexadecimal digits (either case).
     *
     * @param hex the text
     * @return the id
     * @throws RDocException ({@link RDocException#INVALID_ARGUMENT}) if {@code hex} is not
     *     exactly 24 hex digits
     */
    public static ObjectId parse(String hex) {
        if (hex.length() != 2 * LENGTH || !isHex(hex)) {
            throw RDocException.invalid("objectId must be 24 hex digits");
        }
        return new ObjectId(HEX.parseHex(hex));
    }

    /** ASCII hex digits only ({@link Character#digit} also accepts other Unicode digits). */
    static boolean isHex(CharSequence s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    /**
     * The 12 bytes.
     *
     * @return a copy of the bytes
     */
    public byte[] toByteArray() {
        return bytes.clone();
    }

    byte[] raw() {
        return bytes;
    }

    /**
     * The creation time in Unix seconds (first 4 bytes, unsigned).
     *
     * @return seconds since the epoch
     */
    public long seconds() {
        return ((bytes[0] & 0xFFL) << 24) | ((bytes[1] & 0xFFL) << 16)
                | ((bytes[2] & 0xFFL) << 8) | (bytes[3] & 0xFFL);
    }

    /**
     * 24 lowercase hex digits.
     *
     * @return the hex text
     */
    @Override
    public String toString() {
        return HEX.formatHex(bytes);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ObjectId other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public int compareTo(ObjectId o) {
        return Arrays.compareUnsigned(bytes, o.bytes);
    }
}
