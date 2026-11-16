// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * RFC 9562 version-7 UUIDs for {@code rgn-request-id} (protocol.md §2, §5.1): 48-bit Unix
 * milliseconds, version 7, 12 random bits, the RFC variant, 62 random bits. The server rejects
 * any other version (RGN-1001), and the id keys its idempotency records, so it must be unique:
 * 74 random bits per millisecond make a collision negligible.
 */
public final class UuidV7 {
    private static final SecureRandom RANDOM = new SecureRandom();

    private UuidV7() {}

    /**
     * A new id.
     *
     * @return the id
     */
    public static UUID next() {
        return at(System.currentTimeMillis());
    }

    /**
     * A new id for a given time (tests).
     *
     * @param unixMillis milliseconds since the epoch
     * @return the id
     */
    static UUID at(long unixMillis) {
        long randA = RANDOM.nextInt(1 << 12);
        long randB = RANDOM.nextLong();
        long msb = (unixMillis & 0xFFFF_FFFF_FFFFL) << 16 | 0x7000L | randA;
        long lsb = (randB & 0x3FFF_FFFF_FFFF_FFFFL) | 0x8000_0000_0000_0000L;
        return new UUID(msb, lsb);
    }
}
