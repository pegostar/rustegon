// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

/**
 * A {@code timestamp} value: a hybrid logical clock reading, mostly system-generated
 * (data-model.md §2, type tag 0x09). Both parts are unsigned; JSON form {@code {"$ts":"w.l"}}.
 *
 * @param wall the wall part, an unsigned 64-bit integer
 * @param logical the logical part, an unsigned 32-bit integer
 */
public record RTimestamp(long wall, int logical) {
    @Override
    public String toString() {
        return Long.toUnsignedString(wall) + "." + Integer.toUnsignedString(logical);
    }
}
