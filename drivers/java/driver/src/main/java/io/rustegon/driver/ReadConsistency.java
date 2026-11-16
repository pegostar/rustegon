// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Read consistency of operations (proto {@code ReadConsistencyLevel}, consistency.md).
 * {@code null} in the settings means the server default (linearizable).
 */
public enum ReadConsistency {
    /** Reads observe every write committed before they started. */
    LINEARIZABLE,
    /** Reads may be at most the configured staleness behind (needs a max staleness). */
    BOUNDED_STALENESS,
    /** Reads served by any replica at its latest applied state. */
    FOLLOWER;

    /** Connection-string spelling (lowercase snake case, as REST enumerations). */
    String wireName() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
