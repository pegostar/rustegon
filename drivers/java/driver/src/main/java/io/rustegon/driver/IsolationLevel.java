// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/** Isolation level of a transaction (transactions.md §2). */
public enum IsolationLevel {
    /** Serializable (the default). */
    SERIALIZABLE,
    /** Snapshot isolation. */
    SNAPSHOT,
    /** Read committed. */
    READ_COMMITTED
}
