// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Write concern of operations (proto {@code WriteConcern}, consistency.md). {@code null} in the
 * settings means the server default (majority).
 */
public enum WriteConcern {
    /** Acknowledged by a majority of replicas. */
    MAJORITY,
    /** Acknowledged by every replica. */
    ALL,
    /** Majority within the local datacenter (cross-datacenter collections). */
    LOCAL_DC_MAJORITY,
    /** Synchronous cross-datacenter replication. */
    SYNC_CROSS_DC,
    /** Asynchronous cross-datacenter replication. */
    ASYNC_CROSS_DC;

    /** Connection-string spelling (lowercase snake case). */
    String wireName() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
