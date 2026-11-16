// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/** The outcome of a commit as reported by {@code TransactionService.Status} (transactions.md §3). */
public enum TransactionOutcome {
    /** The transaction committed. */
    COMMITTED,
    /** The transaction aborted: none of its writes took effect. */
    ABORTED,
    /** Still unknown (active or committing): ask again later. */
    UNKNOWN
}
