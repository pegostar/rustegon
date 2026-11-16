// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The body of {@link RustegonClient#withTransaction}. It may run several times (each time in a
 * new transaction), so it must be idempotent with respect to external side effects
 * (transactions.md §5).
 *
 * @param <T> the result type
 */
@FunctionalInterface
public interface TransactionCallback<T> {
    /**
     * Runs the work of one attempt.
     *
     * @param txn the transaction of this attempt
     * @return the result
     */
    T run(Transaction txn);
}
