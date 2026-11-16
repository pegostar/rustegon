// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Options of {@link RustegonClient#beginTransaction} and {@link RustegonClient#withTransaction}
 * (transactions.md §2, §5). Immutable:
 * {@code TransactionOptions.serializable().maxRetryTime(Duration.ofMinutes(2))}.
 */
public final class TransactionOptions {
    /** Default retry budget of {@code withTransaction} (transactions.md §5). */
    public static final Duration DEFAULT_MAX_RETRY_TIME = Duration.ofSeconds(120);
    private static final TransactionOptions DEFAULTS =
            new TransactionOptions(null, false, DEFAULT_MAX_RETRY_TIME);

    private final IsolationLevel isolation;
    private final boolean readOnly;
    private final Duration maxRetryTime;

    private TransactionOptions(IsolationLevel isolation, boolean readOnly, Duration maxRetryTime) {
        this.isolation = isolation;
        this.readOnly = readOnly;
        this.maxRetryTime = maxRetryTime;
    }

    /**
     * The server's default isolation (serializable), read-write, 120 s retry budget.
     *
     * @return the options
     */
    public static TransactionOptions defaults() {
        return DEFAULTS;
    }

    /**
     * Serializable isolation.
     *
     * @return the options
     */
    public static TransactionOptions serializable() {
        return DEFAULTS.isolation(IsolationLevel.SERIALIZABLE);
    }

    /**
     * Snapshot isolation.
     *
     * @return the options
     */
    public static TransactionOptions snapshot() {
        return DEFAULTS.isolation(IsolationLevel.SNAPSHOT);
    }

    /**
     * Read-committed isolation.
     *
     * @return the options
     */
    public static TransactionOptions readCommitted() {
        return DEFAULTS.isolation(IsolationLevel.READ_COMMITTED);
    }

    /**
     * These options with another isolation level.
     *
     * @param level the level
     * @return the options
     */
    public TransactionOptions isolation(IsolationLevel level) {
        return new TransactionOptions(Objects.requireNonNull(level, "level"), readOnly,
                maxRetryTime);
    }

    /**
     * These options, read-only or read-write.
     *
     * @param readOnly whether the transaction only reads
     * @return the options
     */
    public TransactionOptions readOnly(boolean readOnly) {
        return new TransactionOptions(isolation, readOnly, maxRetryTime);
    }

    /**
     * These options with another retry budget of {@code withTransaction}: retryable failures
     * re-run the callback while less than this time has passed since the first attempt.
     *
     * @param time zero or more
     * @return the options
     */
    public TransactionOptions maxRetryTime(Duration time) {
        if (Objects.requireNonNull(time, "time").isNegative()) {
            throw new IllegalArgumentException("maxRetryTime must not be negative");
        }
        return new TransactionOptions(isolation, readOnly, time);
    }

    /**
     * The isolation level.
     *
     * @return the level, empty for the server default (serializable)
     */
    public Optional<IsolationLevel> isolation() {
        return Optional.ofNullable(isolation);
    }

    /**
     * Whether the transaction only reads.
     *
     * @return the flag
     */
    public boolean isReadOnly() {
        return readOnly;
    }

    /**
     * The retry budget of {@code withTransaction}.
     *
     * @return the budget
     */
    public Duration maxRetryTime() {
        return maxRetryTime;
    }

    @Override
    public String toString() {
        return "TransactionOptions[isolation=" + isolation + ", readOnly=" + readOnly
                + ", maxRetryTime=" + maxRetryTime + "]";
    }
}
