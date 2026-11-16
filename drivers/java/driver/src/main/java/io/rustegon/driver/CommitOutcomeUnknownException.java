// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.function.Supplier;

/**
 * The commit may or may not have taken effect (RGN-2006 {@code CommitOutcomeUnknown}): never
 * retry it blindly, resolve it with the transaction status first (transactions.md §5).
 * {@link RustegonClient#withTransaction} resolves it on its own; in manual mode the exception
 * thrown by {@link Transaction#commit()} offers {@link #resolve()}.
 */
public class CommitOutcomeUnknownException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /** Asks the server for the outcome; {@code null} when not raised by a commit. */
    private final transient Supplier<TransactionOutcome> resolver;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public CommitOutcomeUnknownException(String message, RustegonError error, Throwable cause) {
        this(message, error, cause, null);
    }

    CommitOutcomeUnknownException(String message, RustegonError error, Throwable cause,
            Supplier<TransactionOutcome> resolver) {
        super(message, error, cause);
        this.resolver = resolver;
    }

    /**
     * Asks the server whether the transaction committed ({@code TransactionService.Status},
     * same as {@link Transaction#resolve()}); call it again later while it answers
     * {@link TransactionOutcome#UNKNOWN}.
     *
     * @return the outcome
     * @throws IllegalStateException if the exception was not raised by
     *     {@link Transaction#commit()}
     * @throws RustegonException if the status call fails
     */
    public TransactionOutcome resolve() {
        if (resolver == null) {
            throw new IllegalStateException("no transaction to resolve");
        }
        return resolver.get();
    }
}
