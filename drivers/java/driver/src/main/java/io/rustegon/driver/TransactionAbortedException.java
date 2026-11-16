// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The transaction was aborted (RGN-2002 {@code TransactionAborted}); {@link #isRetryable()} depends on the reason in {@link #details()}.
 */
public class TransactionAbortedException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public TransactionAbortedException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}