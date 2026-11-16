// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The transaction lost a conflict and was aborted; retrying the whole transaction is safe (RGN-2001 {@code TransactionConflict}, RGN-2005 {@code DeadlockDetected}, RGN-2007 {@code ReadTimestampTooOld}, RGN-2008 {@code WriteTooOld}).
 */
public class TransactionConflictException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public TransactionConflictException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}