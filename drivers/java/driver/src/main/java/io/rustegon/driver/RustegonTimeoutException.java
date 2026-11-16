// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The operation did not finish within its deadline (RGN-5006 {@code DeadlineExceeded}, RGN-2003 {@code TransactionTimeout}, RGN-1024 {@code IndexStaleTimeout}, RGN-3006 {@code WriteConcernTimeout} with {@link #committed()} = true).
 */
public class RustegonTimeoutException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public RustegonTimeoutException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}