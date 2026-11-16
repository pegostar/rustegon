// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The node or the data is temporarily unavailable, or the connection failed (RGN-3002 {@code Unavailable}, RGN-3004 {@code NodeDraining}, RGN-3005, RGN-3007 and internal routing codes); retryable.
 */
public class UnavailableException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public UnavailableException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}