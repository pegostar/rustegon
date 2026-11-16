// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The server throttled the caller (RGN-4003 {@code RateLimited}); wait {@link #retryAfter()} before retrying.
 */
public class RateLimitedException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public RateLimitedException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}