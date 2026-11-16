// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The authenticated principal lacks the privilege for the operation (RGN-4002 {@code PermissionDenied}).
 */
public class AuthorizationException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public AuthorizationException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}