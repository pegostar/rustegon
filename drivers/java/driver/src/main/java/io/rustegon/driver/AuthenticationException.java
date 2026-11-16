// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The credentials were rejected or the session ended (RGN-4001 {@code Unauthenticated}, RGN-4004
 * {@code TlsRequired}, RGN-4005 {@code SessionExpired} after re-authentication failed, RGN-4007
 * {@code AccountLocked}); also raised when the server's SCRAM signature does not verify.
 */
public class AuthenticationException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public AuthenticationException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}