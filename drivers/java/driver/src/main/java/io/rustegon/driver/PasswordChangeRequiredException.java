// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The login succeeded but the server requires a new password before any other operation (PD-076, {@code must_change_password}); raised unless the settings allow a password-change-only session ({@link RustegonClientSettings.Builder#allowPasswordChangeOnly(boolean)}).
 */
public class PasswordChangeRequiredException extends AuthenticationException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public PasswordChangeRequiredException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}