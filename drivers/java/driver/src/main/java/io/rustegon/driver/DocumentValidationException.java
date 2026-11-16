// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * A document fails the collection's validator (RGN-1006 {@code SchemaValidationFailed}); {@link #details()} carries {@code path}, {@code keyword} and {@code message}.
 */
public class DocumentValidationException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public DocumentValidationException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}