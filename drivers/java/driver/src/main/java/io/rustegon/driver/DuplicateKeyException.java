// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * A write would create a second document with the same key in a unique index or {@code _id} (RGN-1005 {@code DuplicateKey}).
 */
public class DuplicateKeyException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public DuplicateKeyException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}