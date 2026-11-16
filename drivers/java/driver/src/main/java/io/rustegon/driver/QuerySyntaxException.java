// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * An RGQL statement is rejected by the parser or the type checker (RGN-1010
 * {@code QuerySyntaxError}, RGN-1011 {@code QueryTypeError}, RGN-1012 {@code UnknownFunction});
 * {@link #details()} locates the error.
 */
public class QuerySyntaxException extends RustegonClientException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public QuerySyntaxException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}