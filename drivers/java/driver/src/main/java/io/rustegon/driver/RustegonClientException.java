// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * The request itself is wrong and must not be retried unchanged: invalid arguments, documents
 * that are too large or too deep, unknown indexes or collections, precondition failures and the
 * other client errors of {@code drivers/conformance/errors-map.yaml} without a more specific
 * class (java-driver.md §6, PD-075). {@link QuerySyntaxException} is a subclass.
 */
public class RustegonClientException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public RustegonClientException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}
