// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

/**
 * A SCRAM exchange failed on the client side (malformed or hostile server message, signature
 * mismatch). The session authenticator turns it into an {@code AuthenticationException}.
 */
public final class ScramException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message reason (never contains secrets)
     */
    public ScramException(String message) {
        super(message);
    }
}
