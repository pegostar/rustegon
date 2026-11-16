// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * A server-side failure (RGN-5001…5006: {@code Internal}, {@code StorageCorruption},
 * {@code DiskFull}, {@code ResourceExhausted}, {@code Cancelled} by the server; RGN-4006
 * {@code KeyUnavailable}; the internal RGN-1034), and failed calls without a server error
 * detail whose gRPC status has no more specific mapping.
 */
public class RustegonServerException extends RustegonException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public RustegonServerException(String message, RustegonError error, Throwable cause) {
        super(message, error, cause);
    }
}