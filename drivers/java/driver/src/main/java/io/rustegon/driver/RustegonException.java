// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * Base of every error the driver reports for a failed operation (java-driver.md §6). Unchecked.
 *
 * <p>The subclass follows from the error code only, by the table shared with the .NET driver
 * ({@code drivers/conformance/errors-map.yaml}, compiled as
 * {@link io.rustegon.driver.errors.ErrorCodes}, PD-075); a code unknown to this driver version
 * (a newer server) is reported as this class with {@link #code()} set. {@link #isRetryable()}
 * and {@link #committed()} come from the server's response, never from the table. Messages
 * never contain document contents or secrets.
 */
public class RustegonException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** The structured error. */
    private final transient RustegonError error;

    /**
     * Creates the exception.
     *
     * @param message human-readable message
     * @param error the structured error
     * @param cause the underlying failure, or {@code null}
     */
    public RustegonException(String message, RustegonError error, Throwable cause) {
        super(message, cause);
        this.error = error;
    }

    /**
     * The numeric error code ({@code RGN-<code>}).
     *
     * @return the code
     */
    public int code() {
        return error.code();
    }

    /**
     * The stable error name, e.g. {@code DuplicateKey}.
     *
     * @return the name
     */
    public String name() {
        return error.name();
    }

    /**
     * Whether the operation may be retried, as reported by the server (protocol.md §7).
     *
     * @return the retry flag
     */
    public boolean isRetryable() {
        return error.retryable();
    }

    /**
     * For commit errors, whether the transaction is known to have committed.
     *
     * @return the commit state, empty when not applicable
     */
    public Optional<Boolean> committed() {
        return error.committedState();
    }

    /**
     * Structured details of the error (never document contents or secrets).
     *
     * @return an unmodifiable map
     */
    public Map<String, String> details() {
        return error.details();
    }

    /**
     * W3C trace id of the failed request, for correlation with server logs.
     *
     * @return the trace id, {@code ""} when unknown
     */
    public String traceId() {
        return error.traceId();
    }

    /**
     * Suggested wait before retrying ({@code RateLimited} and similar).
     *
     * @return the wait, empty when none was suggested
     */
    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(error.retryAfter());
    }

    /**
     * The whole structured error.
     *
     * @return the error
     */
    public RustegonError error() {
        return error;
    }
}
