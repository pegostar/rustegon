// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * The structured error the server reports with a failed call ({@code ErrorDetail}, protocol.md
 * §3, §7), or the equivalent the driver derives for a transport failure.
 *
 * @param code numeric code ({@code RGN-<code>}, catalog {@code proto/errors.yaml})
 * @param name stable name, e.g. {@code DuplicateKey}
 * @param retryable whether the server says the operation may be retried
 * @param committed for commit errors, whether the transaction is known to have committed;
 *     {@code null} when not applicable
 * @param details structured details (never document contents or secrets)
 * @param traceId W3C trace id of the failed request ({@code ""} when unknown)
 * @param retryAfter suggested wait before retrying; {@code null} when none
 */
public record RustegonError(int code, String name, boolean retryable, Boolean committed,
        Map<String, String> details, String traceId, Duration retryAfter) {
    /**
     * Copies {@code details}.
     *
     * @param code numeric code
     * @param name stable name
     * @param retryable retry flag
     * @param committed commit state or {@code null}
     * @param details details (copied)
     * @param traceId trace id
     * @param retryAfter wait or {@code null}
     */
    public RustegonError {
        details = Map.copyOf(details);
        traceId = traceId == null ? "" : traceId;
    }

    /**
     * {@link #committed} as an optional.
     *
     * @return the commit state, empty when not applicable
     */
    public Optional<Boolean> committedState() {
        return Optional.ofNullable(committed);
    }
}
