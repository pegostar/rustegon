// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@code updateOne} / {@code updateMany}.
 *
 * @param ifRev expected current {@code _rev} (by-id updates only; RGN-2009 on mismatch), or
 *     {@code null}
 */
public record UpdateOptions(String ifRev) {
    /**
     * No options.
     *
     * @return the options
     */
    public static UpdateOptions defaults() {
        return new UpdateOptions(null);
    }

    /**
     * Only update when the document's {@code _rev} is {@code rev} (optimistic concurrency).
     *
     * @param rev the expected revision
     * @return the options
     */
    public static UpdateOptions ifRev(String rev) {
        return new UpdateOptions(java.util.Objects.requireNonNull(rev, "rev"));
    }
}
