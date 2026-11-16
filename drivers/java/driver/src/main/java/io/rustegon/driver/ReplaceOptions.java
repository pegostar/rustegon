// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@code replaceOne}.
 *
 * @param upsert insert the document when no document has the id (needs {@code Filters.id})
 * @param ifRev expected current {@code _rev} (by-id only), or {@code null}
 */
public record ReplaceOptions(boolean upsert, String ifRev) {
    /**
     * No options.
     *
     * @return the options
     */
    public static ReplaceOptions defaults() {
        return new ReplaceOptions(false, null);
    }

    /**
     * Insert when missing ({@code DocumentService.Upsert}).
     *
     * @return the options
     */
    public static ReplaceOptions withUpsert() {
        return new ReplaceOptions(true, null);
    }

    /**
     * Only replace when the document's {@code _rev} is {@code rev}.
     *
     * @param rev the expected revision
     * @return the options
     */
    public static ReplaceOptions ifRev(String rev) {
        return new ReplaceOptions(false, java.util.Objects.requireNonNull(rev, "rev"));
    }
}
