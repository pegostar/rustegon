// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@code deleteOne} / {@code deleteMany}.
 *
 * @param ifRev expected current {@code _rev} (by-id deletes only), or {@code null}
 */
public record DeleteOptions(String ifRev) {
    /**
     * No options.
     *
     * @return the options
     */
    public static DeleteOptions defaults() {
        return new DeleteOptions(null);
    }

    /**
     * Only delete when the document's {@code _rev} is {@code rev}.
     *
     * @param rev the expected revision
     * @return the options
     */
    public static DeleteOptions ifRev(String rev) {
        return new DeleteOptions(java.util.Objects.requireNonNull(rev, "rev"));
    }
}
