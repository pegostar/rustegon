// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

/** JSON output mode (data-model.md §2 type-system notes). The parser accepts both. */
public enum JsonMode {
    /**
     * Plain JSON wherever lossless — int64 as a number when |v| ≤ 2^53, float64 as a number
     * that always contains {@code .} or an exponent — and the {@code $} wrappers otherwise.
     * The same document always gives the same text.
     */
    CANONICAL,
    /** As canonical, but every int64 is {@code {"$int64":…}} and every float64 {@code {"$float":…}}. */
    EXTENDED
}
