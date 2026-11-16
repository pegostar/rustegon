// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@link RustegonClient#startSession(SessionOptions)}.
 *
 * @param causalConsistency whether the session propagates causality tokens (default true)
 */
public record SessionOptions(boolean causalConsistency) {
    /**
     * The defaults: causal consistency on.
     *
     * @return the options
     */
    public static SessionOptions defaults() {
        return new SessionOptions(true);
    }
}
