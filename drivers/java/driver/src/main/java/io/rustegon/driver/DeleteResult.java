// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Result of {@code deleteOne} / {@code deleteMany}.
 *
 * @param deletedCount documents deleted
 */
public record DeleteResult(long deletedCount) {}
