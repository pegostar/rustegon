// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * A failed operation of a bulk write.
 *
 * @param index index of the operation in the request
 * @param error the structured error ({@code error().code()} is the RGN code)
 * @param message human-readable message
 */
public record BulkWriteError(int index, RustegonError error, String message) {}
