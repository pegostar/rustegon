// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/** State of an index ({@code IndexState} of schema.proto). */
public enum IndexState {
    /** Being built; not used by queries yet. */
    BUILDING,
    /** Ready. */
    READY,
    /** The build failed. */
    FAILED,
    /** Maintained but hidden from the planner. */
    HIDDEN,
    /** A state this driver version does not know. */
    UNKNOWN
}
