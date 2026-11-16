// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.util.Arrays;

/**
 * A {@code vector_f32} value (data-model.md §2, type tag 0x0E): finite 32-bit floats. A plain
 * {@code float[]} written into a document becomes a vector; documents read back hold
 * {@code RVector} so that {@link #equals} compares elements.
 *
 * @param values the elements (defensively copied in and out)
 */
public record RVector(float[] values) {
    /**
     * Validates and copies.
     *
     * @param values the elements
     * @throws RDocException ({@link RDocException#INVALID_VECTOR}) for a non-finite element
     */
    public RVector {
        for (float v : values) {
            if (!Float.isFinite(v)) {
                throw new RDocException(RDocException.INVALID_VECTOR, "non-finite element");
            }
        }
        values = values.clone();
    }

    /**
     * The elements.
     *
     * @return a copy of the elements
     */
    @Override
    public float[] values() {
        return values.clone();
    }

    float[] raw() {
        return values;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RVector v && Arrays.equals(values, v.values);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(values);
    }

    @Override
    public String toString() {
        return "RVector" + Arrays.toString(values);
    }
}
