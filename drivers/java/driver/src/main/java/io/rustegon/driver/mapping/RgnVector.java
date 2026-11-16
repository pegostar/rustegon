// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A {@code float[]} property with a fixed number of dimensions ({@code vector_f32}); a value
 * of another length is rejected when written and when read. {@code float[]} properties without
 * this annotation are vectors of any length.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.RECORD_COMPONENT})
public @interface RgnVector {
    /**
     * The number of dimensions.
     *
     * @return the dimensions (at least 1)
     */
    int value();
}
