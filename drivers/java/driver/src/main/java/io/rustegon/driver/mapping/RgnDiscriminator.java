// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Polymorphism over a sealed interface or sealed abstract class. On the sealed root,
 * {@link #field()} names the discriminator field (default {@code _type}); on a permitted
 * subtype, {@link #value()} is the value written to that field (default: the subtype's simple
 * name). The discriminator follows {@code _id} (or comes first without one); a document whose
 * value names no subtype is rejected when read.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface RgnDiscriminator {
    /**
     * The discriminator value of the annotated subtype (default: its simple name).
     *
     * @return the value, or empty for the default
     */
    String value() default "";

    /**
     * The discriminator field of the annotated sealed root.
     *
     * @return the field name
     */
    String field() default "_type";
}
