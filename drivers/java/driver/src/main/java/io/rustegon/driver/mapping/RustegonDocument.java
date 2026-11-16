// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a record, class or sealed interface as a mapped document type (java-driver.md §5): the
 * {@code rustegon-processor} annotation processor generates its zero-reflection codec
 * ({@code <Type>_RgnCodec}) and its field-name metamodel ({@code <Type>_}). Types used by an
 * annotated type (nested documents, permitted subtypes) get codecs as well. Without the
 * processor the same mapping is done at run time with {@code MethodHandles} ({@link Mapper}).
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface RustegonDocument {}
