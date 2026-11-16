// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A {@code double[]} property {@code [longitude, latitude]} (WGS84 degrees) stored as a GeoJSON
 * point {@code {"type": "Point", "coordinates": [lon, lat]}} (FR-GEO-001); longitude must be
 * in [-180, 180] and latitude in [-90, 90].
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.RECORD_COMPONENT})
public @interface RgnGeoPoint {}
