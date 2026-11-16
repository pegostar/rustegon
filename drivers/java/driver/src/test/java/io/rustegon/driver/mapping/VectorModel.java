// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

/**
 * The models of the cross-driver mapping vectors ({@code drivers/conformance/mapping/vectors.yaml}),
 * member for member as the file declares them; the .NET twins are in
 * {@code Rustegon.Driver.MappedTypes/MappingVectorModels.cs}.
 */
final class VectorModel {
    private VectorModel() {}

    /** Stored by member name, verbatim: the .NET twin spells its members the same way. */
    enum MapStatus { Draft, Paid }

    @RustegonDocument
    record MapItem(String name, String id, int count, float ratio, BigDecimal price,
            List<String> tags, String note, MapStatus status, @RgnField("zip") String postalCode,
            @RgnRev String rev, @RgnCounter long views, OffsetDateTime when) {}

    @RustegonDocument
    record MapGeo(@RgnId String key, @RgnVector(3) float[] embedding,
            @RgnGeoPoint double[] location) {}

    @RustegonDocument
    sealed interface MapShape permits MapCircle, MapSquare {}

    @RgnDiscriminator("circle")
    record MapCircle(String id, double radius) implements MapShape {}

    record MapSquare(double side) implements MapShape {}

    @RustegonDocument
    record MapDrawing(String id, MapShape main, List<MapShape> shapes) {}
}
