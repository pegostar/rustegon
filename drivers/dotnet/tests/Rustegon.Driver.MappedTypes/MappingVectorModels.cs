// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using Rustegon.Driver.Mapping;

namespace Rustegon.Driver.MappedTypes;

// The models of the cross-driver mapping vectors (drivers/conformance/mapping/vectors.yaml),
// member for member as the file declares them; the Java twins are in
// drivers/java/driver/src/test/java/io/rustegon/driver/mapping/VectorModel.java.

/// <summary>Stored by member name, verbatim: the Java twin spells its constants the same way.</summary>
public enum MapStatus
{
    /// <summary>Draft.</summary>
    Draft,

    /// <summary>Paid.</summary>
    Paid,
}

/// <summary>vectors.yaml <c>MapItem</c>.</summary>
[RustegonDocument]
public sealed class MapItem
{
    /// <summary>Name.</summary>
    public string? Name { get; set; }

    /// <summary>Id by convention, declared after <see cref="Name"/>.</summary>
    public string? Id { get; set; }

    /// <summary>int32.</summary>
    public int Count { get; set; }

    /// <summary>float32.</summary>
    public float Ratio { get; set; }

    /// <summary>decimal.</summary>
    public decimal? Price { get; set; }

    /// <summary>Tags.</summary>
    public List<string>? Tags { get; set; }

    /// <summary>Note.</summary>
    public string? Note { get; set; }

    /// <summary>Status.</summary>
    public MapStatus? Status { get; set; }

    /// <summary>Stored as <c>zip</c>.</summary>
    [RgnField("zip")]
    public string? PostalCode { get; set; }

    /// <summary>Read only.</summary>
    [RgnRev]
    public string? Rev { get; set; }

    /// <summary>Read only.</summary>
    [RgnCounter]
    public long Views { get; set; }

    /// <summary>Datetime with offset.</summary>
    public DateTimeOffset? When { get; set; }
}

/// <summary>vectors.yaml <c>MapGeo</c>.</summary>
[RustegonDocument]
public sealed class MapGeo
{
    /// <summary>Id.</summary>
    [RgnId]
    public string? Key { get; set; }

    /// <summary>Three dimensions.</summary>
    [RgnVector(3)]
    public float[]? Embedding { get; set; }

    /// <summary>[longitude, latitude].</summary>
    [RgnGeoPoint]
    public double[]? Location { get; set; }
}

/// <summary>vectors.yaml <c>MapShape</c>: polymorphic root.</summary>
[RustegonDocument]
public abstract class MapShape
{
}

/// <summary>vectors.yaml <c>MapCircle</c>.</summary>
[RustegonDocument]
[RgnDiscriminator("circle")]
public sealed class MapCircle : MapShape
{
    /// <summary>Id.</summary>
    public string? Id { get; set; }

    /// <summary>Radius.</summary>
    public double Radius { get; set; }
}

/// <summary>vectors.yaml <c>MapSquare</c> (default discriminator value).</summary>
[RustegonDocument]
[RgnDiscriminator]
public sealed class MapSquare : MapShape
{
    /// <summary>Side.</summary>
    public double Side { get; set; }
}

/// <summary>vectors.yaml <c>MapDrawing</c>.</summary>
[RustegonDocument]
public sealed class MapDrawing
{
    /// <summary>Id.</summary>
    public string? Id { get; set; }

    /// <summary>Main shape.</summary>
    public MapShape? Main { get; set; }

    /// <summary>Shapes.</summary>
    public List<MapShape>? Shapes { get; set; }
}
