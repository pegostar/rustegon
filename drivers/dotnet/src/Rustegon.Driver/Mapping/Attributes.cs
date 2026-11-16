// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;

namespace Rustegon.Driver.Mapping;

/// <summary>
/// Marks a class, record or struct as a mapped document (dotnet-driver.md §7): the
/// <c>Rustegon.Driver.Generators</c> source generator emits its <see cref="IRDocCodec{T}"/> at
/// compile time (AOT and trimming safe). Mapped members are the public instance properties with a
/// getter that are settable (<c>set</c>/<c>init</c>) or bound by a constructor parameter of the
/// same name; names are camelCase unless <see cref="RgnFieldAttribute"/> says otherwise.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = false)]
public sealed class RustegonDocumentAttribute : Attribute
{
}

/// <summary>
/// The member is the document id (<c>_id</c>, written first). Without it a property named
/// <c>Id</c>/<c>id</c> is the id. A null id is not written: the server generates an objectId.
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RgnIdAttribute : Attribute
{
}

/// <summary>Stores the member under an explicit field name instead of the camelCase name.</summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RgnFieldAttribute : Attribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="name">The field name.</param>
    public RgnFieldAttribute(string name)
    {
        Name = name;
    }

    /// <summary>The field name.</summary>
    public string Name { get; }
}

/// <summary>The member is not mapped.</summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RgnIgnoreAttribute : Attribute
{
}

/// <summary>
/// The member receives the server-maintained revision <c>_rev</c> (a string) on reads; it is never
/// written (the server rejects <c>_rev</c> in documents, data-model.md §1).
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RgnRevAttribute : Attribute
{
}

/// <summary>A <c>float[]</c> / <c>ReadOnlyMemory&lt;float&gt;</c> stored as <c>vector_f32</c> with a fixed number of dimensions (checked on writes and reads).</summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RgnVectorAttribute : Attribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="dimensions">The number of dimensions.</param>
    public RgnVectorAttribute(int dimensions)
    {
        Dimensions = dimensions;
    }

    /// <summary>The number of dimensions.</summary>
    public int Dimensions { get; }
}

/// <summary>
/// A <c>double[]</c> of <c>[longitude, latitude]</c> stored as a GeoJSON point
/// <c>{"type": "Point", "coordinates": [lng, lat]}</c>, the form of the geo functions
/// (query-language.md §9; PD-109).
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RgnGeoPointAttribute : Attribute
{
}

/// <summary>
/// A <c>long</c> filled from a document counter projection (<c>counter(name)</c>, data-model.md §10);
/// never written, since counters are not accepted as input (RGN-1004).
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RgnCounterAttribute : Attribute
{
}

/// <summary>
/// Polymorphism: a mapped type derived from another mapped type stores this value (default: the
/// simple type name) in the <c>_type</c> field (<see cref="FieldName"/>), right after <c>_id</c>; a
/// codec of the base type writes and reads every derived type of the same assembly by it (PD-110).
/// </summary>
[AttributeUsage(AttributeTargets.Class, Inherited = false)]
public sealed class RgnDiscriminatorAttribute : Attribute
{
    /// <summary>The discriminator field.</summary>
    public const string FieldName = "_type";

    /// <summary>Creates the attribute with the simple type name as the value.</summary>
    public RgnDiscriminatorAttribute()
    {
    }

    /// <summary>Creates the attribute.</summary>
    /// <param name="value">The discriminator value.</param>
    public RgnDiscriminatorAttribute(string value)
    {
        Value = value;
    }

    /// <summary>The discriminator value, or null for the simple type name.</summary>
    public string? Value { get; }
}
