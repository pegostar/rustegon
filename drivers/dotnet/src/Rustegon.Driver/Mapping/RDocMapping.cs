// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.ComponentModel;
using System.Reflection;

namespace Rustegon.Driver.Mapping;

/// <summary>
/// Member-level steps shared by the generated codecs and the reflection codec, so both behave the
/// same: errors name the field, a null id is not written, absent fields are reported as absent.
/// Not meant to be called by applications.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public static class RDocMapping
{
    /// <summary>Writes a member.</summary>
    /// <typeparam name="TV">Member type.</typeparam>
    /// <param name="document">The document being built.</param>
    /// <param name="name">Field name.</param>
    /// <param name="converter">Member converter.</param>
    /// <param name="value">Member value.</param>
    public static void Write<TV>(RDocument document, string name, RDocConverter<TV> converter, TV value)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(converter);
        RDocValue v;
        try
        {
            v = converter.Write(value);
        }
        catch (Exception e) when (IsMappingError(e))
        {
            throw Wrap(name, e);
        }

        document.Add(name, v);
    }

    /// <summary>Writes the <c>_id</c> member unless it is null (the server then generates an objectId).</summary>
    /// <typeparam name="TV">Member type.</typeparam>
    /// <param name="document">The document being built.</param>
    /// <param name="converter">Member converter.</param>
    /// <param name="value">Member value.</param>
    public static void WriteId<TV>(RDocument document, RDocConverter<TV> converter, TV value)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(converter);
        RDocValue v;
        try
        {
            v = converter.Write(value);
        }
        catch (Exception e) when (IsMappingError(e))
        {
            throw Wrap("_id", e);
        }

        if (!v.IsNull)
        {
            document.Add("_id", v);
        }
    }

    /// <summary>Reads a member; an absent field gives <c>default</c> and <paramref name="present"/> false.</summary>
    /// <typeparam name="TV">Member type.</typeparam>
    /// <param name="document">The document.</param>
    /// <param name="name">Field name.</param>
    /// <param name="converter">Member converter.</param>
    /// <param name="present">Whether the field exists.</param>
    /// <returns>The member value.</returns>
    public static TV Read<TV>(RDocument document, string name, RDocConverter<TV> converter, out bool present)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(converter);
        present = document.TryGetValue(name, out RDocValue v);
        if (!present)
        {
            return default!;
        }

        try
        {
            return converter.Read(v);
        }
        catch (Exception e) when (IsMappingError(e))
        {
            throw Wrap(name, e);
        }
    }

    /// <summary>Writes the discriminator field (<see cref="RgnDiscriminatorAttribute.FieldName"/>).</summary>
    /// <param name="document">The document being built.</param>
    /// <param name="value">The discriminator value.</param>
    public static void WriteDiscriminator(RDocument document, string value)
    {
        ArgumentNullException.ThrowIfNull(document);
        document.Add(RgnDiscriminatorAttribute.FieldName, value);
    }

    /// <summary>The discriminator of a document, or null when it has none.</summary>
    /// <param name="document">The document.</param>
    /// <returns>The value or null.</returns>
    public static string? ReadDiscriminator(RDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (!document.TryGetValue(RgnDiscriminatorAttribute.FieldName, out RDocValue v) || v.IsNull)
        {
            return null;
        }

        return v.Type == RDocType.String
            ? v.AsString()
            : throw new RDocException(1001, $"Cannot map field '{RgnDiscriminatorAttribute.FieldName}': the discriminator is {v.Type}, not a string.");
    }

    /// <summary>The error for a discriminator that names no type of the hierarchy (or a missing one on an abstract type).</summary>
    /// <param name="type">The type being decoded.</param>
    /// <param name="value">The discriminator, or null.</param>
    /// <returns>The exception to throw.</returns>
    public static RDocException UnknownDiscriminator(Type type, string? value)
    {
        ArgumentNullException.ThrowIfNull(type);
        return new RDocException(
            1001,
            value is null
                ? $"Cannot map a document without '{RgnDiscriminatorAttribute.FieldName}' to the abstract type {type.Name}."
                : $"Cannot map '{RgnDiscriminatorAttribute.FieldName}' = '{value}' to {type.Name} or one of its [RgnDiscriminator] types.");
    }

    /// <summary>Writes a boxed member (reflection codec).</summary>
    internal static void WriteBoxed(RDocument document, string name, RDocConverter converter, object? value, bool isId)
    {
        RDocValue v;
        try
        {
            v = converter.WriteBoxed(value);
        }
        catch (Exception e) when (IsMappingError(e))
        {
            throw Wrap(name, e);
        }

        if (!isId || !v.IsNull)
        {
            document.Add(name, v);
        }
    }

    /// <summary>Reads a boxed member (reflection codec); absent → <paramref name="present"/> false.</summary>
    internal static object? ReadBoxed(RDocument document, string name, RDocConverter converter, out bool present)
    {
        present = document.TryGetValue(name, out RDocValue v);
        if (!present)
        {
            return null;
        }

        try
        {
            return converter.ReadBoxed(v);
        }
        catch (Exception e) when (IsMappingError(e))
        {
            throw Wrap(name, e);
        }
    }

    /// <summary>The discriminator value of a type: the attribute's, else the simple type name; null without the attribute (PD-110).</summary>
    internal static string? DiscriminatorOf(Type t) =>
        t.GetCustomAttribute<RgnDiscriminatorAttribute>() is { } a ? a.Value ?? t.Name : null;

    private static bool IsMappingError(Exception e) =>
        e is InvalidCastException or ArgumentException or OverflowException or FormatException or RDocException;

    // Nested documents wrap their own field first, so the message reads outer → inner.
    private static RDocException Wrap(string name, Exception e) => new(1001, $"Cannot map field '{name}': {e.Message}");
}
