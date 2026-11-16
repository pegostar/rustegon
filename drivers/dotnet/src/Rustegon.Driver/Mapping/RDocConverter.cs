// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;

namespace Rustegon.Driver.Mapping;

/// <summary>
/// Converts one CLR member type to and from an RDoc value. The generated codecs and the reflection
/// fallback build the same converters from <see cref="RDocConverters"/>, so both write identical
/// bytes for the same object (TC-DRV-NET-025).
/// </summary>
public abstract class RDocConverter
{
    private protected RDocConverter()
    {
    }

    /// <summary>Writes a boxed value (reflection fallback).</summary>
    internal abstract RDocValue WriteBoxed(object? value);

    /// <summary>Reads a value and boxes it (reflection fallback).</summary>
    internal abstract object? ReadBoxed(RDocValue value);
}

/// <summary>Converts <typeparamref name="T"/> to and from an RDoc value (dotnet-driver.md §7 type mapping).</summary>
/// <typeparam name="T">The CLR type.</typeparam>
public abstract class RDocConverter<T> : RDocConverter
{
    private protected RDocConverter()
    {
    }

    /// <summary>The RDoc value of <paramref name="value"/> (a null reference gives <see cref="RDocValue.Null"/>).</summary>
    /// <param name="value">The value.</param>
    /// <returns>The RDoc value.</returns>
    public abstract RDocValue Write(T value);

    /// <summary>The CLR value of <paramref name="value"/> (<see cref="RDocValue.Null"/> gives a null reference).</summary>
    /// <param name="value">The RDoc value.</param>
    /// <returns>The CLR value.</returns>
    /// <exception cref="InvalidCastException">The RDoc type does not map to <typeparamref name="T"/>.</exception>
    public abstract T Read(RDocValue value);

    internal sealed override RDocValue WriteBoxed(object? value) => Write((T)value!);

    internal sealed override object? ReadBoxed(RDocValue value) => Read(value);
}

/// <summary>
/// A converter made of two functions. Null handling is shared: a null reference is written as
/// <see cref="RDocValue.Null"/> and read back as null; for a value type null reaches
/// <paramref name="read"/>, whose <c>As*</c> call rejects it.
/// </summary>
internal sealed class FuncConverter<T>(Func<T, RDocValue> write, Func<RDocValue, T> read) : RDocConverter<T>
{
    public override RDocValue Write(T value) => value is null ? RDocValue.Null : write(value);

    public override T Read(RDocValue value) => value.IsNull && default(T) is null ? default! : read(value);
}

/// <summary><c>S?</c>: null ↔ <see cref="RDocValue.Null"/>, otherwise the inner converter.</summary>
internal sealed class NullableConverter<TS>(RDocConverter<TS> inner) : RDocConverter<TS?>
    where TS : struct
{
    public override RDocValue Write(TS? value) => value is { } v ? inner.Write(v) : RDocValue.Null;

    public override TS? Read(RDocValue value) => value.IsNull ? null : inner.Read(value);
}

/// <summary>A nested mapped document; its codec is resolved on first use (types may refer to each other or to themselves).</summary>
internal sealed class DocumentConverter<TD> : RDocConverter<TD>
{
    private IRDocCodec<TD>? _codec;

    private IRDocCodec<TD> Codec => _codec ??= RDocCodecRegistry.Get<TD>();

    public override RDocValue Write(TD value) => value is null ? RDocValue.Null : RDocValue.FromDocument(Codec.Encode(value));

    public override TD Read(RDocValue value) => value.IsNull && default(TD) is null ? default! : Codec.Decode(value.AsDocument());
}

/// <summary><c>Dictionary&lt;string, E&gt;</c> ↔ object (fields in the dictionary's enumeration order).</summary>
internal sealed class DictionaryConverter<TE>(RDocConverter<TE> element) : RDocConverter<Dictionary<string, TE>>
{
    public override RDocValue Write(Dictionary<string, TE> value)
    {
        if (value is null)
        {
            return RDocValue.Null;
        }

        var d = new RDocument(value.Count);
        foreach (KeyValuePair<string, TE> e in value)
        {
            d.Add(e.Key, element.Write(e.Value));
        }

        return RDocValue.FromDocument(d);
    }

    public override Dictionary<string, TE> Read(RDocValue value)
    {
        if (value.IsNull)
        {
            return null!;
        }

        RDocument d = value.AsDocument();
        var r = new Dictionary<string, TE>(d.Count, StringComparer.Ordinal);
        foreach (KeyValuePair<string, RDocValue> e in d)
        {
            r.Add(e.Key, element.Read(e.Value));
        }

        return r;
    }
}
