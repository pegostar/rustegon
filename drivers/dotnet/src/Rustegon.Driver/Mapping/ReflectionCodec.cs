// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;

namespace Rustegon.Driver.Mapping;

/// <summary>
/// The opt-in reflection codec (dotnet-driver.md §7, TC-DRV-NET-025). It applies the rules of the
/// source generator (<c>Rustegon.Driver.Generators/DocumentGenerator.cs</c>) at run time; any
/// change of a rule must be made in both places (the generated-vs-reflection byte-identity tests
/// catch a drift):
/// <list type="number">
/// <item>Members: public instance properties with a public getter, base types first, declaration
/// order; <see cref="RgnIgnoreAttribute"/> and indexers excluded; a property is mapped when it has a
/// public <c>set</c>/<c>init</c> or is bound by the chosen constructor.</item>
/// <item>Constructor: the public constructor with the most parameters whose parameters all match a
/// property (same name ignoring case, same type); a struct's default constructor counts as one
/// without parameters.</item>
/// <item>Names: <see cref="RgnIdAttribute"/> (else a property named <c>Id</c>/<c>id</c> without
/// <see cref="RgnFieldAttribute"/>) → <c>_id</c>, <see cref="RgnRevAttribute"/> →
/// <c>_rev</c>, <see cref="RgnFieldAttribute"/>, else camelCase (System.Text.Json's policy).</item>
/// <item>Writes: <c>_id</c> first, then the discriminator, then the members in declaration order;
/// a null id, <c>_rev</c> and counters are not written.</item>
/// <item>Reads: unknown fields are ignored; every mapped member is assigned, an absent field gives
/// <c>default</c> (PD-108).</item>
/// <item>Polymorphism: derived <see cref="RustegonDocumentAttribute"/> types with a
/// <see cref="RgnDiscriminatorAttribute"/> in the same assembly, most derived first (PD-110).</item>
/// </list>
/// </summary>
[RequiresUnreferencedCode("Reflection over mapped types.")]
[RequiresDynamicCode("Generic converters built at run time.")]
internal static class ReflectionCodec
{
    /// <summary>The codec of <paramref name="type"/> (an <c>IRDocCodec&lt;type&gt;</c>).</summary>
    internal static object Create(Type type)
    {
        try
        {
            return Activator.CreateInstance(typeof(ReflectionCodec<>).MakeGenericType(type))!;
        }
        catch (TargetInvocationException e) when (e.InnerException is not null)
        {
            ExceptionDispatchInfo.Throw(e.InnerException);
            throw;
        }
    }

    /// <summary>The converter of a member type (the generator's <c>ConverterExpression</c>).</summary>
    internal static RDocConverter For(Type type, PropertyInfo? member = null)
    {
        if (member?.GetCustomAttribute<RgnCounterAttribute>() is not null)
        {
            return type == typeof(long) ? RDocConverters.Counter
                : type == typeof(long?) ? RDocConverters.Nullable(RDocConverters.Counter)
                : throw Unsupported(member, "[RgnCounter] needs a long");
        }

        if (member?.GetCustomAttribute<RgnGeoPointAttribute>() is not null)
        {
            return type == typeof(double[]) ? RDocConverters.GeoPoint : throw Unsupported(member, "[RgnGeoPoint] needs a double[]");
        }

        if (member?.GetCustomAttribute<RgnVectorAttribute>() is { } vector)
        {
            return vector.Dimensions <= 0 ? throw Unsupported(member, "[RgnVector] needs a positive dimension count")
                : type == typeof(float[]) ? RDocConverters.FixedVector(vector.Dimensions)
                : type == typeof(ReadOnlyMemory<float>) ? RDocConverters.FixedVectorMemory(vector.Dimensions)
                : throw Unsupported(member, "[RgnVector] needs a float[] or ReadOnlyMemory<float>");
        }

        if (Nullable.GetUnderlyingType(type) is { } underlying)
        {
            return Generic(nameof(RDocConverters.Nullable), underlying, For(underlying));
        }

        if (Scalar(type) is { } scalar)
        {
            return scalar;
        }

        if (type.IsEnum)
        {
            return Generic(nameof(RDocConverters.Enum), type);
        }

        if (type.IsSZArray)
        {
            Type element = type.GetElementType()!;
            return Generic(nameof(RDocConverters.Array), element, For(element));
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>))
        {
            Type element = type.GetGenericArguments()[0];
            return Generic(nameof(RDocConverters.List), element, For(element));
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Dictionary<,>) && type.GetGenericArguments()[0] == typeof(string))
        {
            Type element = type.GetGenericArguments()[1];
            return Generic(nameof(RDocConverters.Dictionary), element, For(element));
        }

        // Any other class or struct is a nested document; the fallback maps it too, so unlike
        // the generator it needs no [RustegonDocument].
        if ((type.IsClass || (type.IsValueType && !type.IsPrimitive)) && !type.IsGenericType && type != typeof(string) && !typeof(Delegate).IsAssignableFrom(type))
        {
            return Generic(nameof(RDocConverters.Document), type);
        }

        throw new NotSupportedException($"{type} is not a mapped type (dotnet-driver.md §7){(member is null ? string.Empty : $" (member {member.DeclaringType?.Name}.{member.Name})")}.");
    }

    internal static string FieldName(PropertyInfo p) => FieldPath.Name(p);

    internal static NotSupportedException Unsupported(PropertyInfo p, string why) =>
        new($"Cannot map {p.DeclaringType?.Name}.{p.Name}: {why}.");

    private static RDocConverter? Scalar(Type t) =>
        t == typeof(bool) ? RDocConverters.Boolean
        : t == typeof(long) ? RDocConverters.Int64
        : t == typeof(int) ? RDocConverters.Int32
        : t == typeof(short) ? RDocConverters.Int16
        : t == typeof(double) ? RDocConverters.Double
        : t == typeof(float) ? RDocConverters.Single
        : t == typeof(decimal) ? RDocConverters.Decimal
        : t == typeof(Decimal128) ? RDocConverters.Decimal128
        : t == typeof(string) ? RDocConverters.String
        : t == typeof(byte[]) ? RDocConverters.Binary
        : t == typeof(ReadOnlyMemory<byte>) ? RDocConverters.BinaryMemory
        : t == typeof(DateTime) ? RDocConverters.DateTime
        : t == typeof(DateTimeOffset) ? RDocConverters.DateTimeOffset
        : t == typeof(Guid) ? RDocConverters.Guid
        : t == typeof(ObjectId) ? RDocConverters.ObjectId
        : t == typeof(RDocValue) ? RDocConverters.Value
        : t == typeof(RDocument) ? RDocConverters.RawDocument
        : t == typeof(RDocArray) ? RDocConverters.RawArray
        : t == typeof(float[]) ? RDocConverters.Vector
        : t == typeof(ReadOnlyMemory<float>) ? RDocConverters.VectorMemory
        : null;

    private static RDocConverter Generic(string factory, Type argument, params object[] args) =>
        (RDocConverter)typeof(RDocConverters).GetMethod(factory, BindingFlags.Public | BindingFlags.Static)!
            .MakeGenericMethod(argument).Invoke(null, args)!;
}

/// <summary>The reflection codec of one type (see <see cref="ReflectionCodec"/> for the rules).</summary>
[RequiresUnreferencedCode("Reflection over mapped types.")]
[RequiresDynamicCode("Generic converters built at run time.")]
internal sealed class ReflectionCodec<T> : IRDocCodec<T>
{
    private readonly Member[] _members;
    private readonly ConstructorInfo? _constructor;
    private readonly Member?[] _parameters;
    private readonly string? _discriminator;
    private readonly Derived[] _derived;
    private readonly bool _polymorphic;

    public ReflectionCodec()
    {
        Type type = typeof(T);
        List<PropertyInfo> properties = Properties(type);
        _discriminator = RDocMapping.DiscriminatorOf(type);
        _derived = [.. DerivedTypes(type)];
        _polymorphic = _discriminator is not null || _derived.Length > 0;
        if (_derived.Select(d => d.Value).Append(_discriminator).OfType<string>().GroupBy(v => v, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1) is { } dup)
        {
            throw new NotSupportedException($"Cannot map {type.Name}: the discriminator '{dup.Key}' is used twice.");
        }

        if (!type.IsAbstract)
        {
            (_constructor, ParameterInfo[] ps) = Constructor(type, properties);
            _parameters = new Member?[ps.Length];
            var members = new List<Member>();
            foreach (PropertyInfo p in properties)
            {
                int bound = Array.FindIndex(ps, q => string.Equals(q.Name, p.Name, StringComparison.OrdinalIgnoreCase));
                MethodInfo? setter = p.SetMethod?.IsPublic == true ? p.SetMethod : null;
                if (bound < 0 && setter is null)
                {
                    continue;
                }

                var m = new Member(
                    p,
                    ReflectionCodec.FieldName(p),
                    ReflectionCodec.For(p.PropertyType, p),
                    Kind(p),
                    Bound: bound >= 0);
                if (bound >= 0)
                {
                    _parameters[bound] = m;
                }

                members.Add(m);
            }

            _members = [.. members];
            Validate(type);
        }
        else
        {
            _members = [];
            _parameters = [];
        }
    }

    private enum MemberKind
    {
        Normal,
        Id,
        Rev,
        Counter,
    }

    public RDocument Encode(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        foreach (Derived d in _derived)
        {
            if (d.Type.IsInstanceOfType(value))
            {
                return d.Encode(value);
            }
        }

        var doc = new RDocument(_members.Length + 1);
        foreach (Member m in _members)
        {
            if (m.Kind == MemberKind.Id)
            {
                RDocMapping.WriteBoxed(doc, m.Name, m.Converter, m.Property.GetValue(value), isId: true);
            }
        }

        if (_discriminator is not null)
        {
            RDocMapping.WriteDiscriminator(doc, _discriminator);
        }

        foreach (Member m in _members)
        {
            if (m.Kind == MemberKind.Normal)
            {
                RDocMapping.WriteBoxed(doc, m.Name, m.Converter, m.Property.GetValue(value), isId: false);
            }
        }

        return doc;
    }

    public T Decode(RDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (_polymorphic)
        {
            string? value = RDocMapping.ReadDiscriminator(document);
            if (value is not null && value != _discriminator)
            {
                foreach (Derived d in _derived)
                {
                    if (d.Value == value)
                    {
                        return (T)d.Decode(document);
                    }
                }

                throw RDocMapping.UnknownDiscriminator(typeof(T), value);
            }
        }

        if (typeof(T).IsAbstract)
        {
            throw RDocMapping.UnknownDiscriminator(typeof(T), null);
        }

        var values = new object?[_members.Length];
        for (int i = 0; i < _members.Length; i++)
        {
            Member m = _members[i];
            values[i] = RDocMapping.ReadBoxed(document, m.Name, m.Converter, out _) ?? Default(m.Property.PropertyType);
        }

        object?[] args = [.. _parameters.Select((m, i) => m is null ? Default(_constructor!.GetParameters()[i].ParameterType) : values[Array.IndexOf(_members, m)])];
        object result = _constructor is null ? Activator.CreateInstance<T>()! : _constructor.Invoke(args);
        for (int i = 0; i < _members.Length; i++)
        {
            Member m = _members[i];
            if (!m.Bound)
            {
                m.Property.SetValue(result, values[i]);
            }
        }

        return (T)result;
    }

    private static object? Default(Type t) => t.IsValueType && Nullable.GetUnderlyingType(t) is null ? RuntimeHelpers.GetUninitializedObject(t) : null;

    private static MemberKind Kind(PropertyInfo p) =>
        FieldPath.IsId(p) ? MemberKind.Id
        : p.IsDefined(typeof(RgnRevAttribute)) ? MemberKind.Rev
        : p.IsDefined(typeof(RgnCounterAttribute)) ? MemberKind.Counter
        : MemberKind.Normal;

    /// <summary>Public instance properties with a public getter, base type first, declaration order.</summary>
    private static List<PropertyInfo> Properties(Type type)
    {
        var chain = new List<Type>();
        for (Type? t = type; t is not null && t != typeof(object) && t != typeof(ValueType); t = t.BaseType)
        {
            chain.Insert(0, t);
        }

        var order = new List<string>();
        var byName = new Dictionary<string, PropertyInfo>(StringComparer.Ordinal);
        foreach (Type level in chain)
        {
            foreach (PropertyInfo p in level.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).OrderBy(p => p.MetadataToken))
            {
                if (p.GetIndexParameters().Length > 0 || p.GetMethod is not { IsPublic: true } || p.IsDefined(typeof(RgnIgnoreAttribute)))
                {
                    continue;
                }

                if (!byName.ContainsKey(p.Name))
                {
                    order.Add(p.Name);
                }

                byName[p.Name] = p;
            }
        }

        return [.. order.Select(n => byName[n])];
    }

    private static (ConstructorInfo? Constructor, ParameterInfo[] Parameters) Constructor(Type type, List<PropertyInfo> properties)
    {
        ConstructorInfo? best = null;
        int bestCount = -1;
        foreach (ConstructorInfo c in type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).OrderBy(c => c.MetadataToken))
        {
            ParameterInfo[] ps = c.GetParameters();
            if (ps.Length > bestCount && ps.All(q => properties.Any(p => string.Equals(p.Name, q.Name, StringComparison.OrdinalIgnoreCase) && p.PropertyType == q.ParameterType)))
            {
                best = c;
                bestCount = ps.Length;
            }
        }

        if (best is not null && (bestCount > 0 || !type.IsValueType))
        {
            return (best, best.GetParameters());
        }

        return type.IsValueType
            ? (null, [])
            : throw new NotSupportedException($"Cannot map {type.Name}: no public constructor whose parameters all match properties.");
    }

    private static IEnumerable<Derived> DerivedTypes(Type type) =>
        type.Assembly.GetTypes()
            .Where(t => t != type && type.IsAssignableFrom(t) && t.IsDefined(typeof(RustegonDocumentAttribute), false) && RDocMapping.DiscriminatorOf(t) is not null)
            .OrderByDescending(Depth)
            .ThenBy(t => t.FullName, StringComparer.Ordinal)
            .Select(t => (Derived)typeof(Derived).GetMethod(nameof(Derived.For), BindingFlags.NonPublic | BindingFlags.Static)!.MakeGenericMethod(t).Invoke(null, null)!);

    private static int Depth(Type t)
    {
        int d = 0;
        for (Type? b = t.BaseType; b is not null; b = b.BaseType)
        {
            d++;
        }

        return d;
    }

    private void Validate(Type type)
    {
        string? duplicate = _members.GroupBy(m => m.Name, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1)?.Key;
        if (duplicate is not null)
        {
            throw new NotSupportedException($"Cannot map {type.Name}: two members use the field name '{duplicate}'.");
        }

        foreach (Member m in _members)
        {
            if (m.Kind == MemberKind.Rev && m.Property.PropertyType != typeof(string))
            {
                throw ReflectionCodec.Unsupported(m.Property, "[RgnRev] needs a string");
            }
        }
    }

    private sealed record Member(PropertyInfo Property, string Name, RDocConverter Converter, MemberKind Kind, bool Bound);

    private sealed record Derived(Type Type, string Value, Func<T, RDocument> Encode, Func<RDocument, object> Decode)
    {
        internal static Derived For<TD>() =>
            new(
                typeof(TD),
                RDocMapping.DiscriminatorOf(typeof(TD))!,
                v => RDocCodecRegistry.Get<TD>().Encode((TD)(object)v!),
                d => RDocCodecRegistry.Get<TD>().Decode(d)!);
    }
}
