// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq.Expressions;
using System.Reflection;
using System.Text.Json;
using Rustegon.Driver.Internal.Builders;
using Rustegon.Driver.Mapping;

namespace Rustegon.Driver;

/// <summary>
/// Dotted field paths from member expressions of a mapped type (dotnet-driver.md §7): each
/// property becomes its field name under the mapping rules (<see cref="RgnIdAttribute"/> →
/// <c>_id</c>, <see cref="RgnRevAttribute"/> → <c>_rev</c>, <see cref="RgnFieldAttribute"/>,
/// else camelCase), a constant list or array index an array position, a constant dictionary key
/// a field. The builders' generic overloads use it; it also feeds <see cref="Sort"/>,
/// <see cref="Update"/> and <see cref="Projection"/>, which take string paths.
/// </summary>
public static class FieldPath
{
    /// <summary>The path of a member expression, e.g. <c>x =&gt; x.Lines[0].Sku</c> → <c>"lines.0.sku"</c>.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="member">The member expression.</param>
    /// <returns>The dotted path.</returns>
    /// <exception cref="NotSupportedException">The expression is not a chain of mapped properties, constant indexes and constant keys.</exception>
    public static string Of<T>(Expression<Func<T, object?>> member)
    {
        ArgumentNullException.ThrowIfNull(member);
        var segments = new List<string>();
        Expression e = member.Body;
        if (e is UnaryExpression { NodeType: ExpressionType.Convert or ExpressionType.ConvertChecked } convert)
        {
            e = convert.Operand;
        }

        while (e != member.Parameters[0])
        {
            switch (e)
            {
                // Properties of framework types (string.Length, List.Count) are not stored fields.
                case MemberExpression { Member: PropertyInfo p, Expression: { } owner } when p.DeclaringType?.Namespace?.StartsWith("System", StringComparison.Ordinal) != true:
                    segments.Add(Name(p));
                    e = owner;
                    break;
                case BinaryExpression { NodeType: ExpressionType.ArrayIndex, Right: ConstantExpression { Value: int i } } index:
                    segments.Add(Position(i));
                    e = index.Left;
                    break;
                case MethodCallExpression { Method.Name: "get_Item", Object: { } owner, Arguments: [ConstantExpression { Value: int i }] }:
                    segments.Add(Position(i));
                    e = owner;
                    break;
                case MethodCallExpression { Method.Name: "get_Item", Object: { } owner, Arguments: [ConstantExpression { Value: string key }] }:
                    segments.Add(Key(key));
                    e = owner;
                    break;
                default:
                    throw new NotSupportedException($"Cannot translate '{e}' of '{member}' to a field path: use properties, constant indexes and constant keys only.");
            }
        }

        if (segments.Count == 0)
        {
            throw new NotSupportedException($"'{member}' names no field.");
        }

        segments.Reverse();
        string path = string.Join('.', segments);
        _ = AstBuild.Path(path);
        return path;
    }

    /// <summary>The field name of a mapped property (shared with the reflection codec).</summary>
    internal static string Name(PropertyInfo p) =>
        p.IsDefined(typeof(RgnIgnoreAttribute)) ? throw new NotSupportedException($"{p.DeclaringType?.Name}.{p.Name} is [RgnIgnore]: it is not stored.")
        : IsId(p) ? "_id"
        : p.IsDefined(typeof(RgnRevAttribute)) ? "_rev"
        : p.GetCustomAttribute<RgnFieldAttribute>()?.Name ?? JsonNamingPolicy.CamelCase.ConvertName(p.Name);

    /// <summary>The id member: <see cref="RgnIdAttribute"/>, else a property named <c>Id</c>/<c>id</c> without <see cref="RgnFieldAttribute"/> (PD-108).</summary>
    internal static bool IsId(PropertyInfo p) =>
        p.IsDefined(typeof(RgnIdAttribute)) || (p.Name is "Id" or "id" && !p.IsDefined(typeof(RgnFieldAttribute)));

    private static string Position(int i) =>
        i >= 0 ? i.ToString(CultureInfo.InvariantCulture) : throw new NotSupportedException("A negative index names no element.");

    private static string Key(string key) =>
        key.Length == 0 || key.Contains('.', StringComparison.Ordinal) || IsAllDigits(key)
            ? throw new NotSupportedException($"The dictionary key '{key}' cannot be a path segment (empty, dotted or all digits, which would name an array position).")
            : key;

    private static bool IsAllDigits(string s)
    {
        foreach (char c in s)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return true;
    }
}
