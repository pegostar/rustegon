// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;

namespace Rustegon.Driver.Tests.Conformance;

/// <summary>
/// The builder DSL of the conformance suite (README §4) translated into the driver's builder calls
/// (<see cref="Driver.Filter"/>, <see cref="Driver.Update"/>, <see cref="Sort"/>, <see cref="Projection"/>,
/// <see cref="IndexKeys"/>); shared by the server runner and the AST vector checks.
/// </summary>
internal sealed class ConformanceDsl
{
    private readonly Func<string, RDocValue> _resolve;

    /// <param name="resolve">Turns a YAML string into a value (substitutions, <c>$$ref</c>).</param>
    internal ConformanceDsl(Func<string, RDocValue> resolve)
    {
        _resolve = resolve;
    }

    /// <summary>A DSL without substitutions (the AST vectors).</summary>
    internal static ConformanceDsl Plain { get; } = new(RDocValue.FromString);


    internal RDocValue Value(object? yaml) => ConformanceValues.ToValue(yaml, _resolve);

    internal RDocument Document(object? yaml) => ConformanceValues.ToDocument((Dictionary<string, object?>)yaml!, _resolve);

    /// <summary>A DSL filter (README §4) as a builder call.</summary>
    internal Filter Filter(object? yaml)
    {
        var map = (Dictionary<string, object?>)yaml!;
        if (map.Count == 0)
        {
            return Driver.Filter.Empty;
        }

        (string op, object? a) = map.Single();
        List<object?> L() => (List<object?>)a!;
        string P() => (string)L()[0]!;
        IEnumerable<RDocValue> Values() => ((List<object?>)L()[1]!).Select(Value);
        return op switch
        {
            "eq" => Driver.Filter.Eq(P(), Value(L()[1])),
            "ne" => Driver.Filter.Ne(P(), Value(L()[1])),
            "gt" => Driver.Filter.Gt(P(), Value(L()[1])),
            "gte" => Driver.Filter.Gte(P(), Value(L()[1])),
            "lt" => Driver.Filter.Lt(P(), Value(L()[1])),
            "lte" => Driver.Filter.Lte(P(), Value(L()[1])),
            "in" => Driver.Filter.In(P(), Values()),
            "nin" => Driver.Filter.Nin(P(), Values()),
            "exists" => Driver.Filter.Exists(P(), (bool)L()[1]!),
            "isNull" => Driver.Filter.IsNull((string)a!),
            "contains" => Driver.Filter.Contains(P(), Value(L()[1])),
            "containsAny" => Driver.Filter.ContainsAny(P(), Values()),
            "containsAll" => Driver.Filter.ContainsAll(P(), Values()),
            "elemMatch" => Driver.Filter.ElemMatch(P(), Filter(L()[1])),
            "like" => Driver.Filter.Like(P(), (string)L()[1]!),
            "regex" => Driver.Filter.Regex(P(), (string)L()[1]!),
            "and" => Driver.Filter.And([.. L().Select(Filter)]),
            "or" => Driver.Filter.Or([.. L().Select(Filter)]),
            "not" => Driver.Filter.Not(Filter(a)),
            "id" => Driver.Filter.Id(Value(a)),
            _ => throw new FormatException($"unknown filter operator '{op}'"),
        };
    }

    /// <summary>A DSL update (README §4): one-key objects, chained in order.</summary>
    internal Update UpdateOf(List<object?> ops)
    {
        Update? result = null;
        foreach (object? item in ops)
        {
            (string op, object? a) = ((Dictionary<string, object?>)item!).Single();
            List<object?> L() => (List<object?>)a!;
            string P() => (string)L()[0]!;
            Update next = op switch
            {
                "set" => Update.Set(P(), Value(L()[1])),
                "unset" => Update.Unset((string)a!),
                "inc" => Update.Inc(P(), Value(L()[1])),
                "mul" => Update.Mul(P(), Value(L()[1])),
                "min" => Update.Min(P(), Value(L()[1])),
                "max" => Update.Max(P(), Value(L()[1])),
                "push" => Update.Push(P(), Value(L()[1])),
                "addToSet" => Update.AddToSet(P(), Value(L()[1])),
                "pull" => Update.Pull(P(), Value(L()[1])),
                "pop" => (string)L()[1]! == "first" ? Update.PopFirst(P()) : Update.PopLast(P()),
                "rename" => Update.Rename(P(), (string)L()[1]!),
                "currentDate" => Update.CurrentDate((string)a!),
                _ => throw new FormatException($"unknown update operator '{op}'"),
            };
            result = result is null ? next : Update.Combine(result, next);
        }

        return result ?? throw new FormatException("empty update");
    }

    internal static Sort SortOf(List<object?> keys)
    {
        Sort? sort = null;
        foreach (string k in keys.Cast<string>())
        {
            bool desc = k.StartsWith('-');
            string path = desc ? k[1..] : k;
            sort = sort is null
                ? (desc ? Sort.Descending(path) : Sort.Ascending(path))
                : (desc ? sort.ThenDescending(path) : sort.ThenAscending(path));
        }

        return sort ?? throw new FormatException("empty sort");
    }

    internal static Projection ProjectionOf(Dictionary<string, object?> p) =>
        p.TryGetValue("include", out object? inc)
            ? Projection.Include([.. ((List<object?>)inc!).Cast<string>()])
            : Projection.Exclude([.. ((List<object?>)p["exclude"]!).Cast<string>()]);

    internal static IndexKeys KeysOf(List<object?> keys)
    {
        IndexKeys? result = null;
        foreach (Dictionary<string, object?> k in keys.Cast<Dictionary<string, object?>>())
        {
            string path = (string)k["path"]!;
            bool desc = k.GetValueOrDefault("descending") is true;
            result = result is null
                ? (desc ? IndexKeys.Descending(path) : IndexKeys.Ascending(path))
                : (desc ? result.ThenDescending(path) : result.ThenAscending(path));
        }

        return result ?? throw new FormatException("no keys");
    }
}
