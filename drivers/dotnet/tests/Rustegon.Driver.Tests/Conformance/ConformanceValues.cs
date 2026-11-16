// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Rustegon.Driver.Tests.Conformance;

/// <summary>
/// Values of the conformance files (README §5 "Values and matching"): YAML (the JSON subset read by
/// <see cref="ConformanceYaml"/>) to <see cref="RDocValue"/>, the expectation matcher with its
/// placeholders (<c>$$any</c>, <c>$$type</c>, <c>$$ref</c>) and the result normalisation of §6.
/// </summary>
internal static class ConformanceValues
{
    /// <summary>Extended-JSON wrappers (data-model.md §2): a one-key object with one of these is a value, not a document.</summary>
    private static readonly HashSet<string> Wrappers =
        ["$oid", "$date", "$int64", "$float", "$decimal", "$binary", "$uuid", "$vector", "$ts", "$minKey", "$maxKey", "$counter"];

    /// <summary>System fields removed from server documents unless the expectation names them (README §5).</summary>
    internal static readonly string[] SystemFields = ["_rev", "_createdAt", "_updatedAt"];

    internal static bool IsWrapper(Dictionary<string, object?> d) => d.Count == 1 && Wrappers.Contains(d.Keys.First());

    /// <summary>A YAML value as an RDoc value; <paramref name="resolve"/> substitutes strings (<c>${…}</c>, <c>$$ref:</c>).</summary>
    internal static RDocValue ToValue(object? yaml, Func<string, RDocValue>? resolve = null) => yaml switch
    {
        null => RDocValue.Null,
        bool b => RDocValue.FromBoolean(b),
        long l => RDocValue.FromInt64(l),
        double d => RDocValue.FromDouble(d),
        string s => resolve?.Invoke(s) ?? RDocValue.FromString(s),
        List<object?> list => RDocValue.FromArray(new RDocArray(list.Select(e => ToValue(e, resolve)))),
        Dictionary<string, object?> map when IsWrapper(map) => RDocValue.FromJson(ToJson(map)),
        Dictionary<string, object?> map => RDocValue.FromDocument(ToDocument(map, resolve)),
        _ => throw new FormatException($"unsupported YAML value {yaml.GetType().Name}"),
    };

    /// <summary>
    /// A YAML mapping as a document, field by field (so names the codec rejects, such as <c>$set</c>,
    /// are rejected by the driver operation that encodes it, not by this conversion).
    /// </summary>
    internal static RDocument ToDocument(Dictionary<string, object?> map, Func<string, RDocValue>? resolve = null)
    {
        var doc = new RDocument(map.Count);
        foreach ((string k, object? v) in map)
        {
            doc.Add(k, ToValue(v, resolve));
        }

        return doc;
    }

    /// <summary>Plain JSON text of a YAML value (YAML floats keep a fraction so they stay float64).</summary>
    internal static string ToJson(object? yaml)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(buffer))
        {
            Write(w, yaml);
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void Write(Utf8JsonWriter w, object? yaml)
    {
        switch (yaml)
        {
            case null:
                w.WriteNullValue();
                break;
            case bool b:
                w.WriteBooleanValue(b);
                break;
            case long l:
                w.WriteNumberValue(l);
                break;
            case double d:
                string text = d.ToString("R", CultureInfo.InvariantCulture);
                w.WriteRawValue(text.Contains('.', StringComparison.Ordinal) || text.Contains('E', StringComparison.Ordinal) ? text : text + ".0");
                break;
            case string s:
                w.WriteStringValue(s);
                break;
            case List<object?> list:
                w.WriteStartArray();
                foreach (object? e in list)
                {
                    Write(w, e);
                }

                w.WriteEndArray();
                break;
            case Dictionary<string, object?> map:
                w.WriteStartObject();
                foreach ((string k, object? v) in map)
                {
                    w.WritePropertyName(k);
                    Write(w, v);
                }

                w.WriteEndObject();
                break;
            default:
                throw new FormatException($"unsupported YAML value {yaml.GetType().Name}");
        }
    }

    /// <summary>The data-model §2 name of a value's type (for <c>{"$$type": …}</c>).</summary>
    internal static string TypeName(RDocValue v) => v.Type switch
    {
        RDocType.Null => "null",
        RDocType.Bool => "bool",
        RDocType.Int64 => "int64",
        RDocType.Float64 => "float64",
        RDocType.Decimal128 => "decimal128",
        RDocType.String => "string",
        RDocType.Binary => "binary",
        RDocType.DateTime => "datetime",
        RDocType.Timestamp => "timestamp",
        RDocType.ObjectId => "objectId",
        RDocType.Uuid => "uuid",
        RDocType.Array => "array",
        RDocType.Object => "object",
        RDocType.VectorF32 => "vector_f32",
        RDocType.Counter => "counter",
        RDocType.MinKey => "minKey",
        RDocType.MaxKey => "maxKey",
        _ => "missing",
    };
}

/// <summary>How an expectation is compared (README §5).</summary>
/// <param name="Subset">Expected fields must be present and match; extra fields allowed.</param>
/// <param name="Ordered">Lists of results compared in order (else as multisets).</param>
/// <param name="FieldOrder">Documents compared with their field order.</param>
internal readonly record struct MatchMode(bool Subset, bool Ordered, bool FieldOrder);

/// <summary>The expectation matcher of README §5.</summary>
internal sealed class Matcher
{
    private readonly Func<string, string> _substitute;
    private readonly Func<string, RDocValue> _resolveRef;

    internal Matcher(Func<string, string> substitute, Func<string, RDocValue> resolveRef)
    {
        _substitute = substitute;
        _resolveRef = resolveRef;
    }

    /// <summary>Null when <paramref name="actual"/> matches, else why not.</summary>
    internal string? Result(object? expected, RDocValue actual, MatchMode mode)
    {
        if (!mode.Ordered && expected is List<object?> list && actual.Type == RDocType.Array)
        {
            RDocArray items = actual.AsArray();

            // README §5: with match: subset an unordered result list may hold extra rows.
            if (mode.Subset ? items.Count < list.Count : items.Count != list.Count)
            {
                return $"expected {list.Count} rows, got {items.Count}: {actual.ToJson()}";
            }

            var left = items.ToList();
            foreach (object? e in list)
            {
                int i = left.FindIndex(a => Why(e, a, mode, "") is null);
                if (i < 0)
                {
                    return $"no row matches {ConformanceValues.ToJson(e)} in {actual.ToJson()}";
                }

                left.RemoveAt(i);
            }

            return null;
        }

        return Why(expected, actual, mode, "$");
    }

    private string? Why(object? e, RDocValue a, MatchMode mode, string at)
    {
        string Fail(string what) => $"{at}: {what} (actual {(a.IsMissing ? "missing" : a.ToJson())})";
        switch (e)
        {
            case "$$any":
                return null;
            case string s when s.StartsWith("$$ref:", StringComparison.Ordinal):
                RDocValue r = _resolveRef(s);
                return a.Equals(r) ? null : Fail($"expected {r.ToJson()}");
            case string s:
                string want = _substitute(s);
                return a.Type == RDocType.String && a.AsString() == want ? null : Fail($"expected \"{want}\"");
            case null:
                return a.IsNull ? null : Fail("expected null");
            case bool b:
                return a.Type == RDocType.Bool && a.AsBoolean() == b ? null : Fail($"expected {b}");
            case long l:
                return a.Type == RDocType.Int64 && a.AsInt64() == l ? null : Fail($"expected int64 {l}");
            case double d:
                return a.Type == RDocType.Float64 && a.Equals(RDocValue.FromDouble(d)) ? null : Fail($"expected float64 {d.ToString("R", CultureInfo.InvariantCulture)}");
            case List<object?> list:
                if (a.Type != RDocType.Array || a.AsArray().Count != list.Count)
                {
                    return Fail($"expected an array of {list.Count}");
                }

                for (int i = 0; i < list.Count; i++)
                {
                    if (Why(list[i], a.AsArray()[i], mode, $"{at}[{i}]") is { } inner)
                    {
                        return inner;
                    }
                }

                return null;
            case Dictionary<string, object?> map when map.Count == 1 && map.TryGetValue("$$type", out object? type):
                return ConformanceValues.TypeName(a) == (string?)type ? null : Fail($"expected type {type}");
            case Dictionary<string, object?> map when ConformanceValues.IsWrapper(map):
                RDocValue v = ConformanceValues.ToValue(map);
                return a.Equals(v) ? null : Fail($"expected {v.ToJson()}");
            case Dictionary<string, object?> map:
                if (a.Type != RDocType.Object)
                {
                    return Fail("expected a document");
                }

                RDocument doc = a.AsDocument();
                var names = doc.Names.Where(n => !ConformanceValues.SystemFields.Contains(n) || map.ContainsKey(n)).ToList();
                foreach ((string k, object? ev) in map)
                {
                    if (!doc.TryGetValue(k, out RDocValue av))
                    {
                        return Fail($"missing field '{k}'");
                    }

                    if (Why(ev, av, mode, $"{at}.{k}") is { } inner)
                    {
                        return inner;
                    }
                }

                if (!mode.Subset && names.Count != map.Count)
                {
                    return Fail($"unexpected fields {string.Join(", ", names.Where(n => !map.ContainsKey(n)))}");
                }

                if (mode.FieldOrder && !mode.Subset && !names.SequenceEqual(map.Keys))
                {
                    return Fail($"field order {string.Join(",", names)} instead of {string.Join(",", map.Keys)}");
                }

                return null;
            default:
                throw new FormatException($"unsupported expectation {e.GetType().Name}");
        }
    }
}

/// <summary>
/// README §6 normalisation of observed results: system fields removed, sorted object keys,
/// canonical extended JSON, and volatile values replaced by tokens in order of first appearance:
/// objectIds and datetimes that do not appear in the test file are server-generated
/// (<c>&lt;oid:n&gt;</c>, <c>&lt;datetime&gt;</c>); session and causality tokens are
/// <c>&lt;volatile&gt;</c>.
/// </summary>
internal sealed class Normalizer
{
    private readonly string _testText;
    private readonly Dictionary<string, string> _oids = new(StringComparer.Ordinal);

    internal Normalizer(string testText)
    {
        _testText = testText;
    }

    internal string Json(RDocValue v) => Normalize(v).ToJson();

    internal RDocValue Normalize(RDocValue v)
    {
        switch (v.Type)
        {
            case RDocType.ObjectId:
                string hex = v.AsObjectId().ToString();
                if (_testText.Contains(hex, StringComparison.OrdinalIgnoreCase))
                {
                    return v;
                }

                if (!_oids.TryGetValue(hex, out string? token))
                {
                    token = $"<oid:{_oids.Count + 1}>";
                    _oids[hex] = token;
                }

                return RDocValue.FromString(token);
            case RDocType.DateTime:
                string text = v.ToJson();
                string iso = text[(text.IndexOf(':', StringComparison.Ordinal) + 2)..^2];
                return _testText.Contains(iso, StringComparison.Ordinal) ? v : RDocValue.FromString("<datetime>");
            case RDocType.Array:
                var array = new RDocArray();
                foreach (RDocValue item in v.AsArray())
                {
                    array.Add(Normalize(item));
                }

                return RDocValue.FromArray(array);
            case RDocType.Object:
                var sorted = new RDocument();
                foreach (KeyValuePair<string, RDocValue> f in v.AsDocument().OrderBy(f => f.Key, StringComparer.Ordinal))
                {
                    // System fields are always removed from observations (README §6): the test's
                    // expectation checks them, and their values are volatile.
                    if (!ConformanceValues.SystemFields.Contains(f.Key))
                    {
                        sorted.Add(f.Key, Normalize(f.Value));
                    }
                }

                return RDocValue.FromDocument(sorted);
            default:
                return v;
        }
    }
}
