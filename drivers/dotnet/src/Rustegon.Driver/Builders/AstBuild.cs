// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using Google.Protobuf;
using Google.Protobuf.Collections;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Internal.Builders;

/// <summary>
/// Collects the parameters of one request while builders are compiled to the structured AST
/// (PD-070, conformance README §4 rule 1): every user value becomes a named parameter, filter
/// values <c>f0, f1, …</c> and update values <c>u0, u1, …</c>, numbered in depth-first,
/// left-to-right order of the builder tree. Values never become AST literals, so no value can
/// change the statement's structure (no injection, and the server's canonical-AST check holds).
/// </summary>
internal sealed class ParamSink
{
    private int _filters;
    private int _updates;

    internal MapField<string, V1.Value> Params { get; } = new();

    internal V1.AstExpr Filter(RDocValue value) => Add("f" + (_filters++).ToString(CultureInfo.InvariantCulture), value);

    internal V1.AstExpr Update(RDocValue value) => Add("u" + (_updates++).ToString(CultureInfo.InvariantCulture), value);

    private V1.AstExpr Add(string name, RDocValue value)
    {
        Params[name] = AstBuild.Value(value);
        return new V1.AstExpr { Param = new V1.AstParam { Name = name } };
    }
}

/// <summary>Small AST helpers shared by the builders and the data-plane requests.</summary>
internal static class AstBuild
{
    /// <summary>The wire form of a value (<c>Value.rdoc_value</c>: type tag + payload, protocol.md §3).</summary>
    internal static V1.Value Value(RDocValue value)
    {
        if (value.IsMissing)
        {
            throw new ArgumentException("A missing value cannot be sent; use RDocValue.Null.", nameof(value));
        }

        return new V1.Value { RdocValue = ByteString.CopyFrom(RDocWriter.ValueToBytes(value)) };
    }

    /// <summary>The value of a <c>Value</c> message (RDocValue.Missing for an absent one).</summary>
    internal static RDocValue FromValue(V1.Value? value) =>
        value is null ? RDocValue.Missing : RDocReader.ReadValue(value.RdocValue.Span);

    /// <summary>
    /// A dotted path as AST segments (conformance README §4): field names become
    /// <c>AstSegment.field</c>, never text, and an all-digit segment after the first is an array
    /// position. Field names that contain dots cannot be addressed by a dotted path.
    /// </summary>
    internal static V1.AstPath Path(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var result = new V1.AstPath();
        string[] parts = path.Split('.');
        for (int i = 0; i < parts.Length; i++)
        {
            string p = parts[i];
            if (p.Length == 0)
            {
                throw new ArgumentException($"The path '{path}' has an empty segment.", nameof(path));
            }

            if (i > 0 && IsDigits(p) && uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out uint position))
            {
                result.Segments.Add(new V1.AstSegment { Position = position });
            }
            else
            {
                result.Segments.Add(new V1.AstSegment { Field = p });
            }
        }

        return result;
    }

    /// <summary>The dotted text of an AST path (the inverse of <see cref="Path"/> for field and position segments).</summary>
    internal static string PathText(V1.AstPath path)
    {
        var parts = new List<string>(path.Segments.Count);
        foreach (V1.AstSegment s in path.Segments)
        {
            parts.Add(s.SegmentCase == V1.AstSegment.SegmentOneofCase.Position
                ? s.Position.ToString(CultureInfo.InvariantCulture)
                : s.Field);
        }

        return string.Join('.', parts);
    }

    internal static V1.AstExpr PathExpr(V1.AstPath path) => new() { Path = new V1.AstPathExpr { Path = path } };

    internal static V1.AstExpr Int(long value) => new() { Literal = new V1.AstLiteral { IntValue = value } };

    internal static V1.AstOptionItem AllowFullScanWrite() => new()
    {
        Name = "allow_full_scan_write",
        Value = new V1.AstExpr { Literal = new V1.AstLiteral { BoolValue = true } },
    };

    private static bool IsDigits(string s)
    {
        foreach (char c in s)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }
}
