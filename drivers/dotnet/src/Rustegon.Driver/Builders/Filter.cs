// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using Rustegon.Driver.Internal.Builders;
using V1 = Rustegon.V1;

namespace Rustegon.Driver;

/// <summary>
/// A query filter (dotnet-driver.md §4, PD-070). Filters compile to the structured AST of
/// <c>query_ast.proto</c>, never to RGQL text: field paths become AST segments and every value a
/// named parameter, so values cannot inject syntax. The exact output is pinned by
/// <c>drivers/conformance/ast/filters.json</c>. Comparison semantics are RGQL's
/// (query-language.md §4.3): a missing or null field never satisfies a comparison, arrays match
/// element-wise, numbers compare across int64, float64 and decimal128.
/// </summary>
/// <remarks>
/// Paths are dotted strings (<c>"maker.city"</c>); an all-digit segment after the first is an array
/// position (<c>"items.0.sku"</c>). The generic overloads take member expressions of a mapped type
/// instead (<c>Filter.Eq&lt;Order&gt;(x =&gt; x.Maker.City, "Turin")</c>), translated by
/// <see cref="FieldPath.Of{T}"/> to the same path and AST. Filters are immutable.
/// </remarks>
public sealed class Filter
{
    private readonly Kind _kind;
    private readonly string? _path;
    private readonly V1.AstBinaryOp _op;
    private readonly RDocValue _value;
    private readonly bool _flag;
    private readonly Filter[] _children;

    private Filter(Kind kind, string? path = null, V1.AstBinaryOp op = V1.AstBinaryOp.Unspecified, RDocValue value = default, bool flag = false, Filter[]? children = null)
    {
        _kind = kind;
        _path = path;
        _op = op;
        _value = value;
        _flag = flag;
        _children = children ?? [];
    }

    private enum Kind
    {
        Empty,
        Id,
        Binary,
        Exists,
        IsNull,
        ElemMatch,
        And,
        Or,
        Not,
    }

    /// <summary>Matches every document.</summary>
    public static Filter Empty { get; } = new(Kind.Empty);

    /// <summary>Whether this is <see cref="Empty"/> (writes with it need <c>allow_full_scan_write</c>, which the driver adds).</summary>
    internal bool IsEmpty => _kind == Kind.Empty;

    /// <summary>The id when the filter is exactly <see cref="Id"/> (routes single-document writes to <c>DocumentService</c>).</summary>
    internal RDocValue? IdValue => _kind == Kind.Id ? _value : (RDocValue?)null;

    /// <summary><c>_id = id</c>.</summary>
    /// <param name="id">The document id.</param>
    /// <returns>The filter.</returns>
    public static Filter Id(RDocValue id) => new(Kind.Id, "_id", V1.AstBinaryOp.Eq, Checked(id));

    /// <summary><c>path = value</c> (also element-wise on arrays).</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Eq(string path, RDocValue value) => Binary(path, V1.AstBinaryOp.Eq, value);

    /// <summary><c>path != value</c> (a missing or null field does not match).</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Ne(string path, RDocValue value) => Binary(path, V1.AstBinaryOp.Ne, value);

    /// <summary><c>path &gt; value</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Gt(string path, RDocValue value) => Binary(path, V1.AstBinaryOp.Gt, value);

    /// <summary><c>path &gt;= value</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Gte(string path, RDocValue value) => Binary(path, V1.AstBinaryOp.Ge, value);

    /// <summary><c>path &lt; value</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Lt(string path, RDocValue value) => Binary(path, V1.AstBinaryOp.Lt, value);

    /// <summary><c>path &lt;= value</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Lte(string path, RDocValue value) => Binary(path, V1.AstBinaryOp.Le, value);

    /// <summary><c>path IN values</c> (one array parameter; an empty list matches nothing).</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="values">The candidate values.</param>
    /// <returns>The filter.</returns>
    public static Filter In(string path, IEnumerable<RDocValue> values) => Binary(path, V1.AstBinaryOp.In, List(values));

    /// <summary><c>path NOT IN values</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="values">The excluded values.</param>
    /// <returns>The filter.</returns>
    public static Filter Nin(string path, IEnumerable<RDocValue> values) => Binary(path, V1.AstBinaryOp.NotIn, List(values));

    /// <summary><c>path IS NOT MISSING</c> (exists = true; a null field exists) or <c>path IS MISSING</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="exists">Whether the field must be present.</param>
    /// <returns>The filter.</returns>
    public static Filter Exists(string path, bool exists = true) => new(Kind.Exists, CheckedPath(path), flag: exists);

    /// <summary><c>path IS NULL</c>: the field is null or missing.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The filter.</returns>
    public static Filter IsNull(string path) => new(Kind.IsNull, CheckedPath(path));

    /// <summary><c>path CONTAINS value</c>: the array holds an element equal to the value.</summary>
    /// <param name="path">Dotted field path of an array.</param>
    /// <param name="value">The element.</param>
    /// <returns>The filter.</returns>
    public static Filter Contains(string path, RDocValue value) => Binary(path, V1.AstBinaryOp.Contains, value);

    /// <summary><c>path CONTAINS ANY values</c>.</summary>
    /// <param name="path">Dotted field path of an array.</param>
    /// <param name="values">The candidate elements.</param>
    /// <returns>The filter.</returns>
    public static Filter ContainsAny(string path, IEnumerable<RDocValue> values) => Binary(path, V1.AstBinaryOp.ContainsAny, List(values));

    /// <summary><c>path CONTAINS ALL values</c>.</summary>
    /// <param name="path">Dotted field path of an array.</param>
    /// <param name="values">The required elements.</param>
    /// <returns>The filter.</returns>
    public static Filter ContainsAll(string path, IEnumerable<RDocValue> values) => Binary(path, V1.AstBinaryOp.ContainsAll, List(values));

    /// <summary><c>ELEM MATCH (path, filter)</c>: one array element satisfies the whole filter (paths relative to the element).</summary>
    /// <param name="path">Dotted field path of an array.</param>
    /// <param name="filter">Filter on the element.</param>
    /// <returns>The filter.</returns>
    public static Filter ElemMatch(string path, Filter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        if (filter.IsEmpty)
        {
            throw new ArgumentException("ElemMatch needs a non-empty element filter.", nameof(filter));
        }

        return new(Kind.ElemMatch, CheckedPath(path), children: [filter]);
    }

    /// <summary><c>path LIKE pattern</c> (whole string; <c>%</c> any run, <c>_</c> one character).</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="pattern">The pattern.</param>
    /// <returns>The filter.</returns>
    public static Filter Like(string path, string pattern) => Binary(path, V1.AstBinaryOp.Like, RDocValue.FromString(pattern ?? throw new ArgumentNullException(nameof(pattern))));

    /// <summary><c>path MATCHES regex</c> (unanchored, Rust regex syntax).</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="regex">The regular expression.</param>
    /// <returns>The filter.</returns>
    public static Filter Regex(string path, string regex) => Binary(path, V1.AstBinaryOp.Matches, RDocValue.FromString(regex ?? throw new ArgumentNullException(nameof(regex))));

    /// <summary>All filters hold (nested <c>And</c> are flattened; empty filters are ignored).</summary>
    /// <param name="filters">The filters.</param>
    /// <returns>The filter.</returns>
    public static Filter And(params Filter[] filters) => Nary(Kind.And, filters);

    /// <summary>At least one filter holds (nested <c>Or</c> are flattened).</summary>
    /// <param name="filters">The filters.</param>
    /// <returns>The filter.</returns>
    public static Filter Or(params Filter[] filters) => Nary(Kind.Or, filters);

    /// <summary>The filter does not hold.</summary>
    /// <param name="filter">The filter.</param>
    /// <returns>The filter.</returns>
    public static Filter Not(Filter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        if (filter.IsEmpty)
        {
            throw new ArgumentException("Not of the empty filter matches nothing; use a real condition.", nameof(filter));
        }

        return new(Kind.Not, children: [filter]);
    }

    /// <summary><see cref="And"/>.</summary>
    /// <param name="left">Left filter.</param>
    /// <param name="right">Right filter.</param>
    /// <returns>The conjunction.</returns>
    public static Filter operator &(Filter left, Filter right) => And(left, right);

    /// <summary><see cref="Or"/>.</summary>
    /// <param name="left">Left filter.</param>
    /// <param name="right">Right filter.</param>
    /// <returns>The disjunction.</returns>
    public static Filter operator |(Filter left, Filter right) => Or(left, right);

    /// <summary><see cref="Not"/>.</summary>
    /// <param name="filter">The filter.</param>
    /// <returns>The negation.</returns>
    public static Filter operator !(Filter filter) => Not(filter);

    /// <summary>The <c>WHERE</c> expression, or null for <see cref="Empty"/>; parameters go to <paramref name="sink"/>.</summary>
    internal V1.AstExpr? ToAst(ParamSink sink)
    {
        switch (_kind)
        {
            case Kind.Empty:
                return null;
            case Kind.Id:
            case Kind.Binary:
                return new V1.AstExpr
                {
                    Binary = new V1.AstBinary
                    {
                        Op = _op,
                        Left = AstBuild.PathExpr(AstBuild.Path(_path!)),
                        Right = sink.Filter(_value),
                    },
                };
            case Kind.Exists:
                // exists = true is `IS NOT MISSING`: the canonical AST of a negated IS test.
                return new V1.AstExpr { Is = new V1.AstIs { Expr = AstBuild.PathExpr(AstBuild.Path(_path!)), Test = V1.AstIsTest.Missing, Negated = _flag } };
            case Kind.IsNull:
                return new V1.AstExpr { Is = new V1.AstIs { Expr = AstBuild.PathExpr(AstBuild.Path(_path!)), Test = V1.AstIsTest.Null } };
            case Kind.ElemMatch:
                return new V1.AstExpr { ElemMatch = new V1.AstElemMatch { Path = AstBuild.Path(_path!), Predicate = _children[0].ToAst(sink) } };
            case Kind.Not:
                return new V1.AstExpr { Not = new V1.AstUnary { Expr = _children[0].ToAst(sink) } };
            default:
                var nary = new V1.AstNary();
                foreach (Filter c in _children)
                {
                    nary.Args.Add(c.ToAst(sink));
                }

                return _kind == Kind.And ? new V1.AstExpr { And = nary } : new V1.AstExpr { Or = nary };
        }
    }

    /// <summary><c>field = value</c> on a member of a mapped type (<see cref="FieldPath.Of{T}"/>).</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member, e.g. <c>x =&gt; x.Maker.City</c>.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Eq<T>(Expression<Func<T, object?>> field, RDocValue value) => Eq(FieldPath.Of(field), value);

    /// <summary><c>field != value</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Ne<T>(Expression<Func<T, object?>> field, RDocValue value) => Ne(FieldPath.Of(field), value);

    /// <summary><c>field &gt; value</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Gt<T>(Expression<Func<T, object?>> field, RDocValue value) => Gt(FieldPath.Of(field), value);

    /// <summary><c>field &gt;= value</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Gte<T>(Expression<Func<T, object?>> field, RDocValue value) => Gte(FieldPath.Of(field), value);

    /// <summary><c>field &lt; value</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Lt<T>(Expression<Func<T, object?>> field, RDocValue value) => Lt(FieldPath.Of(field), value);

    /// <summary><c>field &lt;= value</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="value">The value.</param>
    /// <returns>The filter.</returns>
    public static Filter Lte<T>(Expression<Func<T, object?>> field, RDocValue value) => Lte(FieldPath.Of(field), value);

    /// <summary><c>field IN values</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="values">The candidate values.</param>
    /// <returns>The filter.</returns>
    public static Filter In<T>(Expression<Func<T, object?>> field, IEnumerable<RDocValue> values) => In(FieldPath.Of(field), values);

    /// <summary><c>field NOT IN values</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="values">The excluded values.</param>
    /// <returns>The filter.</returns>
    public static Filter Nin<T>(Expression<Func<T, object?>> field, IEnumerable<RDocValue> values) => Nin(FieldPath.Of(field), values);

    /// <summary><c>field IS [NOT] MISSING</c> on a member of a mapped type.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="field">The member.</param>
    /// <param name="exists">Whether the field must be present.</param>
    /// <returns>The filter.</returns>
    public static Filter Exists<T>(Expression<Func<T, object?>> field, bool exists = true) => Exists(FieldPath.Of(field), exists);

    private static Filter Binary(string path, V1.AstBinaryOp op, RDocValue value) => new(Kind.Binary, CheckedPath(path), op, Checked(value));

    private static Filter Nary(Kind kind, Filter[] filters)
    {
        ArgumentNullException.ThrowIfNull(filters);
        var flat = new List<Filter>(filters.Length);
        foreach (Filter f in filters)
        {
            ArgumentNullException.ThrowIfNull(f, nameof(filters));
            if (f.IsEmpty)
            {
                continue;
            }

            // The server accepts only canonical ASTs (query_ast.proto header): an `and` inside an
            // `and` would print and re-parse as one flat list, so it must be flat already (PD-070
            // rule 2; otherwise RGN-1010).
            if (f._kind == kind)
            {
                flat.AddRange(f._children);
            }
            else
            {
                flat.Add(f);
            }
        }

        return flat.Count switch
        {
            0 => Empty,
            1 => flat[0],
            _ => new Filter(kind, children: [.. flat]),
        };
    }

    private static string CheckedPath(string path)
    {
        _ = AstBuild.Path(path);
        return path;
    }

    private static RDocValue Checked(RDocValue value) =>
        value.IsMissing ? throw new ArgumentException("A filter value cannot be missing; use RDocValue.Null.", nameof(value)) : value;

    private static RDocValue List(IEnumerable<RDocValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        return RDocValue.FromArray(new RDocArray(values));
    }
}
