// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using Rustegon.Driver.Internal.Builders;
using V1 = Rustegon.V1;

namespace Rustegon.Driver;

/// <summary>
/// Sort order of a find (<c>ORDER BY</c>, PD-070): <c>Sort.Descending("createdAt").ThenAscending("_id")</c>.
/// Rows with equal keys come back in <c>_id</c> order; numbers compare across types. Immutable.
/// </summary>
public sealed class Sort
{
    private readonly (string Path, bool Descending)[] _keys;

    private Sort((string, bool)[] keys)
    {
        _keys = keys;
    }

    /// <summary>Ascending on the given paths, in order.</summary>
    /// <param name="paths">Dotted field paths.</param>
    /// <returns>The sort.</returns>
    public static Sort Ascending(params string[] paths) => new(Keys(paths, false));

    /// <summary>Descending on the given paths, in order.</summary>
    /// <param name="paths">Dotted field paths.</param>
    /// <returns>The sort.</returns>
    public static Sort Descending(params string[] paths) => new(Keys(paths, true));

    /// <summary>This order, then ascending on <paramref name="path"/>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The sort.</returns>
    public Sort ThenAscending(string path) => new([.. _keys, .. Keys([path], false)]);

    /// <summary>This order, then descending on <paramref name="path"/>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The sort.</returns>
    public Sort ThenDescending(string path) => new([.. _keys, .. Keys([path], true)]);

    internal IEnumerable<V1.AstOrderItem> ToAst()
    {
        foreach ((string path, bool descending) in _keys)
        {
            yield return new V1.AstOrderItem { Expr = AstBuild.PathExpr(AstBuild.Path(path)), Descending = descending };
        }
    }

    private static (string, bool)[] Keys(string[] paths, bool descending)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (paths.Length == 0)
        {
            throw new ArgumentException("A sort needs at least one path.", nameof(paths));
        }

        var keys = new (string, bool)[paths.Length];
        for (int i = 0; i < paths.Length; i++)
        {
            _ = AstBuild.Path(paths[i]);
            keys[i] = (paths[i], descending);
        }

        return keys;
    }
}

/// <summary>
/// Projection of a find (<c>SELECT</c>, PD-070). <see cref="Include"/> returns only the listed
/// paths (each named after its last field; <c>_id</c> is not added implicitly);
/// <see cref="Exclude"/> returns the documents without the listed paths.
/// </summary>
public sealed class Projection
{
    private readonly string[] _paths;
    private readonly bool _exclude;

    private Projection(string[] paths, bool exclude)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (paths.Length == 0)
        {
            throw new ArgumentException("A projection needs at least one path.", nameof(paths));
        }

        foreach (string p in paths)
        {
            _ = AstBuild.Path(p);
        }

        _paths = [.. paths];
        _exclude = exclude;
    }

    /// <summary>Only these paths.</summary>
    /// <param name="paths">Dotted field paths.</param>
    /// <returns>The projection.</returns>
    public static Projection Include(params string[] paths) => new(paths, false);

    /// <summary>Everything except these paths.</summary>
    /// <param name="paths">Dotted field paths.</param>
    /// <returns>The projection.</returns>
    public static Projection Exclude(params string[] paths) => new(paths, true);

    internal V1.AstSelect ToAst()
    {
        var items = new V1.AstSelectItems();
        foreach (string p in _paths)
        {
            items.Items.Add(_exclude
                ? new V1.AstProjection { Exclude = new V1.AstPathProjection { Path = AstBuild.Path(p) } }
                : new V1.AstProjection { Expr = new V1.AstExprProjection { Expr = AstBuild.PathExpr(AstBuild.Path(p)) } });
        }

        return new V1.AstSelect { Items = items };
    }
}

/// <summary>Keys of an index, in order: <c>IndexKeys.Ascending("sku").ThenDescending("qty")</c>. Immutable.</summary>
public sealed class IndexKeys
{
    private IndexKeys(IReadOnlyList<IndexKey> keys)
    {
        Keys = keys;
    }

    /// <summary>The keys.</summary>
    public IReadOnlyList<IndexKey> Keys { get; }

    /// <summary>Ascending keys on the given paths.</summary>
    /// <param name="paths">Dotted field paths.</param>
    /// <returns>The keys.</returns>
    public static IndexKeys Ascending(params string[] paths) => new(Make(paths, false));

    /// <summary>Descending keys on the given paths.</summary>
    /// <param name="paths">Dotted field paths.</param>
    /// <returns>The keys.</returns>
    public static IndexKeys Descending(params string[] paths) => new(Make(paths, true));

    /// <summary>These keys, then an ascending key.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The keys.</returns>
    public IndexKeys ThenAscending(string path) => new([.. Keys, .. Make([path], false)]);

    /// <summary>These keys, then a descending key.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The keys.</returns>
    public IndexKeys ThenDescending(string path) => new([.. Keys, .. Make([path], true)]);

    private static IndexKey[] Make(string[] paths, bool descending)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (paths.Length == 0)
        {
            throw new ArgumentException("An index needs at least one key.", nameof(paths));
        }

        var keys = new IndexKey[paths.Length];
        for (int i = 0; i < paths.Length; i++)
        {
            _ = AstBuild.Path(paths[i]);
            keys[i] = new IndexKey(paths[i], descending);
        }

        return keys;
    }
}

/// <summary>One key of an index.</summary>
/// <param name="Path">Dotted field path.</param>
/// <param name="Descending">Descending order.</param>
public sealed record IndexKey(string Path, bool Descending);
