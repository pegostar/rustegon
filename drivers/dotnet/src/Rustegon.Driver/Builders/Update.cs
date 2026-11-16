// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using Rustegon.Driver.Internal.Builders;
using V1 = Rustegon.V1;

namespace Rustegon.Driver;

/// <summary>
/// Update operators (dotnet-driver.md §4, PD-070), applied all-or-nothing in order. They compile
/// to <c>AstUpdateOp</c>s with every value as a parameter (<c>u0, u1, …</c>); the exact output is
/// pinned by <c>drivers/conformance/ast/updates.json</c>. Start with a static method and chain
/// further operators: <c>Update.Set("status", "shipped").Inc("version", 1)</c>. Two operators on
/// overlapping paths are rejected by the server (RGN-1001). Immutable.
/// </summary>
public sealed class Update
{
    private readonly Func<ParamSink, V1.AstUpdateOp>[] _ops;

    private Update(Func<ParamSink, V1.AstUpdateOp>[] ops)
    {
        _ops = ops;
    }

    /// <summary>Number of operators.</summary>
    public int Count => _ops.Length;

    /// <summary><c>SET path = value</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">New value.</param>
    /// <returns>The update.</returns>
    public static Update Set(string path, RDocValue value) => One(MakeSet, path, value);

    /// <summary><c>UNSET path</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The update.</returns>
    public static Update Unset(string path)
    {
        V1.AstPath p = AstBuild.Path(path);
        return new([_ => new V1.AstUpdateOp { Unset = new V1.AstUnsetStage { Paths = { p.Clone() } } }]);
    }

    /// <summary><c>INC path BY amount</c> (numeric; a non-numeric field fails with RGN-1011).</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="amount">Increment.</param>
    /// <returns>The update.</returns>
    public static Update Inc(string path, RDocValue amount) => One(MakeInc, path, amount);

    /// <summary><c>MUL path BY factor</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="factor">Factor.</param>
    /// <returns>The update.</returns>
    public static Update Mul(string path, RDocValue factor) => One(MakeMul, path, factor);

    /// <summary><c>MIN path WITH value</c>: keeps the smaller value.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Candidate.</param>
    /// <returns>The update.</returns>
    public static Update Min(string path, RDocValue value) => One(MakeMin, path, value);

    /// <summary><c>MAX path WITH value</c>: keeps the larger value.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Candidate.</param>
    /// <returns>The update.</returns>
    public static Update Max(string path, RDocValue value) => One(MakeMax, path, value);

    /// <summary><c>PUSH path VALUE value</c>: appends to an array.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Element.</param>
    /// <returns>The update.</returns>
    public static Update Push(string path, RDocValue value) => One(MakePush, path, value);

    /// <summary><c>ADD TO SET path VALUE value</c>: appends unless an equal element exists.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Element.</param>
    /// <returns>The update.</returns>
    public static Update AddToSet(string path, RDocValue value) => One(MakeAddToSet, path, value);

    /// <summary>Removes the array elements equal to <paramref name="value"/> (<c>PULL p WHERE &lt;last field of p&gt; = value</c>).</summary>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Element to remove.</param>
    /// <returns>The update.</returns>
    public static Update Pull(string path, RDocValue value) => One(MakePull, path, value);

    /// <summary><c>POP path FIRST</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The update.</returns>
    public static Update PopFirst(string path) => Pop(path, V1.AstPopEnd.First);

    /// <summary><c>POP path LAST</c>.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The update.</returns>
    public static Update PopLast(string path) => Pop(path, V1.AstPopEnd.Last);

    /// <summary><c>RENAME from TO to</c>.</summary>
    /// <param name="from">Current dotted path.</param>
    /// <param name="to">New dotted path.</param>
    /// <returns>The update.</returns>
    public static Update Rename(string from, string to)
    {
        V1.AstPath f = AstBuild.Path(from);
        V1.AstPath t = AstBuild.Path(to);
        return new([_ => new V1.AstUpdateOp { Rename = new V1.AstRenameOp { From = f.Clone(), To = t.Clone() } }]);
    }

    /// <summary><c>CURRENT DATE path</c>: the server's commit time as a datetime.</summary>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The update.</returns>
    public static Update CurrentDate(string path)
    {
        V1.AstPath p = AstBuild.Path(path);
        return new([_ => new V1.AstUpdateOp { CurrentDate = new V1.AstPathOnly { Path = p.Clone() } }]);
    }

    /// <summary>The operators of several updates, in order.</summary>
    /// <param name="updates">The updates.</param>
    /// <returns>The combined update.</returns>
    public static Update Combine(params Update[] updates)
    {
        ArgumentNullException.ThrowIfNull(updates);
        var ops = new List<Func<ParamSink, V1.AstUpdateOp>>();
        foreach (Update u in updates)
        {
            ArgumentNullException.ThrowIfNull(u, nameof(updates));
            ops.AddRange(u._ops);
        }

        return new([.. ops]);
    }

    /// <summary><c>REPLACE WITH document</c>: the sole operator of a replacement statement (driver internal).</summary>
    internal static Update Replace(RDocument document)
    {
        RDocValue v = RDocValue.FromDocument(document);
        return new([s => new V1.AstUpdateOp { Replace = new V1.AstReplaceOp { Value = s.Update(v) } }]);
    }

    /// <summary>The operators; parameters go to <paramref name="sink"/>.</summary>
    internal IEnumerable<V1.AstUpdateOp> ToAst(ParamSink sink)
    {
        if (_ops.Length == 0)
        {
            throw new ArgumentException("An update needs at least one operator.");
        }

        var result = new List<V1.AstUpdateOp>(_ops.Length);
        foreach (Func<ParamSink, V1.AstUpdateOp> op in _ops)
        {
            result.Add(op(sink));
        }

        return result;
    }

    internal Update Then(Update next) => Combine(this, next);

    private static Update One(Func<V1.AstPath, V1.AstExpr, V1.AstUpdateOp> make, string path, RDocValue value)
    {
        V1.AstPath p = AstBuild.Path(path);
        if (value.IsMissing)
        {
            throw new ArgumentException("An update value cannot be missing; use RDocValue.Null or Unset.", nameof(value));
        }

        return new([s => make(p.Clone(), s.Update(value))]);
    }

    private static Update Pop(string path, V1.AstPopEnd end)
    {
        V1.AstPath p = AstBuild.Path(path);
        return new([_ => new V1.AstUpdateOp { Pop = new V1.AstPopOp { Path = p.Clone(), End = end } }]);
    }

    private static V1.AstUpdateOp MakeSet(V1.AstPath p, V1.AstExpr v) =>
        new() { Set = new V1.AstSetStage { Items = { new V1.AstSetItem { Path = p, Value = v } } } };

    private static V1.AstUpdateOp MakeInc(V1.AstPath p, V1.AstExpr v) => new() { Inc = new V1.AstPathBy { Path = p, By = v } };

    private static V1.AstUpdateOp MakeMul(V1.AstPath p, V1.AstExpr v) => new() { Mul = new V1.AstPathBy { Path = p, By = v } };

    private static V1.AstUpdateOp MakeMin(V1.AstPath p, V1.AstExpr v) => new() { Min = new V1.AstPathValue { Path = p, Value = v } };

    private static V1.AstUpdateOp MakeMax(V1.AstPath p, V1.AstExpr v) => new() { Max = new V1.AstPathValue { Path = p, Value = v } };

    private static V1.AstUpdateOp MakePush(V1.AstPath p, V1.AstExpr v) => new() { Push = new V1.AstPushOp { Path = p, Value = v } };

    private static V1.AstUpdateOp MakeAddToSet(V1.AstPath p, V1.AstExpr v) => new() { AddToSet = new V1.AstPathValue { Path = p, Value = v } };

    private static V1.AstUpdateOp MakePull(V1.AstPath p, V1.AstExpr v)
    {
        // PULL p WHERE <last field of p> = v: inside the predicate the element is addressed by the
        // array's own field name (conformance README §4, ast/updates.json `pull_nested_path`).
        string last = p.Segments[^1].Field;
        var element = new V1.AstPath { Segments = { new V1.AstSegment { Field = last } } };
        return new()
        {
            Pull = new V1.AstPullOp
            {
                Path = p,
                Where = new V1.AstExpr { Binary = new V1.AstBinary { Op = V1.AstBinaryOp.Eq, Left = AstBuild.PathExpr(element), Right = v } },
            },
        };
    }
}

/// <summary>Chaining of <see cref="Update"/> operators: <c>Update.Set("a", 1).Inc("b", 2)</c>.</summary>
public static class UpdateChain
{
    /// <summary>Appends <see cref="Update.Set(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">New value.</param>
    /// <returns>The longer update.</returns>
    public static Update Set(this Update update, string path, RDocValue value) => Chain(update).Then(Update.Set(path, value));

    /// <summary>Appends <see cref="Update.Unset(string)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The longer update.</returns>
    public static Update Unset(this Update update, string path) => Chain(update).Then(Update.Unset(path));

    /// <summary>Appends <see cref="Update.Inc(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="amount">Increment.</param>
    /// <returns>The longer update.</returns>
    public static Update Inc(this Update update, string path, RDocValue amount) => Chain(update).Then(Update.Inc(path, amount));

    /// <summary>Appends <see cref="Update.Mul(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="factor">Factor.</param>
    /// <returns>The longer update.</returns>
    public static Update Mul(this Update update, string path, RDocValue factor) => Chain(update).Then(Update.Mul(path, factor));

    /// <summary>Appends <see cref="Update.Min(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Candidate.</param>
    /// <returns>The longer update.</returns>
    public static Update Min(this Update update, string path, RDocValue value) => Chain(update).Then(Update.Min(path, value));

    /// <summary>Appends <see cref="Update.Max(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Candidate.</param>
    /// <returns>The longer update.</returns>
    public static Update Max(this Update update, string path, RDocValue value) => Chain(update).Then(Update.Max(path, value));

    /// <summary>Appends <see cref="Update.Push(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Element.</param>
    /// <returns>The longer update.</returns>
    public static Update Push(this Update update, string path, RDocValue value) => Chain(update).Then(Update.Push(path, value));

    /// <summary>Appends <see cref="Update.AddToSet(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Element.</param>
    /// <returns>The longer update.</returns>
    public static Update AddToSet(this Update update, string path, RDocValue value) => Chain(update).Then(Update.AddToSet(path, value));

    /// <summary>Appends <see cref="Update.Pull(string, RDocValue)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <param name="value">Element to remove.</param>
    /// <returns>The longer update.</returns>
    public static Update Pull(this Update update, string path, RDocValue value) => Chain(update).Then(Update.Pull(path, value));

    /// <summary>Appends <see cref="Update.PopFirst(string)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The longer update.</returns>
    public static Update PopFirst(this Update update, string path) => Chain(update).Then(Update.PopFirst(path));

    /// <summary>Appends <see cref="Update.PopLast(string)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The longer update.</returns>
    public static Update PopLast(this Update update, string path) => Chain(update).Then(Update.PopLast(path));

    /// <summary>Appends <see cref="Update.Rename(string, string)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="from">Current dotted path.</param>
    /// <param name="to">New dotted path.</param>
    /// <returns>The longer update.</returns>
    public static Update Rename(this Update update, string from, string to) => Chain(update).Then(Update.Rename(from, to));

    /// <summary>Appends <see cref="Update.CurrentDate(string)"/>.</summary>
    /// <param name="update">The update so far.</param>
    /// <param name="path">Dotted field path.</param>
    /// <returns>The longer update.</returns>
    public static Update CurrentDate(this Update update, string path) => Chain(update).Then(Update.CurrentDate(path));

    private static Update Chain(Update update) => update ?? throw new ArgumentNullException(nameof(update));
}
