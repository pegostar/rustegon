// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Rustegon.Driver.Internal.Json;

namespace Rustegon.Driver;

/// <summary>An ordered list of values (data-model.md §2, type 0x0C). Not thread-safe for concurrent mutation.</summary>
public sealed class RDocArray : IList<RDocValue>, IReadOnlyList<RDocValue>, IEquatable<RDocArray>
{
    private readonly List<RDocValue> _items;

    /// <summary>Creates an empty array.</summary>
    public RDocArray()
    {
        _items = [];
    }

    /// <summary>Creates an empty array with room for <paramref name="capacity"/> elements.</summary>
    /// <param name="capacity">Expected number of elements.</param>
    public RDocArray(int capacity)
    {
        _items = new List<RDocValue>(capacity);
    }

    /// <summary>Creates an array from values.</summary>
    /// <param name="items">The elements (none may be <see cref="RDocValue.Missing"/>).</param>
    /// <exception cref="ArgumentException">An element is missing.</exception>
    public RDocArray(IEnumerable<RDocValue> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        _items = [];
        foreach (RDocValue v in items)
        {
            Add(v);
        }
    }

    /// <inheritdoc cref="ICollection{T}.Count"/>
    public int Count => _items.Count;

    /// <inheritdoc/>
    public bool IsReadOnly => false;

    /// <inheritdoc cref="IList{T}.this"/>
    public RDocValue this[int index]
    {
        get => _items[index];
        set
        {
            RDocument.CheckStorable(value);
            _items[index] = value;
        }
    }

    /// <inheritdoc/>
    public void Add(RDocValue item)
    {
        RDocument.CheckStorable(item);
        _items.Add(item);
    }

    /// <inheritdoc/>
    public void Insert(int index, RDocValue item)
    {
        RDocument.CheckStorable(item);
        _items.Insert(index, item);
    }

    /// <inheritdoc/>
    public void RemoveAt(int index) => _items.RemoveAt(index);

    /// <inheritdoc/>
    public bool Remove(RDocValue item) => _items.Remove(item);

    /// <inheritdoc/>
    public void Clear() => _items.Clear();

    /// <inheritdoc/>
    public bool Contains(RDocValue item) => _items.Contains(item);

    /// <inheritdoc/>
    public int IndexOf(RDocValue item) => _items.IndexOf(item);

    /// <inheritdoc/>
    public void CopyTo(RDocValue[] array, int arrayIndex) => _items.CopyTo(array, arrayIndex);

    /// <inheritdoc/>
    public IEnumerator<RDocValue> GetEnumerator() => _items.GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>Representation equality, element by element (see <see cref="RDocValue"/>).</summary>
    /// <param name="other">The other array.</param>
    /// <returns>Whether both arrays are equal.</returns>
    public bool Equals([NotNullWhen(true)] RDocArray? other)
    {
        if (other is null || other.Count != Count)
        {
            return false;
        }

        for (int i = 0; i < _items.Count; i++)
        {
            if (!_items[i].Equals(other._items[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is RDocArray other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => _items.Count;

    /// <summary>The canonical JSON form.</summary>
    /// <returns>The text.</returns>
    public override string ToString() => RDocJsonWriter.WriteValue(RDocValue.FromArray(this), RDocJsonMode.Canonical);

    /// <summary>Appends without the missing-value check (decoder use).</summary>
    internal void AddUnchecked(RDocValue item) => _items.Add(item);
}
