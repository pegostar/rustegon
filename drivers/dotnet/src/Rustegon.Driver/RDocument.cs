// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Rustegon.Driver.Internal.Json;

namespace Rustegon.Driver;

/// <summary>
/// A schemaless document: an ordered dictionary of unique field names to <see cref="RDocValue"/>s
/// (data-model.md §2, type 0x0D). Field order is part of the document (insertion order is kept and
/// encoded), so <c>{"x":1,"y":2}</c> and <c>{"y":2,"x":1}</c> are different documents.
/// </summary>
/// <remarks>
/// Not thread-safe for concurrent mutation. Field names are validated when the document is encoded
/// or parsed (1–1024 bytes of UTF-8, no NUL, no leading <c>$</c>; RGN-1004), not on every
/// assignment.
/// </remarks>
public sealed class RDocument : IEnumerable<KeyValuePair<string, RDocValue>>, IEquatable<RDocument>
{
    private readonly List<KeyValuePair<string, RDocValue>> _fields;
    private readonly Dictionary<string, int> _index;

    /// <summary>Creates an empty document.</summary>
    public RDocument()
        : this(0)
    {
    }

    /// <summary>Creates an empty document with room for <paramref name="capacity"/> fields.</summary>
    /// <param name="capacity">Expected number of fields.</param>
    public RDocument(int capacity)
    {
        _fields = new List<KeyValuePair<string, RDocValue>>(capacity);
        _index = new Dictionary<string, int>(capacity, StringComparer.Ordinal);
    }

    /// <summary>Number of fields.</summary>
    public int Count => _fields.Count;

    /// <summary>Field names in document order.</summary>
    public IEnumerable<string> Names
    {
        get
        {
            foreach (KeyValuePair<string, RDocValue> f in _fields)
            {
                yield return f.Key;
            }
        }
    }

    /// <summary>
    /// Gets a field (<see cref="RDocValue.Missing"/> when absent) or sets it (replacing in place, or
    /// appending a new field at the end).
    /// </summary>
    /// <param name="name">The field name.</param>
    public RDocValue this[string name]
    {
        get => TryGetValue(name, out RDocValue v) ? v : RDocValue.Missing;
        set
        {
            ArgumentNullException.ThrowIfNull(name);
            CheckStorable(value);
            if (_index.TryGetValue(name, out int i))
            {
                _fields[i] = new KeyValuePair<string, RDocValue>(name, value);
            }
            else
            {
                _index.Add(name, _fields.Count);
                _fields.Add(new KeyValuePair<string, RDocValue>(name, value));
            }
        }
    }

    /// <summary>The field at a position (document order).</summary>
    /// <param name="index">Zero-based position.</param>
    /// <returns>Name and value.</returns>
    public KeyValuePair<string, RDocValue> GetFieldAt(int index) => _fields[index];

    /// <summary>Appends a field.</summary>
    /// <param name="name">A name not yet present.</param>
    /// <param name="value">Any value except <see cref="RDocValue.Missing"/>.</param>
    /// <exception cref="ArgumentException">The name exists already, or the value is missing.</exception>
    public void Add(string name, RDocValue value)
    {
        if (!TryAdd(name, value))
        {
            throw new ArgumentException($"The document already has a field named '{name}'.", nameof(name));
        }
    }

    /// <summary>Appends a field unless the name exists already.</summary>
    /// <param name="name">The field name.</param>
    /// <param name="value">Any value except <see cref="RDocValue.Missing"/>.</param>
    /// <returns>Whether the field was added.</returns>
    /// <exception cref="ArgumentException">The value is missing.</exception>
    public bool TryAdd(string name, RDocValue value)
    {
        ArgumentNullException.ThrowIfNull(name);
        CheckStorable(value);
        if (!_index.TryAdd(name, _fields.Count))
        {
            return false;
        }

        _fields.Add(new KeyValuePair<string, RDocValue>(name, value));
        return true;
    }

    /// <summary>Looks up a field.</summary>
    /// <param name="name">The field name.</param>
    /// <param name="value">The value, or <see cref="RDocValue.Missing"/>.</param>
    /// <returns>Whether the field exists.</returns>
    public bool TryGetValue(string name, out RDocValue value)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (_index.TryGetValue(name, out int i))
        {
            value = _fields[i].Value;
            return true;
        }

        value = default;
        return false;
    }

    /// <summary>Whether a field exists.</summary>
    /// <param name="name">The field name.</param>
    /// <returns>Whether the document has it.</returns>
    public bool ContainsKey(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return _index.ContainsKey(name);
    }

    /// <summary>Removes a field, keeping the order of the others.</summary>
    /// <param name="name">The field name.</param>
    /// <returns>Whether the field existed.</returns>
    public bool Remove(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!_index.Remove(name, out int i))
        {
            return false;
        }

        _fields.RemoveAt(i);
        for (int j = i; j < _fields.Count; j++)
        {
            _index[_fields[j].Key] = j;
        }

        return true;
    }

    /// <summary>Removes every field.</summary>
    public void Clear()
    {
        _fields.Clear();
        _index.Clear();
    }

    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<string, RDocValue>> GetEnumerator() => _fields.GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>Decodes an RDoc v1 document (full validation; data-model.md §4).</summary>
    /// <param name="rdoc">The bytes.</param>
    /// <returns>The document.</returns>
    /// <exception cref="RDocException">Malformed or non-canonical input (with the canonical flag), limits exceeded.</exception>
    public static RDocument FromBytes(ReadOnlySpan<byte> rdoc) => RDocReader.ReadDocument(rdoc);

    /// <summary>Encodes the document as canonical RDoc v1.</summary>
    /// <returns>The bytes.</returns>
    /// <exception cref="RDocException">An invalid field name, a counter or missing value, limits exceeded.</exception>
    public byte[] ToBytes() => RDocWriter.ToBytes(this);

    /// <summary>Encodes the document as canonical RDoc v1 into a buffer writer.</summary>
    /// <param name="output">Destination.</param>
    /// <returns>Number of bytes written.</returns>
    /// <exception cref="RDocException">As <see cref="ToBytes"/>.</exception>
    public int WriteTo(IBufferWriter<byte> output) => RDocWriter.Write(this, output);

    /// <summary>Parses a JSON object in canonical or extended form (data-model.md §2).</summary>
    /// <param name="json">The JSON text.</param>
    /// <returns>The document.</returns>
    /// <exception cref="RDocException">Invalid JSON, not an object, or an invalid value.</exception>
    public static RDocument FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return RDocJsonReader.ParseDocument(json);
    }

    /// <summary>Parses a <see cref="JsonElement"/> holding an object (its raw text is parsed, so duplicate names are still rejected).</summary>
    /// <param name="element">The element.</param>
    /// <returns>The document.</returns>
    /// <exception cref="RDocException">Not an object or an invalid value.</exception>
    public static RDocument FromJson(JsonElement element) => RDocJsonReader.ParseDocument(element.GetRawText());

    /// <summary>Serializes the document as JSON.</summary>
    /// <param name="mode">Canonical (default) or extended output.</param>
    /// <returns>Compact JSON with fields in document order.</returns>
    public string ToJson(RDocJsonMode mode = RDocJsonMode.Canonical) => RDocJsonWriter.WriteDocument(this, mode);

    /// <summary>The canonical JSON form.</summary>
    /// <returns>The text.</returns>
    public override string ToString() => ToJson();

    /// <summary>Representation equality: same names, same order, equal values (see <see cref="RDocValue"/>).</summary>
    /// <param name="other">The other document.</param>
    /// <returns>Whether both documents are equal.</returns>
    public bool Equals([NotNullWhen(true)] RDocument? other)
    {
        if (other is null || other.Count != Count)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        for (int i = 0; i < _fields.Count; i++)
        {
            KeyValuePair<string, RDocValue> a = _fields[i];
            KeyValuePair<string, RDocValue> b = other._fields[i];
            if (!string.Equals(a.Key, b.Key, StringComparison.Ordinal) || !a.Value.Equals(b.Value))
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is RDocument other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = default(HashCode);
        foreach (KeyValuePair<string, RDocValue> f in _fields)
        {
            h.Add(f.Key, StringComparer.Ordinal);
        }

        return h.ToHashCode();
    }

    /// <summary>Appends a field without the public checks (decoder use: names unique and validated).</summary>
    internal void AddUnchecked(string name, RDocValue value)
    {
        _index.Add(name, _fields.Count);
        _fields.Add(new KeyValuePair<string, RDocValue>(name, value));
    }

    internal static void CheckStorable(RDocValue value)
    {
        if (value.IsMissing)
        {
            throw new ArgumentException("A missing value cannot be stored; use RDocValue.Null.", nameof(value));
        }
    }
}
