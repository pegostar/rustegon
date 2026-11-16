// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.IO.Hashing;
using System.Text;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver.Internal.Codec;

/// <summary>
/// Constants and primitives of RDoc v1 (data-model.md §4, frozen at M2 exit, DEC-018). Mirrors
/// <c>crates/rustegon-doc/src/rdoc/mod.rs</c>.
/// </summary>
internal static class RDocFormat
{
    /// <summary>First byte of every RDoc.</summary>
    internal const byte Magic = 0xD7;

    /// <summary>Format version written and read by this driver.</summary>
    internal const byte Version = 1;

    /// <summary><c>flags</c> bit 0: canonical form.</summary>
    internal const byte FlagCanonical = 0x01;

    /// <summary>Header: magic, version, flags, total_len (u32 LE).</summary>
    internal const int HeaderLength = 7;

    /// <summary>Object index entry: name_hash16 (u16 LE) + offset (u32 LE).</summary>
    internal const int IndexEntryLength = 6;

    /// <summary>Array offset-table entry (u32 LE).</summary>
    internal const int ArrayOffsetLength = 4;

    /// <summary>Encoded document limit, header included (FR-DOC-004, RGN-1002): 16 MiB.</summary>
    internal const int MaxDocumentSize = 16 * 1024 * 1024;

    /// <summary>Nesting limit: the root object is depth 1 (RGN-1003).</summary>
    internal const int MaxDepth = 100;

    /// <summary>Field-name limit in UTF-8 bytes (data-model.md §2.2).</summary>
    internal const int MaxFieldNameLength = 1024;

    /// <summary>A u64 varint has at most 10 groups of 7 bits.</summary>
    internal const int MaxVarintLength = 10;

    /// <summary>Strict UTF-8: lone surrogates and invalid bytes throw instead of being replaced.</summary>
    internal static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Error codes of codec failures (proto/errors.yaml).</summary>
    internal const int Malformed = ErrorCodes.InvalidArgument;

    /// <summary>The low 16 bits of xxh3_64(name) with seed 0.</summary>
    internal static ushort NameHash16(ReadOnlySpan<byte> utf8Name) => unchecked((ushort)XxHash3.HashToUInt64(utf8Name));

    /// <summary>zigzag(v) = (v &lt;&lt; 1) ^ (v &gt;&gt; 63): small magnitudes give short varints.</summary>
    internal static ulong ZigZag(long v) => unchecked((ulong)((v << 1) ^ (v >> 63)));

    /// <summary>Inverse of <see cref="ZigZag"/>.</summary>
    internal static long UnZigZag(ulong z) => unchecked((long)(z >> 1) ^ -(long)(z & 1));

    /// <summary>Length of a minimal unsigned LEB128 varint.</summary>
    internal static int VarintLength(ulong v)
    {
        int n = 1;
        while (v >= 0x80)
        {
            v >>= 7;
            n++;
        }

        return n;
    }

    /// <summary>Validates a field name (§2.2): 1–1024 bytes, no NUL, no leading <c>$</c> (RGN-1004).</summary>
    internal static string? FieldNameError(string name, int utf8Length)
    {
        if (name.Length == 0)
        {
            return "empty field name";
        }

        if (utf8Length > MaxFieldNameLength)
        {
            return "field name longer than 1024 bytes";
        }

        if (name.Contains('\0', StringComparison.Ordinal))
        {
            return "field name contains NUL";
        }

        return name[0] == '$' ? "field name starts with '$'" : null;
    }
}
