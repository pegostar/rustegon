// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

namespace Rustegon.Driver;

/// <summary>Binary subtypes of data-model.md §2: 0 generic, 4 UUID (16 bytes), 0x80–0xFF user defined.</summary>
public static class BinarySubtype
{
    /// <summary>Generic binary data.</summary>
    public const byte Generic = 0x00;

    /// <summary>A UUID stored as binary (exactly 16 bytes).</summary>
    public const byte Uuid = 0x04;

    /// <summary>First user-defined subtype; every subtype from here to 0xFF is user defined.</summary>
    public const byte UserDefinedMin = 0x80;

    private const int UuidLength = 16;

    /// <summary>Checks a subtype and length; returns the reason when invalid, else null.</summary>
    internal static string? Check(byte subtype, int length) => subtype switch
    {
        Generic => null,
        Uuid when length == UuidLength => null,
        Uuid => "binary subtype 4 (uuid) needs 16 bytes",
        >= UserDefinedMin => null,
        _ => "reserved binary subtype",
    };
}
