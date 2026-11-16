// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

namespace Rustegon.Driver;

/// <summary>
/// The Rustegon type system (data-model.md §2). The numeric value of each member is the one-byte
/// type tag of the RDoc v1 encoding.
/// </summary>
public enum RDocType : byte
{
    /// <summary>
    /// Not a stored type: the value of an absent field, and of <c>default(RDocValue)</c>. It is
    /// never encoded; writing it is an error.
    /// </summary>
    Missing = 0x00,

    /// <summary><c>null</c>.</summary>
    Null = 0x01,

    /// <summary>Boolean.</summary>
    Bool = 0x02,

    /// <summary>Signed 64-bit integer.</summary>
    Int64 = 0x03,

    /// <summary>IEEE 754 binary64 floating point.</summary>
    Float64 = 0x04,

    /// <summary>IEEE 754-2008 decimal128 (BID encoding), see <see cref="Driver.Decimal128"/>.</summary>
    Decimal128 = 0x05,

    /// <summary>UTF-8 string (NUL allowed in values).</summary>
    String = 0x06,

    /// <summary>Binary data with a subtype (0 generic, 4 UUID, 0x80–0xFF user defined).</summary>
    Binary = 0x07,

    /// <summary>UTC instant in milliseconds since the Unix epoch.</summary>
    DateTime = 0x08,

    /// <summary>Hybrid logical clock timestamp (mostly system generated), see <see cref="RDocTimestamp"/>.</summary>
    Timestamp = 0x09,

    /// <summary>12-byte object identifier, see <see cref="Driver.ObjectId"/>.</summary>
    ObjectId = 0x0A,

    /// <summary>16-byte UUID.</summary>
    Uuid = 0x0B,

    /// <summary>Ordered list of values, see <see cref="RDocArray"/>.</summary>
    Array = 0x0C,

    /// <summary>Ordered object with unique field names, see <see cref="RDocument"/>.</summary>
    Object = 0x0D,

    /// <summary>Vector of finite 32-bit floats.</summary>
    VectorF32 = 0x0E,

    /// <summary>Read-only projection of a document counter; never accepted as input.</summary>
    Counter = 0x0F,

    /// <summary>Smallest value of the total order (range bounds).</summary>
    MinKey = 0x10,

    /// <summary>Largest value of the total order (range bounds).</summary>
    MaxKey = 0x11,
}
