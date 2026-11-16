// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

namespace Rustegon.Driver;

/// <summary>JSON output mode (data-model.md §2 type-system notes). Parsers accept both.</summary>
public enum RDocJsonMode
{
    /// <summary>
    /// Plain JSON wherever lossless (int64 as a number when |v| ≤ 2^53, float64 as a number that
    /// always has a <c>.</c> or an exponent), <c>$</c> wrappers otherwise; compact, fields in
    /// stored order, minimal escaping: the same document always yields the same text.
    /// </summary>
    Canonical,

    /// <summary>As canonical, but every int64 is <c>{"$int64":"…"}</c> and every float64 <c>{"$float":"…"}</c>.</summary>
    Extended,
}
