// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Globalization;
using System.Text;

namespace Rustegon.Driver.Internal.Auth;

/// <summary>
/// SASLprep (RFC 4013: the stringprep profile of RFC 3454) for SCRAM passwords (RFC 5802 §5.1),
/// hand-written (PD-074) and mirroring the Rust <c>stringprep</c> crate the server uses: map
/// (C.1.2 → space, then drop B.1), NFKC, reject prohibited output (C.1.2, C.2.1, C.2.2, C.3–C.9),
/// check bidirectional text, reject unassigned code points (A.1, Unicode 3.2).
/// </summary>
/// <remarks>
/// Only the mapping and NFKC change the derived key; the checks merely reject early what the server
/// could never have stored. Differences that remain are therefore harmless in one direction only,
/// and were chosen that way: .NET normalizes with its current Unicode version (identical to 3.2
/// NFKC except for a handful of corrigenda), and the bidi rule uses RFC 3454 D.1 for RandALCat and
/// an approximation of LCat (letters outside the right-to-left blocks), so it can only accept a
/// string the server rejects — which then fails as a normal wrong-password login — and never
/// rejects one the server accepts. Recorded in drivers/DIVERGENCES.md.
/// </remarks>
internal static partial class SaslPrep
{
    // RFC 3454 D.1: characters with bidirectional property R or AL (Unicode 3.2).
    private static readonly int[] RandALCatRanges =
    [
        0x05BE, 0x05BE, 0x05C0, 0x05C0, 0x05C3, 0x05C3, 0x05D0, 0x05EA, 0x05F0, 0x05F4,
        0x061B, 0x061B, 0x061F, 0x061F, 0x0621, 0x063A, 0x0640, 0x064A, 0x066D, 0x066F,
        0x0671, 0x06D5, 0x06DD, 0x06DD, 0x06E5, 0x06E6, 0x06FA, 0x06FE, 0x0700, 0x070D,
        0x0710, 0x0710, 0x0712, 0x072C, 0x0780, 0x07A5, 0x07B1, 0x07B1, 0x200F, 0x200F,
        0xFB1D, 0xFB1D, 0xFB1F, 0xFB28, 0xFB2A, 0xFB36, 0xFB38, 0xFB3C, 0xFB3E, 0xFB3E,
        0xFB40, 0xFB41, 0xFB43, 0xFB44, 0xFB46, 0xFBB1, 0xFBD3, 0xFD3D, 0xFD50, 0xFD8F,
        0xFD92, 0xFDC7, 0xFDF0, 0xFDFC, 0xFE70, 0xFE74, 0xFE76, 0xFEFC,
    ];

    /// <summary>Applies SASLprep.</summary>
    /// <param name="s">The password.</param>
    /// <param name="prepared">The prepared string.</param>
    /// <returns>Whether <paramref name="s"/> is valid SASLprep input.</returns>
    internal static bool TryPrepare(string s, out string prepared)
    {
        prepared = s;
        // Fast path (as the Rust crate): printable ASCII and space are unchanged by every step.
        bool ascii = true;
        foreach (char c in s)
        {
            if (c >= 0x80 || c < 0x20 || c == 0x7F)
            {
                ascii = false;
                break;
            }
        }

        if (ascii)
        {
            return true;
        }

        // 2.1 Mapping: non-ASCII spaces to SPACE, then "commonly mapped to nothing" removed.
        var mapped = new StringBuilder(s.Length);
        if (HasLoneSurrogate(s))
        {
            // C.5: a lone surrogate is not a character (and EnumerateRunes would hide it as U+FFFD).
            return false;
        }

        foreach (Rune r in s.EnumerateRunes())
        {
            if (IsNonAsciiSpace(r.Value))
            {
                mapped.Append(' ');
            }
            else if (!IsMappedToNothing(r.Value))
            {
                mapped.Append(r.ToString());
            }
        }

        // 2.2 Normalization: NFKC.
        string normalized;
        try
        {
            normalized = mapped.ToString().Normalize(NormalizationForm.FormKC);
        }
        catch (ArgumentException)
        {
            return false;
        }

        // 2.3 Prohibited output, 2.5 unassigned code points.
        foreach (Rune r in normalized.EnumerateRunes())
        {
            if (IsProhibited(r.Value) || IsUnassigned(r.Value))
            {
                return false;
            }
        }

        // 2.4 Bidirectional characters (RFC 3454 §6).
        if (IsProhibitedBidi(normalized))
        {
            return false;
        }

        prepared = normalized;
        return true;
    }

    private static bool HasLoneSurrogate(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(s[i]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsNonAsciiSpace(int c) =>
        c is 0x00A0 or 0x1680 or (>= 0x2000 and <= 0x200B) or 0x202F or 0x205F or 0x3000;

    private static bool IsMappedToNothing(int c) =>
        c is 0x00AD or 0x034F or 0x1806 or (>= 0x180B and <= 0x180D) or (>= 0x200B and <= 0x200D)
            or 0x2060 or (>= 0xFE00 and <= 0xFE0F) or 0xFEFF;

    private static bool IsProhibited(int c) =>
        IsNonAsciiSpace(c)                                                   // C.1.2
        || c is <= 0x1F or 0x7F                                              // C.2.1
        || c is (>= 0x80 and <= 0x9F) or 0x06DD or 0x070F or 0x180E or 0x200C or 0x200D or 0x2028
            or 0x2029 or (>= 0x2060 and <= 0x2063) or (>= 0x206A and <= 0x206F) or 0xFEFF
            or (>= 0xFFF9 and <= 0xFFFC) or (>= 0x1D173 and <= 0x1D17A)      // C.2.2
        || c is (>= 0xE000 and <= 0xF8FF) or (>= 0xF0000 and <= 0xFFFFD) or (>= 0x100000 and <= 0x10FFFD) // C.3
        || c is (>= 0xFDD0 and <= 0xFDEF) || (c & 0xFFFE) == 0xFFFE           // C.4
        || c is >= 0xD800 and <= 0xDFFF                                      // C.5
        || c is >= 0xFFF9 and <= 0xFFFD                                      // C.6
        || c is >= 0x2FF0 and <= 0x2FFB                                      // C.7
        || c is 0x0340 or 0x0341 or 0x200E or 0x200F or (>= 0x202A and <= 0x202E) or (>= 0x206A and <= 0x206F) // C.8
        || c is 0xE0001 or (>= 0xE0020 and <= 0xE007F);                      // C.9

    private static bool IsUnassigned(int c) => InRanges(UnassignedRanges, c);

    private static bool IsRandALCat(int c) => InRanges(RandALCatRanges, c);

    /// <summary>LCat approximation: letters outside the right-to-left blocks (see the class remarks).</summary>
    private static bool IsLCat(int c)
    {
        if (c is (>= 0x0590 and <= 0x08FF) or (>= 0xFB1D and <= 0xFDFF) or (>= 0xFE70 and <= 0xFEFF)
            or (>= 0x10800 and <= 0x10FFF) or (>= 0x1E800 and <= 0x1EFFF))
        {
            return false;
        }

        UnicodeCategory cat = CharUnicodeInfo.GetUnicodeCategory(c);
        return cat is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter
            or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter;
    }

    private static bool IsProhibitedBidi(string s)
    {
        bool anyRandAL = false;
        bool anyL = false;
        int first = -1;
        int last = -1;
        foreach (Rune r in s.EnumerateRunes())
        {
            if (first < 0)
            {
                first = r.Value;
            }

            last = r.Value;
            anyRandAL |= IsRandALCat(r.Value);
            anyL |= IsLCat(r.Value);
        }

        // RFC 3454 §6: with any RandALCat character there must be no LCat character, and the
        // first and the last character must be RandALCat.
        return anyRandAL && (anyL || !IsRandALCat(first) || !IsRandALCat(last));
    }

    /// <summary>Binary search over inclusive [start, end] pairs.</summary>
    private static bool InRanges(int[] ranges, int c)
    {
        int lo = 0;
        int hi = (ranges.Length / 2) - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (c < ranges[2 * mid])
            {
                hi = mid - 1;
            }
            else if (c > ranges[(2 * mid) + 1])
            {
                lo = mid + 1;
            }
            else
            {
                return true;
            }
        }

        return false;
    }
}
