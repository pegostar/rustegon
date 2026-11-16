// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { UNASSIGNED_RANGES } from './saslprep-tables.generated.ts';

/** A string SASLprep refuses (RFC 4013). The message never contains the input (it may be a password). */
export class SaslPrepError extends Error {}

// RFC 3454 D.1: characters with bidirectional property R or AL (Unicode 3.2).
const RANDALCAT_RANGES: readonly number[] = [
  0x05be, 0x05be, 0x05c0, 0x05c0, 0x05c3, 0x05c3, 0x05d0, 0x05ea, 0x05f0, 0x05f4, 0x061b, 0x061b, 0x061f, 0x061f,
  0x0621, 0x063a, 0x0640, 0x064a, 0x066d, 0x066f, 0x0671, 0x06d5, 0x06dd, 0x06dd, 0x06e5, 0x06e6, 0x06fa, 0x06fe,
  0x0700, 0x070d, 0x0710, 0x0710, 0x0712, 0x072c, 0x0780, 0x07a5, 0x07b1, 0x07b1, 0x200f, 0x200f, 0xfb1d, 0xfb1d,
  0xfb1f, 0xfb28, 0xfb2a, 0xfb36, 0xfb38, 0xfb3c, 0xfb3e, 0xfb3e, 0xfb40, 0xfb41, 0xfb43, 0xfb44, 0xfb46, 0xfbb1,
  0xfbd3, 0xfd3d, 0xfd50, 0xfd8f, 0xfd92, 0xfdc7, 0xfdf0, 0xfdfc, 0xfe70, 0xfe74, 0xfe76, 0xfefc,
];

const LETTER = /^\p{L}$/u;

/**
 * SASLprep (RFC 4013, the stringprep profile of RFC 3454) as the server's Rust `stringprep`
 * crate applies it to passwords: mapping, NFKC, prohibited output, bidi rules, unassigned code
 * points (stored strings: unassigned code points are refused). Same rules as the .NET and Java
 * drivers (scram/vectors.yaml, PD-074).
 */
export function saslPrep(text: string): string {
  // Fast path (as the Rust crate): printable ASCII and space are unchanged by every step.
  if (/^[\x20-\x7e]*$/.test(text)) {
    return text;
  }
  // With the `u` flag a surrogate class only matches unpaired surrogates.
  if (/[\ud800-\udfff]/u.test(text)) {
    // C.5: a lone surrogate is not a character.
    throw new SaslPrepError('the text contains a lone surrogate');
  }
  // 2.1 Mapping: non-ASCII spaces to SPACE, then "commonly mapped to nothing" removed.
  let mapped = '';
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0;
    if (isNonAsciiSpace(c)) {
      mapped += ' ';
    } else if (!isMappedToNothing(c)) {
      mapped += ch;
    }
  }
  // 2.2 Normalization: NFKC.
  const normalized = mapped.normalize('NFKC');
  // 2.3 Prohibited output, 2.5 unassigned code points.
  const cps = Array.from(normalized, (ch) => ch.codePointAt(0) ?? 0);
  if (cps.some((c) => isProhibited(c) || inRanges(UNASSIGNED_RANGES, c))) {
    throw new SaslPrepError('the text contains a prohibited or unassigned character');
  }
  // 2.4 Bidirectional characters (RFC 3454 §6): with any RandALCat character there must be no
  // LCat character, and the first and the last character must be RandALCat.
  if (cps.some((c) => inRanges(RANDALCAT_RANGES, c))) {
    const first = cps[0] ?? 0;
    const last = cps[cps.length - 1] ?? 0;
    if (cps.some(isLCat) || !inRanges(RANDALCAT_RANGES, first) || !inRanges(RANDALCAT_RANGES, last)) {
      throw new SaslPrepError('the text violates the bidirectional rules');
    }
  }
  return normalized;
}

function isNonAsciiSpace(c: number): boolean {
  return c === 0x00a0 || c === 0x1680 || (c >= 0x2000 && c <= 0x200b) || c === 0x202f || c === 0x205f || c === 0x3000;
}

function isMappedToNothing(c: number): boolean {
  return (
    c === 0x00ad ||
    c === 0x034f ||
    c === 0x1806 ||
    (c >= 0x180b && c <= 0x180d) ||
    (c >= 0x200b && c <= 0x200d) ||
    c === 0x2060 ||
    (c >= 0xfe00 && c <= 0xfe0f) ||
    c === 0xfeff
  );
}

function isProhibited(c: number): boolean {
  return (
    isNonAsciiSpace(c) || // C.1.2
    c <= 0x1f ||
    c === 0x7f || // C.2.1
    (c >= 0x80 && c <= 0x9f) ||
    c === 0x06dd ||
    c === 0x070f ||
    c === 0x180e ||
    c === 0x200c ||
    c === 0x200d ||
    c === 0x2028 ||
    c === 0x2029 ||
    (c >= 0x2060 && c <= 0x2063) ||
    (c >= 0x206a && c <= 0x206f) ||
    c === 0xfeff ||
    (c >= 0xfff9 && c <= 0xfffc) ||
    (c >= 0x1d173 && c <= 0x1d17a) || // C.2.2
    (c >= 0xe000 && c <= 0xf8ff) ||
    (c >= 0xf0000 && c <= 0xffffd) ||
    (c >= 0x100000 && c <= 0x10fffd) || // C.3
    (c >= 0xfdd0 && c <= 0xfdef) ||
    (c & 0xfffe) === 0xfffe || // C.4
    (c >= 0xd800 && c <= 0xdfff) || // C.5
    (c >= 0xfff9 && c <= 0xfffd) || // C.6
    (c >= 0x2ff0 && c <= 0x2ffb) || // C.7
    c === 0x0340 ||
    c === 0x0341 ||
    c === 0x200e ||
    c === 0x200f ||
    (c >= 0x202a && c <= 0x202e) || // C.8
    c === 0xe0001 ||
    (c >= 0xe0020 && c <= 0xe007f) // C.9
  );
}

function isLCat(c: number): boolean {
  // Right-to-left blocks are never LCat, whatever the current Unicode tables say of new letters there.
  if (
    (c >= 0x0590 && c <= 0x08ff) ||
    (c >= 0xfb1d && c <= 0xfdff) ||
    (c >= 0xfe70 && c <= 0xfeff) ||
    (c >= 0x10800 && c <= 0x10fff) ||
    (c >= 0x1e800 && c <= 0x1efff)
  ) {
    return false;
  }
  return LETTER.test(String.fromCodePoint(c));
}

/** Binary search in sorted inclusive start/end pairs. */
function inRanges(ranges: readonly number[], c: number): boolean {
  let lo = 0;
  let hi = ranges.length / 2 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (c < (ranges[2 * mid] ?? 0)) {
      hi = mid - 1;
    } else if (c > (ranges[2 * mid + 1] ?? 0)) {
      lo = mid + 1;
    } else {
      return true;
    }
  }
  return false;
}
