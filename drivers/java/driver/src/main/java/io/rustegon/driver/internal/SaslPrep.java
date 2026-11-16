// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import java.text.Normalizer;

/**
 * SASLprep (RFC 4013, the "stored strings" profile of stringprep, RFC 3454) for SCRAM passwords
 * (RFC 5802 §5.1; PD-074: hand-written, checked against shared vectors).
 *
 * <p>Steps: map non-ASCII spaces (C.1.2) to U+0020 and the "commonly mapped to nothing"
 * characters (B.1) to nothing; normalize with NFKC ({@link Normalizer}); reject prohibited
 * output (C.1.2, C.2.1, C.2.2, C.3–C.9) and unassigned code points; apply the bidirectional
 * check (RFC 3454 §6).
 *
 * <p>Known difference from a Unicode-3.2 implementation such as the server's {@code stringprep}
 * crate: "unassigned" and the bidi classes come from the JDK's Unicode version rather than the
 * frozen table A.1/D.1/D.2. A code point assigned after Unicode 3.2 is accepted here but would
 * have been rejected by the server when the password was set, so such a password can never
 * exist on the server and the login simply fails; NFKC is stable for code points assigned in
 * 3.2. Recorded in {@code drivers/DIVERGENCES.md}.
 */
public final class SaslPrep {
    private SaslPrep() {}

    /**
     * Prepares a password.
     *
     * @param password the password
     * @return the prepared string
     * @throws IllegalArgumentException if the password contains prohibited characters, unpaired
     *     surrogates, or fails the bidi rules (the message never contains the password)
     */
    public static String prepare(CharSequence password) {
        StringBuilder mapped = new StringBuilder(password.length());
        for (int i = 0; i < password.length(); ) {
            int cp = Character.codePointAt(password, i);
            i += Character.charCount(cp);
            if (Character.isSurrogate((char) cp) && cp < 0x10000) {
                throw new IllegalArgumentException("password contains an unpaired surrogate");
            }
            if (isNonAsciiSpace(cp)) {
                mapped.append(' ');
            } else if (!isMappedToNothing(cp)) {
                mapped.appendCodePoint(cp);
            }
        }
        String normalized = Normalizer.normalize(mapped, Normalizer.Form.NFKC);
        boolean randAl = false;
        boolean l = false;
        for (int i = 0; i < normalized.length(); ) {
            int cp = normalized.codePointAt(i);
            i += Character.charCount(cp);
            if (isProhibited(cp)) {
                throw new IllegalArgumentException(
                        "password contains a character prohibited by SASLprep");
            }
            if (Character.getType(cp) == Character.UNASSIGNED) {
                throw new IllegalArgumentException(
                        "password contains an unassigned code point");
            }
            randAl |= isRandAl(cp);
            l |= Character.getDirectionality(cp) == Character.DIRECTIONALITY_LEFT_TO_RIGHT;
        }
        if (randAl) {
            // RFC 3454 §6: no LCat character, and RandALCat first and last.
            int first = normalized.codePointAt(0);
            int last = normalized.codePointBefore(normalized.length());
            if (l || !isRandAl(first) || !isRandAl(last)) {
                throw new IllegalArgumentException(
                        "password mixes right-to-left and left-to-right text");
            }
        }
        return normalized;
    }

    private static boolean isRandAl(int cp) {
        byte d = Character.getDirectionality(cp);
        return d == Character.DIRECTIONALITY_RIGHT_TO_LEFT
                || d == Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC;
    }

    /** RFC 3454 C.1.2: non-ASCII space characters. */
    static boolean isNonAsciiSpace(int cp) {
        return cp == 0x00A0 || cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200B) || cp == 0x202F
                || cp == 0x205F || cp == 0x3000;
    }

    /** RFC 3454 B.1: commonly mapped to nothing. */
    static boolean isMappedToNothing(int cp) {
        return cp == 0x00AD || cp == 0x034F || cp == 0x1806 || (cp >= 0x180B && cp <= 0x180D)
                || (cp >= 0x200B && cp <= 0x200D) || cp == 0x2060
                || (cp >= 0xFE00 && cp <= 0xFE0F) || cp == 0xFEFF;
    }

    /** RFC 4013 §2.3: tables C.1.2, C.2.1, C.2.2, C.3, C.4, C.5, C.6, C.7, C.8, C.9. */
    static boolean isProhibited(int cp) {
        return isNonAsciiSpace(cp)
                // C.2.1 ASCII control characters.
                || cp <= 0x1F || cp == 0x7F
                // C.2.2 non-ASCII control characters.
                || (cp >= 0x80 && cp <= 0x9F) || cp == 0x06DD || cp == 0x070F || cp == 0x180E
                || cp == 0x200C || cp == 0x200D || cp == 0x2028 || cp == 0x2029
                || (cp >= 0x2060 && cp <= 0x2063) || (cp >= 0x206A && cp <= 0x206F)
                || cp == 0xFEFF || (cp >= 0xFFF9 && cp <= 0xFFFC)
                || (cp >= 0x1D173 && cp <= 0x1D17A)
                // C.3 private use.
                || (cp >= 0xE000 && cp <= 0xF8FF) || (cp >= 0xF0000 && cp <= 0xFFFFD)
                || (cp >= 0x100000 && cp <= 0x10FFFD)
                // C.4 non-character code points.
                || (cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) == 0xFFFE
                // C.5 surrogate codes.
                || (cp >= 0xD800 && cp <= 0xDFFF)
                // C.6 inappropriate for plain text.
                || (cp >= 0xFFF9 && cp <= 0xFFFD)
                // C.7 inappropriate for canonical representation.
                || (cp >= 0x2FF0 && cp <= 0x2FFB)
                // C.8 change display properties or deprecated.
                || cp == 0x0340 || cp == 0x0341 || cp == 0x200E || cp == 0x200F
                || (cp >= 0x202A && cp <= 0x202E)
                // C.9 tagging characters.
                || cp == 0xE0001 || (cp >= 0xE0020 && cp <= 0xE007F);
    }
}
