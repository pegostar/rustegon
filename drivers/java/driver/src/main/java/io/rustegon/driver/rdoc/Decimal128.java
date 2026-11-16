// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Objects;

/**
 * An IEEE 754-2008 decimal128 value in the binary integer decimal (BID) encoding
 * (data-model.md §2, type tag 0x05).
 *
 * <p>Like IEEE 754 (and the server), members of a cohort ({@code 1.0} and {@code 1.00}) are
 * distinct representations of the same number: {@link #equals} compares representations, and the
 * text form ({@link #toString}, the General Decimal Arithmetic "to-scientific-string") keeps
 * them apart. Negative zero exists; NaN carries no payload or sign. Values are exact: parsing and
 * {@link #of(BigDecimal)} never round, they reject what needs more than 34 significant digits.
 * The parser and the formatter are ports of the server's {@code rustegon-doc} implementation.
 */
public final class Decimal128 {
    /** Precision in decimal digits. */
    public static final int MAX_DIGITS = 34;
    /** Smallest exponent of the integer coefficient. */
    public static final int EXP_MIN = -6176;
    /** Largest exponent of the integer coefficient. */
    public static final int EXP_MAX = 6111;
    private static final int EXP_BIAS = 6176;
    private static final BigInteger MAX_COEFFICIENT = BigInteger.TEN.pow(MAX_DIGITS)
            .subtract(BigInteger.ONE);
    /** Mask of the 49 coefficient bits held in the high word (113 - 64). */
    private static final long HIGH_COEFF_MASK = (1L << 49) - 1;
    /** High word of +Infinity: combination field {@code 11110}. */
    private static final long INF_HIGH = 0x78L << 56;
    /** High word of the canonical NaN: combination field {@code 11111}, no payload. */
    private static final long NAN_HIGH = 0x7CL << 56;

    /** The canonical quiet NaN. */
    public static final Decimal128 NaN = new Decimal128(Kind.NAN, false, BigInteger.ZERO, 0);
    /** +Infinity. */
    public static final Decimal128 POSITIVE_INFINITY =
            new Decimal128(Kind.INFINITY, false, BigInteger.ZERO, 0);
    /** −Infinity. */
    public static final Decimal128 NEGATIVE_INFINITY =
            new Decimal128(Kind.INFINITY, true, BigInteger.ZERO, 0);

    private enum Kind { FINITE, INFINITY, NAN }

    private final Kind kind;
    private final boolean negative;
    private final BigInteger coefficient;
    private final int exponent;

    private Decimal128(Kind kind, boolean negative, BigInteger coefficient, int exponent) {
        this.kind = kind;
        this.negative = negative;
        this.coefficient = coefficient;
        this.exponent = exponent;
    }

    /**
     * A finite value {@code (-1)^negative × coefficient × 10^exponent}.
     *
     * @param negative the sign (negative zero exists)
     * @param coefficient 0 to 10^34 − 1
     * @param exponent {@link #EXP_MIN} to {@link #EXP_MAX}
     * @return the value
     * @throws RDocException if the coefficient or exponent is out of range
     */
    public static Decimal128 finite(boolean negative, BigInteger coefficient, int exponent) {
        if (coefficient.signum() < 0 || coefficient.compareTo(MAX_COEFFICIENT) > 0) {
            throw RDocException.invalid("decimal128 coefficient exceeds 34 digits");
        }
        if (exponent < EXP_MIN || exponent > EXP_MAX) {
            throw RDocException.invalid("decimal128 exponent out of range");
        }
        return new Decimal128(Kind.FINITE, negative, coefficient, exponent);
    }

    /**
     * The exact decimal128 form of a {@link BigDecimal} (same cohort member: {@code 12.50} keeps
     * two fraction digits).
     *
     * @param value the number
     * @return the value
     * @throws IllegalArgumentException ({@link RDocException}) if it needs more than 34
     *     significant digits or its exponent cannot be represented exactly (java-driver.md §5)
     */
    public static Decimal128 of(BigDecimal value) {
        return parse(value.toString());
    }

    /**
     * The exact decimal128 form of a {@code long} (exponent 0).
     *
     * @param value the number
     * @return the value
     */
    public static Decimal128 of(long value) {
        return new Decimal128(Kind.FINITE, value < 0, BigInteger.valueOf(value).abs(), 0);
    }

    /**
     * Parses the decimal string syntax ({@code [+-]digits[.digits][e[+-]digits]},
     * {@code Infinity}, {@code Inf}, {@code NaN}, case-insensitive). The value must be exact:
     * trailing zeros are dropped or added to bring the exponent into range, nothing is rounded.
     *
     * @param text the text
     * @return the value
     * @throws RDocException on syntax errors, more than 34 significant digits, or an exponent
     *     that cannot be brought into range exactly
     */
    public static Decimal128 parse(String text) {
        boolean neg = false;
        String body = text;
        if (!text.isEmpty() && (text.charAt(0) == '-' || text.charAt(0) == '+')) {
            neg = text.charAt(0) == '-';
            body = text.substring(1);
        }
        if (body.equalsIgnoreCase("inf") || body.equalsIgnoreCase("infinity")) {
            return neg ? NEGATIVE_INFINITY : POSITIVE_INFINITY;
        }
        if (body.equalsIgnoreCase("nan")) {
            return NaN;
        }
        StringBuilder digits = new StringBuilder();
        long fracLen = 0;
        boolean seenDigit = false;
        int i = 0;
        int n = body.length();
        while (i < n && isDigit(body.charAt(i))) {
            pushSignificant(digits, body.charAt(i));
            seenDigit = true;
            i++;
        }
        if (i < n && body.charAt(i) == '.') {
            i++;
            while (i < n && isDigit(body.charAt(i))) {
                pushSignificant(digits, body.charAt(i));
                fracLen++;
                seenDigit = true;
                i++;
            }
        }
        if (!seenDigit) {
            throw bad("no digits");
        }
        long expLit = 0;
        if (i < n && (body.charAt(i) == 'e' || body.charAt(i) == 'E')) {
            i++;
            boolean expNeg = false;
            if (i < n && (body.charAt(i) == '-' || body.charAt(i) == '+')) {
                expNeg = body.charAt(i) == '-';
                i++;
            }
            int start = i;
            while (i < n && isDigit(body.charAt(i))) {
                // Saturate: anything beyond ±10^12 is out of range whatever the digits are.
                expLit = Math.min(expLit * 10 + (body.charAt(i) - '0'), 1_000_000_000_000L);
                i++;
            }
            if (i == start) {
                throw bad("empty exponent");
            }
            if (expNeg) {
                expLit = -expLit;
            }
        }
        if (i != n) {
            throw bad("unexpected character");
        }
        return fromDigits(neg, digits, expLit - fracLen);
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static void pushSignificant(StringBuilder digits, char c) {
        if (c != '0' || !digits.isEmpty()) {
            digits.append(c);
        }
    }

    private static RDocException bad(String reason) {
        return RDocException.invalid("decimal128: " + reason);
    }

    private static Decimal128 fromDigits(boolean neg, StringBuilder digits, long exponent) {
        if (digits.isEmpty()) {
            // Zero: clamping the exponent does not change the value (IEEE 754 does the same).
            long e = Math.max(EXP_MIN, Math.min(EXP_MAX, exponent));
            return new Decimal128(Kind.FINITE, neg, BigInteger.ZERO, (int) e);
        }
        while (digits.length() > MAX_DIGITS && digits.charAt(digits.length() - 1) == '0') {
            digits.setLength(digits.length() - 1);
            exponent++;
        }
        if (digits.length() > MAX_DIGITS) {
            throw bad("more than 34 significant digits (inexact)");
        }
        while (exponent > EXP_MAX && digits.length() < MAX_DIGITS) {
            digits.append('0');
            exponent--;
        }
        if (exponent > EXP_MAX) {
            throw bad("exponent overflow");
        }
        while (exponent < EXP_MIN && digits.charAt(digits.length() - 1) == '0') {
            digits.setLength(digits.length() - 1);
            exponent++;
        }
        if (exponent < EXP_MIN) {
            throw bad("exponent underflow (inexact)");
        }
        return new Decimal128(Kind.FINITE, neg, new BigInteger(digits.toString()), (int) exponent);
    }

    /**
     * Whether this is NaN.
     *
     * @return {@code true} for NaN
     */
    public boolean isNaN() {
        return kind == Kind.NAN;
    }

    /**
     * Whether this is ±Infinity.
     *
     * @return {@code true} for an infinity
     */
    public boolean isInfinite() {
        return kind == Kind.INFINITY;
    }

    /**
     * Whether the sign bit is set (also for −0 and −Infinity; never for NaN).
     *
     * @return the sign
     */
    public boolean isNegative() {
        return negative;
    }

    /**
     * The value as a {@link BigDecimal} (the cohort member is kept; −0 becomes 0).
     *
     * @return the number
     * @throws ArithmeticException for NaN and infinities
     */
    public BigDecimal toBigDecimal() {
        if (kind != Kind.FINITE) {
            throw new ArithmeticException(this + " has no BigDecimal value");
        }
        BigInteger c = negative ? coefficient.negate() : coefficient;
        return new BigDecimal(c, -exponent);
    }

    /**
     * High 64 bits of the canonical BID encoding (small-coefficient form, NaN without payload).
     *
     * @return bits 64..127
     */
    public long highBits() {
        long sign = negative ? 1L << 63 : 0;
        return switch (kind) {
            case NAN -> NAN_HIGH;
            case INFINITY -> sign | INF_HIGH;
            case FINITE -> sign
                    | ((long) (exponent + EXP_BIAS) << 49)
                    | (coefficient.shiftRight(64).longValue() & HIGH_COEFF_MASK);
        };
    }

    /**
     * Low 64 bits of the canonical BID encoding.
     *
     * @return bits 0..63
     */
    public long lowBits() {
        return kind == Kind.FINITE ? coefficient.longValue() : 0;
    }

    /**
     * Decodes BID bits, accepting non-canonical encodings as IEEE 754 does (coefficients above
     * the precision are zero, NaN payloads and sign are dropped, infinity ignores trailing bits).
     *
     * @param high bits 64..127
     * @param low bits 0..63
     * @return the value
     */
    public static Decimal128 fromBits(long high, long low) {
        return decode(high, low, null);
    }

    /** Whether {@code (high, low)} is the canonical encoding of the value it decodes to. */
    static boolean isCanonical(long high, long low) {
        boolean[] canonical = new boolean[1];
        decode(high, low, canonical);
        return canonical[0];
    }

    private static Decimal128 decode(long high, long low, boolean[] canonicalOut) {
        boolean neg = high < 0;
        int combination = (int) ((high >>> 58) & 0x1F);
        boolean canonical;
        Decimal128 value;
        if (combination == 0x1F) {
            value = NaN;
            canonical = high == NAN_HIGH && low == 0;
        } else if (combination == 0x1E) {
            value = neg ? NEGATIVE_INFINITY : POSITIVE_INFINITY;
            canonical = (high & ((1L << 58) - 1)) == 0 && low == 0;
        } else {
            long biased;
            BigInteger c;
            if (((high >>> 61) & 0x3) == 0x3) {
                // Large-coefficient form: the implied coefficient is >= 2^113 > 10^34 - 1, so
                // the value is zero and the encoding never canonical.
                biased = (high >>> 47) & 0x3FFF;
                c = BigInteger.ZERO;
                canonical = false;
            } else {
                biased = (high >>> 49) & 0x3FFF;
                BigInteger raw = BigInteger.valueOf(high & HIGH_COEFF_MASK).shiftLeft(64)
                        .add(new BigInteger(Long.toUnsignedString(low)));
                canonical = raw.compareTo(MAX_COEFFICIENT) <= 0;
                c = canonical ? raw : BigInteger.ZERO;
            }
            // The large form can carry a biased exponent above 12287; clamp it (still zero).
            long e = Math.min(biased, EXP_MAX + EXP_BIAS) - EXP_BIAS;
            value = new Decimal128(Kind.FINITE, neg, c, (int) e);
        }
        if (canonicalOut != null) {
            canonicalOut[0] = canonical;
        }
        return value;
    }

    /**
     * The "to-scientific-string" form: plain notation when the exponent is ≤ 0 and the adjusted
     * exponent ≥ −6, scientific otherwise ({@code 12.50}, {@code 1E+3}, {@code -0},
     * {@code NaN}, {@code -Infinity}). Parsing it gives back the same representation.
     *
     * @return the text
     */
    @Override
    public String toString() {
        if (kind == Kind.NAN) {
            return "NaN";
        }
        if (kind == Kind.INFINITY) {
            return negative ? "-Infinity" : "Infinity";
        }
        StringBuilder out = new StringBuilder();
        if (negative) {
            out.append('-');
        }
        String digits = coefficient.toString();
        long n = digits.length();
        long adjusted = exponent + n - 1;
        if (exponent <= 0 && adjusted >= -6) {
            if (exponent == 0) {
                return out.append(digits).toString();
            }
            long point = n + exponent;
            if (point > 0) {
                int p = (int) point;
                out.append(digits, 0, p).append('.').append(digits, p, digits.length());
            } else {
                out.append("0.").append("0".repeat((int) -point)).append(digits);
            }
        } else {
            out.append(digits.charAt(0));
            if (digits.length() > 1) {
                out.append('.').append(digits, 1, digits.length());
            }
            out.append('E').append(adjusted < 0 ? '-' : '+').append(Math.abs(adjusted));
        }
        return out.toString();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Decimal128 d
                && kind == d.kind
                && negative == d.negative
                && exponent == d.exponent
                && coefficient.equals(d.coefficient);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, negative, coefficient, exponent);
    }
}
