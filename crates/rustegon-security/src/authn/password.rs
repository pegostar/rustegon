// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Password strength policy and random password generation (security.md §2.2, FR-SEC-003).
//!
//! security.md asks for "zxcvbn score ≥ 3, length ≥ 12". No zxcvbn port is used (PD-047: the
//! Rust ports pull large dictionaries and extra dependencies into the server for one check);
//! instead [`estimate_guesses_log10`] is a deliberately small estimator in the same spirit
//! (Wheeler, "zxcvbn: Low-Budget Password Strength Estimation", USENIX Security 2016, §3):
//! the password is split into predictable segments, each costing a fixed number of guesses,
//! and random characters, each costing the size of its character class:
//!
//! | Segment | Guesses |
//! |---|---|
//! | common password / word from [`COMMON_WORDS`] (case-insensitive, after l33t substitution `0→o 1→l 3→e 4→a 5→s 7→t @→a $→s !→i`) | 10³ |
//! | the user name (≥ 3 characters, same normalisation) | 10 |
//! | run of ≥ 3 equal characters | 10 × length |
//! | run of ≥ 3 consecutive characters of `abc…z`, `0…9` or a keyboard row (either direction) | 10² |
//! | year `19xx` / `20xx` | 10² |
//! | other character: lowercase / uppercase letter, digit, ASCII symbol, any other character | 26 / 26 / 10 / 33 / 100 |
//!
//! A password that is a repetition of a shorter unit (`abc1abc1abc1`) is scored as the unit
//! plus `log10(repetitions)`. The policy ([`check_strength`]) requires at least
//! [`MIN_LENGTH`] characters and ≥ 10^[`MIN_GUESSES_LOG10`] estimated guesses — zxcvbn's score
//! 3 lower bound is 10^8; the estimator is cruder than zxcvbn, so the bar is two orders of
//! magnitude higher.

use rustegon_sim_api::Rng;

use crate::authn::{
    SecretString,
    base62::{ALPHABET, random_string},
    error::{AuthnError, AuthnResult},
    secret,
};

/// Minimum password length in characters (security.md §2.2).
pub const MIN_LENGTH: usize = 12;
/// Maximum password length in bytes: bounds `SASLprep` and PBKDF2 input work.
pub const MAX_LENGTH: usize = 1024;
/// Minimum `log10` of the estimated guesses (module docs).
pub const MIN_GUESSES_LOG10: f64 = 10.0;
/// Length of generated passwords (security.md §2.2): 24 base62 characters ≈ 143 bits.
pub const GENERATED_LENGTH: usize = 24;

/// Common passwords and words (lowercase, ≥ 4 characters, already l33t-normalised). Short on
/// purpose: it catches the most frequent choices; the length and character-class estimate does
/// the rest.
pub const COMMON_WORDS: &[&str] = &[
    "password",
    "passwort",
    "qwerty",
    "azerty",
    "letmein",
    "welcome",
    "admin",
    "administrator",
    "root",
    "rustegon",
    "database",
    "login",
    "master",
    "dragon",
    "monkey",
    "football",
    "baseball",
    "soccer",
    "iloveyou",
    "sunshine",
    "princess",
    "shadow",
    "superman",
    "batman",
    "trustnol",
    "hello",
    "secret",
    "changeme",
    "default",
    "access",
    "computer",
    "internet",
    "server",
    "guest",
    "test",
    "user",
    "pass",
    "abc123",
    "qazwsx",
    "michael",
    "jordan",
    "charlie",
    "starwars",
    "whatever",
    "freedom",
    "flower",
    "cheese",
    "summer",
    "winter",
    "spring",
    "autumn",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "love",
    "lovely",
    "angel",
    "killer",
    "pokemon",
    "naruto",
    "matrix",
    "ninja",
    "mustang",
    "harley",
    "hunter",
    "ranger",
    "buster",
    "tigger",
    "ginger",
    "pepper",
    "cookie",
    "orange",
    "banana",
    "apple",
    "purple",
    "silver",
    "golden",
    "diamond",
    "service",
    "system",
    "company",
];

/// Sequences whose consecutive runs are predictable.
const SEQUENCES: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "qwertzuiop",
    "azertyuiop",
];

/// Guesses per predictable segment, `log10` (module docs table).
const WORD_LOG10: f64 = 3.0;
const USER_LOG10: f64 = 1.0;
const SEQUENCE_LOG10: f64 = 2.0;
const YEAR_LOG10: f64 = 2.0;

fn leet(c: char) -> char {
    match c {
        '0' => 'o',
        '1' | '!' => 'l',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '7' => 't',
        c => c,
    }
}

fn class_log10(c: char) -> f64 {
    let size: u32 = match c {
        'a'..='z' | 'A'..='Z' => 26,
        '0'..='9' => 10,
        c if c.is_ascii_graphic() || c == ' ' => 33,
        _ => 100,
    };
    f64::from(size).log10()
}

fn log10_count(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX)).log10()
}

/// Marks every occurrence of `needle` in `hay`; returns the number of new segments.
fn mark(hay: &[char], needle: &[char], covered: &mut [bool]) -> usize {
    let mut found = 0;
    if needle.is_empty() || needle.len() > hay.len() {
        return 0;
    }
    for start in 0..=hay.len() - needle.len() {
        let span = start..start + needle.len();
        if hay[span.clone()] == *needle && covered[span.clone()].iter().any(|c| !c) {
            covered[span].iter_mut().for_each(|c| *c = true);
            found += 1;
        }
    }
    found
}

/// Runs of ≥ 3 characters where each next char follows the previous one in a sequence, or
/// repeats it. Returns `log10` guesses of the segments found.
fn mark_runs(lower: &[char], covered: &mut [bool]) -> f64 {
    let step = |a: char, b: char| {
        SEQUENCES.iter().any(|s| {
            let mut it = s.chars().zip(s.chars().skip(1));
            it.any(|(x, y)| (x, y) == (a, b) || (y, x) == (a, b))
        })
    };
    let mut total = 0.0;
    let mut i = 0;
    while i < lower.len() {
        let mut j = i + 1;
        let repeat = j < lower.len() && lower[j] == lower[i];
        while j < lower.len()
            && if repeat {
                lower[j] == lower[i]
            } else {
                step(lower[j - 1], lower[j])
            }
        {
            j += 1;
        }
        if j - i >= 3 && covered[i..j].iter().any(|c| !c) {
            covered[i..j].iter_mut().for_each(|c| *c = true);
            total += if repeat {
                1.0 + log10_count(j - i)
            } else {
                SEQUENCE_LOG10
            };
            i = j;
        } else {
            i += 1;
        }
    }
    total
}

fn mark_years(chars: &[char], covered: &mut [bool]) -> usize {
    let mut found = 0;
    for start in 0..chars.len().saturating_sub(3) {
        let w = &chars[start..start + 4];
        let is_year =
            w.iter().all(char::is_ascii_digit) && matches!((w[0], w[1]), ('1', '9') | ('2', '0'));
        if is_year && covered[start..start + 4].iter().all(|c| !c) {
            covered[start..start + 4].iter_mut().for_each(|c| *c = true);
            found += 1;
        }
    }
    found
}

/// `log10` of the estimated number of guesses an attacker needs (module docs).
#[must_use]
pub fn estimate_guesses_log10(password: &str, user: &str) -> f64 {
    let chars: Vec<char> = password.chars().collect();
    // Repetition of a shorter unit: score the unit, plus the repetition count.
    let n = chars.len();
    if let Some(p) =
        (1..n).find(|&p| n.is_multiple_of(p) && chars.chunks(p).all(|c| c == &chars[..p]))
    {
        let unit: String = chars[..p].iter().collect();
        return estimate_guesses_log10(&unit, user) + log10_count(n / p);
    }
    let lower: Vec<char> = chars.iter().flat_map(|c| c.to_lowercase()).collect();
    if lower.len() != n {
        // Case folding changed the length (rare non-ASCII letters): skip the pattern checks
        // whose positions would no longer line up and score by character classes only.
        return chars.iter().map(|&c| class_log10(c)).sum();
    }
    let normalised: Vec<char> = lower.iter().map(|&c| leet(c)).collect();
    let mut covered = vec![false; n];
    let mut total = 0.0;
    let user_norm: Vec<char> = user.to_lowercase().chars().map(leet).collect();
    if user_norm.len() >= 3 {
        total += USER_LOG10 * log10_mult(mark(&normalised, &user_norm, &mut covered));
    }
    // Longest words first, so that "administrator" counts as one word, not "admin" + more.
    let mut words: Vec<&str> = COMMON_WORDS.to_vec();
    words.sort_by_key(|w| std::cmp::Reverse(w.len()));
    for word in words {
        let w: Vec<char> = word.chars().collect();
        total += WORD_LOG10 * log10_mult(mark(&normalised, &w, &mut covered));
    }
    total += YEAR_LOG10 * log10_mult(mark_years(&chars, &mut covered));
    total += mark_runs(&lower, &mut covered);
    total += chars
        .iter()
        .zip(&covered)
        .filter(|(_, c)| !**c)
        .map(|(&ch, _)| class_log10(ch))
        .sum::<f64>();
    total
}

/// Segment count as a multiplier of the per-segment `log10`.
fn log10_mult(segments: usize) -> f64 {
    f64::from(u32::try_from(segments).unwrap_or(u32::MAX))
}

/// Checks the password policy for `user`.
///
/// # Errors
/// `InvalidArgument` naming the rule (never the password): too short, too long, a control
/// character, or too predictable.
pub fn check_strength(password: &str, user: &str) -> AuthnResult<()> {
    if password.chars().count() < MIN_LENGTH {
        return Err(AuthnError::InvalidArgument(format!(
            "password must have at least {MIN_LENGTH} characters"
        )));
    }
    if password.len() > MAX_LENGTH {
        return Err(AuthnError::InvalidArgument(format!(
            "password must have at most {MAX_LENGTH} bytes"
        )));
    }
    if password.chars().any(char::is_control) {
        return Err(AuthnError::InvalidArgument(
            "password contains a control character".into(),
        ));
    }
    if estimate_guesses_log10(password, user) < MIN_GUESSES_LOG10 {
        return Err(AuthnError::InvalidArgument(
            "password is too easy to guess (common words, the user name, sequences, repeats \
             or too few random characters)"
                .into(),
        ));
    }
    Ok(())
}

/// A random [`GENERATED_LENGTH`]-character base62 password (no shell-special characters: it is
/// printed once and copied by hand). `rng` must be a CSPRNG (`OsRng` in production).
#[must_use]
pub fn generate_password(rng: &dyn Rng) -> SecretString {
    // 24 uniform base62 characters pass the policy except with negligible probability (they
    // would need ~15 characters covered by dictionary words or runs).
    secret(random_string(rng, ALPHABET, GENERATED_LENGTH))
}

#[cfg(test)]
mod tests {
    use rustegon_sim_api::OsRng;

    use super::*;

    #[test]
    fn tc_sec_003_weak_passwords_are_rejected() {
        for pw in [
            "short",
            "Password1234",
            "P@ssw0rd2026!",
            "aaaaaaaaaaaaaaaa",
            "abcdefghijklmnop",
            "qwertyuiop123456",
            "Summer2026!!",
            "aB3$aB3$aB3$",
            "alicealice12345",
            "rustegonadmin1",
            "1234567890123",
        ] {
            assert!(check_strength(pw, "alice").is_err(), "{pw} accepted");
        }
        assert!(check_strength("tab\tinside password!", "alice").is_err());
        assert!(check_strength(&"x9Q".repeat(400), "alice").is_err());
    }

    #[test]
    fn tc_sec_003_strong_passwords_are_accepted() {
        for pw in [
            "correct horse battery staple",
            "vT8#qL2!zR6m",
            "kjh7Gm2pQx9w",
            "Fjord-Quill-Mosaic-71",
            "über-gemütlich-Kaffeeklatsch",
        ] {
            assert!(check_strength(pw, "alice").is_ok(), "{pw} rejected");
        }
    }

    #[test]
    fn tc_sec_003_generated_passwords_have_24_base62_chars_and_pass() {
        for _ in 0..50 {
            let pw = generate_password(&OsRng);
            assert_eq!(pw.expose().len(), GENERATED_LENGTH);
            assert!(pw.expose().bytes().all(|c| c.is_ascii_alphanumeric()));
            check_strength(pw.expose(), "admin").unwrap();
            assert!(!format!("{pw:?}").contains(pw.expose().as_str()));
        }
    }

    #[test]
    fn estimator_orders_obvious_cases() {
        let weak = estimate_guesses_log10("password", "");
        let strong = estimate_guesses_log10("vT8#qL2!", "");
        assert!(weak < strong);
        assert!((estimate_guesses_log10("password", "") - WORD_LOG10).abs() < 1e-9);
    }
}
