// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Browser credentials of the REST API: the `rgn_session` cookie and its CSRF protection
//! (security.md §2.1; PD-052).
//!
//! The GUI holds its session token in an `HttpOnly; Secure; SameSite=Strict` cookie
//! (`rgn_session`, set by the login endpoint of the authentication layer; no `Secure` on a
//! plain-text listener, ADR-034). Browsers attach
//! cookies to cross-site requests in some cases (`SameSite` is defence in depth, not a
//! guarantee: same-site subdomains, older browsers), so every state-changing request
//! authenticated by the cookie must also carry the `X-RGN-CSRF` header.
//!
//! The CSRF token is a *signed* double-submit token: it is derived from the session token
//! ([`csrf_token`], BLAKE3 in derive-key mode), handed to the GUI in the readable `rgn_csrf`
//! cookie (and/or the login response) and echoed in `X-RGN-CSRF`. Binding it to the session
//! means an attacker who can plant cookies for the domain (cookie tossing from a sibling
//! subdomain) still cannot forge a matching pair, which a plain random double-submit cookie
//! would allow; and since the derivation is one-way, a leaked CSRF token does not reveal the
//! session token.

use http::{HeaderMap, Method};
use rustegon_common::{Error, ErrorCode};
use subtle::ConstantTimeEq;

use super::context::single;
use crate::services::invalid_header;

/// Session cookie set by the GUI login (`HttpOnly; Secure; SameSite=Strict; Path=/`).
pub const SESSION_COOKIE: &str = "rgn_session";
/// Cookie carrying [`csrf_token`] for the GUI's scripts (`Secure; SameSite=Strict; Path=/`,
/// deliberately not `HttpOnly`).
pub const CSRF_COOKIE: &str = "rgn_csrf";
/// Request header that must carry [`csrf_token`] on state-changing cookie-authenticated
/// requests.
pub const CSRF_HEADER: &str = "x-rgn-csrf";

/// BLAKE3 derive-key context of [`csrf_token`]; changing it invalidates every issued token.
const CSRF_CONTEXT: &str = "rustegon 2026-11 csrf token v1";
/// Longest accepted session cookie value. Session tokens are 43 base64url characters (256
/// bits); the margin leaves room for a future token format without accepting unbounded input.
const MAX_SESSION_COOKIE_LEN: usize = 512;

/// The CSRF token belonging to `session_token`: 64 lowercase hex digits.
#[must_use]
pub fn csrf_token(session_token: &str) -> String {
    let key = blake3::derive_key(CSRF_CONTEXT, session_token.as_bytes());
    key.iter().fold(String::with_capacity(64), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Methods that must not change state (RFC 9110 §9.2.1) and therefore need no CSRF token.
#[must_use]
pub fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The `rgn_session` cookie value, if present.
///
/// # Errors
/// RGN-1001 (detail `header` = `cookie`) when the cookie appears more than once (a planted
/// duplicate must not be resolved by picking one) or its value is not a base64url token. The
/// value is never echoed.
pub(crate) fn session_cookie(headers: &HeaderMap) -> Result<Option<String>, Error> {
    let mut found: Option<&str> = None;
    // HTTP/2 clients may split cookies over several `cookie` fields (RFC 9113 §8.2.3).
    let values = headers.get_all(http::header::COOKIE);
    for value in &values {
        let text = value
            .to_str()
            .map_err(|_| invalid_header("cookie", "value is not visible ASCII"))?;
        for pair in text.split(';') {
            let Some((name, value)) = pair.trim_matches(' ').split_once('=') else {
                continue;
            };
            if name != SESSION_COOKIE {
                continue;
            }
            if found.is_some() {
                return Err(invalid_header("cookie", "`rgn_session` cookie repeated"));
            }
            found = Some(value);
        }
    }
    let Some(token) = found else {
        return Ok(None);
    };
    if token.is_empty()
        || token.len() > MAX_SESSION_COOKIE_LEN
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid_header("cookie", "malformed `rgn_session` cookie"));
    }
    Ok(Some(token.to_owned()))
}

/// Checks the CSRF token of a request authenticated by the session cookie.
///
/// # Errors
/// RGN-4002 `PermissionDenied` (detail `reason` = `csrf`) when a state-changing request lacks
/// `X-RGN-CSRF` or carries a token that does not belong to the session; RGN-1001 when the
/// header is repeated or not ASCII.
pub(crate) fn check_csrf(
    method: &Method,
    headers: &HeaderMap,
    session_token: &str,
) -> Result<(), Error> {
    if is_safe_method(method) {
        return Ok(());
    }
    let denied = |message: &str| {
        Error::new(ErrorCode::PermissionDenied, message).with_detail("reason", "csrf")
    };
    let presented = single(headers, CSRF_HEADER)?.ok_or_else(|| denied("missing CSRF token"))?;
    let expected = csrf_token(session_token);
    // Constant time: the comparison must not leak how many leading characters were right.
    if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(denied("invalid CSRF token"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::HeaderValue;
    use rustegon_sim_api::{OsRng, SystemClock};

    use super::*;
    use crate::{Executor, rest::context::context_from_headers, services::ServiceDeps};

    const TOKEN: &str = "c2Vzc2lvbi10b2tlbi1mb3ItdGVzdHMtMDEyMzQ1Njc4OWFi";

    fn deps() -> ServiceDeps {
        let clock = Arc::new(SystemClock::new());
        ServiceDeps {
            executor: Executor::new(clock.clone(), 1),
            clock,
            rng: Arc::new(OsRng),
        }
    }

    fn map(pairs: &[(&str, String)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn tc_sec_008_csrf_token_is_bound_to_the_session() {
        let a = csrf_token(TOKEN);
        assert_eq!(a.len(), 64);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(a, csrf_token(TOKEN));
        assert_ne!(a, csrf_token("another-session"));
        assert!(!a.contains(TOKEN));
    }

    #[test]
    fn tc_sec_008_session_cookie_parsing() {
        let h = map(&[(
            "cookie",
            format!("theme=dark; {SESSION_COOKIE}={TOKEN}; x=1"),
        )]);
        assert_eq!(session_cookie(&h).unwrap().as_deref(), Some(TOKEN));
        // Split cookie fields (HTTP/2) are all searched.
        let h = map(&[
            ("cookie", "theme=dark".to_owned()),
            ("cookie", format!("{SESSION_COOKIE}={TOKEN}")),
        ]);
        assert_eq!(session_cookie(&h).unwrap().as_deref(), Some(TOKEN));
        assert_eq!(
            session_cookie(&map(&[("cookie", "a=b".into())])).unwrap(),
            None
        );
        assert_eq!(session_cookie(&HeaderMap::new()).unwrap(), None);
        for bad in [
            format!("{SESSION_COOKIE}={TOKEN}; {SESSION_COOKIE}={TOKEN}"),
            format!("{SESSION_COOKIE}="),
            format!("{SESSION_COOKIE}=\"{TOKEN}\""),
            format!("{SESSION_COOKIE}=a.b"),
            format!(
                "{SESSION_COOKIE}={}",
                "a".repeat(MAX_SESSION_COOKIE_LEN + 1)
            ),
        ] {
            let err = session_cookie(&map(&[("cookie", bad.clone())])).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.details().get("header").unwrap(), "cookie");
            assert!(!err.message().contains(TOKEN));
        }
    }

    #[test]
    fn tc_sec_008_csrf_required_for_state_changing_cookie_requests() {
        let cookie = ("cookie", format!("{SESSION_COOKIE}={TOKEN}"));
        // Safe methods need no CSRF token; the cookie becomes Bearer credentials.
        let ctx = context_from_headers(&Method::GET, &map(std::slice::from_ref(&cookie)), &deps())
            .unwrap();
        assert_eq!(
            ctx.credentials().unwrap().expose(),
            &format!("Bearer {TOKEN}")
        );

        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let err = context_from_headers(&method, &map(std::slice::from_ref(&cookie)), &deps())
                .unwrap_err();
            assert_eq!(err.error().code(), ErrorCode::PermissionDenied, "{method}");
            assert_eq!(err.error().details().get("reason").unwrap(), "csrf");

            let wrong = (CSRF_HEADER, csrf_token("other"));
            let err =
                context_from_headers(&method, &map(&[cookie.clone(), wrong]), &deps()).unwrap_err();
            assert_eq!(err.error().code(), ErrorCode::PermissionDenied, "{method}");

            let right = (CSRF_HEADER, csrf_token(TOKEN));
            let ctx =
                context_from_headers(&method, &map(&[cookie.clone(), right]), &deps()).unwrap();
            assert_eq!(
                ctx.credentials().unwrap().expose(),
                &format!("Bearer {TOKEN}")
            );
        }

        // Header credentials win and need no CSRF token; the cookie is then ignored.
        let ctx = context_from_headers(
            &Method::POST,
            &map(&[cookie, ("authorization", "Bearer header-token".into())]),
            &deps(),
        )
        .unwrap();
        assert_eq!(ctx.credentials().unwrap().expose(), "Bearer header-token");
    }
}
