// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! AWS Signature Version 4 (PD-065 option b): the `Authorization` header of S3 requests.
//!
//! Algorithm (AWS "Signature Version 4 signing process"):
//! 1. canonical request = method, canonical URI, canonical query, canonical headers, signed
//!    header list and the hex SHA-256 of the payload, joined by `\n`;
//! 2. string to sign = `AWS4-HMAC-SHA256`, the request time, the credential scope
//!    `<date>/<region>/<service>/aws4_request` and the hex SHA-256 of the canonical request;
//! 3. signing key = HMAC chain `"AWS4" + secret` → date → region → service → `aws4_request`;
//! 4. signature = hex HMAC(signing key, string to sign).
//!
//! S3 differs from the generic algorithm in one point only: the canonical URI is the path
//! URI-encoded **once** and never normalised (no `.`/`..` collapsing, no double encoding), so the
//! caller passes the URI already encoded with [`uri_encode_path`] and this module uses it as is.
//! The same encoded path and query are sent on the wire, so what is signed is exactly what the
//! server sees.
//!
//! Secrets: the secret key is only read inside [`signing_key`]; the returned header contains the
//! access key id (not secret) and the signature, never the secret.

use std::fmt::Write as _;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::id::hex;

/// Algorithm identifier in the string to sign and the `Authorization` header.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Hex SHA-256 of the empty payload (test vectors).
#[cfg(test)]
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // RFC 2104 §2: HMAC accepts keys of any length, so construction cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Hex SHA-256 of `data` (payload hash, `x-amz-content-sha256`).
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Credentials used for one signature.
pub(crate) struct SigningCredentials<'a> {
    pub(crate) access_key_id: &'a str,
    pub(crate) secret_access_key: &'a str,
}

/// Everything that identifies one request to sign.
pub(crate) struct SigningRequest<'a> {
    /// HTTP method, upper case.
    pub(crate) method: &'a str,
    /// Path already URI-encoded ([`uri_encode_path`]), starting with `/`.
    pub(crate) canonical_uri: &'a str,
    /// Query parameters, not encoded (encoded and sorted here).
    pub(crate) query: &'a [(String, String)],
    /// Headers to sign (name, value); names in any case. Must include `host` and `x-amz-date`.
    pub(crate) headers: &'a [(String, String)],
    /// Hex SHA-256 of the payload (or `UNSIGNED-PAYLOAD`).
    pub(crate) payload_sha256: &'a str,
}

/// Request time `yyyymmddThhmmssZ` plus region and service: the scope of a signature.
pub(crate) struct SigningScope<'a> {
    pub(crate) amz_date: &'a str,
    pub(crate) region: &'a str,
    pub(crate) service: &'a str,
}

impl SigningScope<'_> {
    fn date(&self) -> &str {
        self.amz_date.get(..8).unwrap_or(self.amz_date)
    }

    fn credential_scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date(),
            self.region,
            self.service
        )
    }
}

/// RFC 3986 encoding as `SigV4` wants it: unreserved characters (`A-Z a-z 0-9 - . _ ~`) stay,
/// everything else becomes `%XX` with upper-case hex; `/` stays only when `keep_slash`.
fn uri_encode(input: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(char::from(b));
        } else {
            // Writing to a String cannot fail.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Encodes an object path (`/bucket/key`, `/key`) for the request line and the canonical URI.
pub(crate) fn uri_encode_path(path: &str) -> String {
    uri_encode(path, true)
}

/// Canonical query string: parameters encoded, sorted by name then value, joined by `&`. The
/// same string is used as the request's query, so the wire and the signature agree.
pub(crate) fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Header value as canonicalised by `SigV4`: trimmed, inner runs of spaces collapsed to one.
fn canonical_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Canonical headers block and signed-header list. Duplicate names are joined with `,` in the
/// order given (`SigV4` rule).
fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = Vec::with_capacity(headers.len());
    let mut lowered: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), canonical_header_value(v)))
        .collect();
    // Stable sort keeps the order of duplicate names.
    lowered.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in lowered {
        match sorted.last_mut() {
            Some((last, joined)) if *last == name => {
                joined.push(',');
                joined.push_str(&value);
            }
            _ => sorted.push((name, value)),
        }
    }
    let mut block = String::new();
    for (k, v) in &sorted {
        let _ = writeln!(block, "{k}:{v}");
    }
    let signed = sorted
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    (block, signed)
}

/// The canonical request (step 1) and the signed-header list.
pub(crate) fn canonical_request(req: &SigningRequest<'_>) -> (String, String) {
    let (headers, signed) = canonical_headers(req.headers);
    let text = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        req.canonical_uri,
        canonical_query(req.query),
        headers,
        signed,
        req.payload_sha256
    );
    (text, signed)
}

/// The string to sign (step 2).
pub(crate) fn string_to_sign(scope: &SigningScope<'_>, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{}\n{}\n{}",
        scope.amz_date,
        scope.credential_scope(),
        sha256_hex(canonical_request.as_bytes())
    )
}

/// The derived signing key (step 3).
fn signing_key(secret: &str, scope: &SigningScope<'_>) -> zeroize::Zeroizing<[u8; 32]> {
    let mut k_secret = zeroize::Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    k_secret.extend_from_slice(b"AWS4");
    k_secret.extend_from_slice(secret.as_bytes());
    let k_date = zeroize::Zeroizing::new(hmac(&k_secret, scope.date().as_bytes()));
    let k_region = zeroize::Zeroizing::new(hmac(&*k_date, scope.region.as_bytes()));
    let k_service = zeroize::Zeroizing::new(hmac(&*k_region, scope.service.as_bytes()));
    zeroize::Zeroizing::new(hmac(&*k_service, b"aws4_request"))
}

/// The value of the `Authorization` header for `req`.
pub(crate) fn authorization(
    creds: &SigningCredentials<'_>,
    scope: &SigningScope<'_>,
    req: &SigningRequest<'_>,
) -> String {
    let (canonical, signed_headers) = canonical_request(req);
    let to_sign = string_to_sign(scope, &canonical);
    let key = signing_key(creds.secret_access_key, scope);
    let signature = hex(&hmac(&*key, to_sign.as_bytes()));
    format!(
        "{ALGORITHM} Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id,
        scope.credential_scope()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// AWS `SigV4` test suite (`aws-sig-v4-test-suite`): credentials, time, region and service.
    const SUITE_CREDS: SigningCredentials<'static> = SigningCredentials {
        access_key_id: "AKIDEXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    };
    const SUITE_SCOPE: SigningScope<'static> = SigningScope {
        amz_date: "20150830T123600Z",
        region: "us-east-1",
        service: "service",
    };

    fn suite_sign(method: &str, query: &[(&str, &str)]) -> String {
        let headers = h(&[
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", "20150830T123600Z"),
        ]);
        let query = h(query);
        authorization(
            &SUITE_CREDS,
            &SUITE_SCOPE,
            &SigningRequest {
                method,
                canonical_uri: "/",
                query: &query,
                headers: &headers,
                payload_sha256: EMPTY_PAYLOAD_SHA256,
            },
        )
    }

    fn suite_header(signature: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature={signature}"
        )
    }

    #[test]
    fn tc_bkp_006_sigv4_suite_get_vanilla() {
        let headers = h(&[
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", "20150830T123600Z"),
        ]);
        let req = SigningRequest {
            method: "GET",
            canonical_uri: "/",
            query: &[],
            headers: &headers,
            payload_sha256: EMPTY_PAYLOAD_SHA256,
        };
        // Intermediate artefacts of get-vanilla (get-vanilla.creq / .sts).
        let (creq, _) = canonical_request(&req);
        assert_eq!(
            creq,
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n\
             host;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            string_to_sign(&SUITE_SCOPE, &creq),
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
        assert_eq!(
            suite_sign("GET", &[]),
            suite_header("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
        );
    }

    #[test]
    fn tc_bkp_006_sigv4_suite_query_order_and_post() {
        // get-vanilla-query-order-key-case: parameters are sorted by encoded name.
        assert_eq!(
            suite_sign("GET", &[("Param2", "value2"), ("Param1", "value1")]),
            suite_header("b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")
        );
        // get-vanilla-empty-query-key.
        assert_eq!(
            suite_sign("GET", &[("Param1", "value1")]),
            suite_header("a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb")
        );
        // post-vanilla.
        assert_eq!(
            suite_sign("POST", &[]),
            suite_header("5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b")
        );
    }

    /// The four worked examples of the S3 documentation ("Signature Calculations for the
    /// Authorization Header: Transferring Payload in a Single Chunk").
    const S3_CREDS: SigningCredentials<'static> = SigningCredentials {
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    };
    const S3_SCOPE: SigningScope<'static> = SigningScope {
        amz_date: "20130524T000000Z",
        region: "us-east-1",
        service: "s3",
    };

    fn s3_signature(
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        payload: &str,
    ) -> String {
        let mut headers = h(&[
            ("Host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-content-sha256", payload),
        ]);
        headers.extend(h(extra));
        let query = h(query);
        let uri = uri_encode_path(path);
        let header = authorization(
            &S3_CREDS,
            &S3_SCOPE,
            &SigningRequest {
                method,
                canonical_uri: &uri,
                query: &query,
                headers: &headers,
                payload_sha256: payload,
            },
        );
        header
            .rsplit_once("Signature=")
            .map(|(_, s)| s.to_owned())
            .unwrap()
    }

    #[test]
    fn tc_bkp_006_sigv4_s3_documentation_examples() {
        // GET Object with a Range header.
        assert_eq!(
            s3_signature(
                "GET",
                "/test.txt",
                &[],
                &[("Range", "bytes=0-9")],
                EMPTY_PAYLOAD_SHA256
            ),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        // PUT Object: `$` in the key is encoded once, the payload hash is signed.
        let body = b"Welcome to Amazon S3.";
        let payload = sha256_hex(body);
        assert_eq!(
            payload,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        assert_eq!(
            s3_signature(
                "PUT",
                "/test$file.text",
                &[],
                &[
                    ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                    ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ],
                &payload
            ),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
        // GET Bucket lifecycle: a parameter without value.
        assert_eq!(
            s3_signature("GET", "/", &[("lifecycle", "")], &[], EMPTY_PAYLOAD_SHA256),
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
        // GET Bucket (list objects).
        assert_eq!(
            s3_signature(
                "GET",
                "/",
                &[("max-keys", "2"), ("prefix", "J")],
                &[],
                EMPTY_PAYLOAD_SHA256
            ),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    #[test]
    fn uri_encoding_follows_sigv4_rules() {
        assert_eq!(uri_encode_path("/a b/c~d/é"), "/a%20b/c~d/%C3%A9");
        assert_eq!(
            canonical_query(&h(&[("continuation-token", "a/b+c="), ("list-type", "2")])),
            "continuation-token=a%2Fb%2Bc%3D&list-type=2"
        );
        let (block, signed) = canonical_headers(&h(&[
            ("My-Header1", "  a   b   c  "),
            ("Host", "h"),
            ("my-header1", "d"),
        ]));
        assert_eq!(block, "host:h\nmy-header1:a b c,d\n");
        assert_eq!(signed, "host;my-header1");
    }
}
