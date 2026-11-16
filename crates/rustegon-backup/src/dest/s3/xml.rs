// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The few XML shapes the S3 client reads and writes (`ListObjectsV2`, multipart initiate and
//! complete, error bodies).
//!
//! Why not an XML crate: the responses used here are flat, attribute-free elements whose
//! content is text (`<Key>`, `<UploadId>`, `<IsTruncated>`, …) or one level of nesting
//! (`<Contents>`, `<CommonPrefixes>`). Extracting them by element name is a few dozen lines;
//! a general parser would add a dependency for no gain. The scanner is tolerant: it ignores
//! namespaces declarations on the root, unknown elements and whitespace, and decodes the five
//! predefined entities plus numeric character references (S3 escapes keys this way).

use std::fmt::Write as _;

/// Inner text of every `<name>…</name>` element in `xml`, in document order, not decoded.
/// Self-closing `<name/>` yields an empty string. Nested elements of the same name are not
/// expected in S3 responses and are not supported.
pub(crate) fn elements<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        // `<Key>` or `<Key attr…>` / `<Key/>`, not `<KeyMarker>`.
        let Some(next) = after.chars().next() else {
            break;
        };
        if !(next == '>' || next == '/' || next.is_whitespace()) {
            rest = after;
            continue;
        }
        let Some(gt) = after.find('>') else {
            break;
        };
        if after[..gt].ends_with('/') {
            out.push("");
            rest = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(end) = body.find(&close) else {
            break;
        };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// Decoded text of the first `<name>` element.
pub(crate) fn first_text(xml: &str, name: &str) -> Option<String> {
    elements(xml, name).first().map(|t| unescape(t))
}

/// Decodes the predefined entities and numeric character references; unknown entities are kept
/// verbatim (a malformed body then fails key validation instead of being guessed at).
pub(crate) fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let Some(semi) = tail.find(';').filter(|&s| s <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = decoded {
            out.push(c);
            rest = &tail[semi + 1..];
        } else {
            out.push('&');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

/// Escapes text for element content.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Body of `CompleteMultipartUpload` for (part number, `ETag`) pairs in ascending order.
pub(crate) fn complete_multipart_body(parts: &[(u32, String)]) -> String {
    let mut body = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        // Writing to a String cannot fail.
        let _ = write!(
            body,
            "<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag></Part>",
            escape(etag)
        );
    }
    body.push_str("</CompleteMultipartUpload>");
    body
}

/// One page of a `ListObjectsV2` response.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ListPage {
    /// Full keys of `<Contents>`.
    pub(crate) keys: Vec<String>,
    /// Full prefixes of `<CommonPrefixes>` (with the trailing delimiter).
    pub(crate) common_prefixes: Vec<String>,
    /// Token for the next page when the listing is truncated.
    pub(crate) next_token: Option<String>,
}

/// Parses a `ListObjectsV2` response body.
pub(crate) fn parse_list(xml: &str) -> ListPage {
    let keys = elements(xml, "Contents")
        .into_iter()
        .filter_map(|c| first_text(c, "Key"))
        .collect();
    let common_prefixes = elements(xml, "CommonPrefixes")
        .into_iter()
        .filter_map(|c| first_text(c, "Prefix"))
        .collect();
    let truncated = first_text(xml, "IsTruncated").is_some_and(|t| t.trim() == "true");
    let next_token = if truncated {
        first_text(xml, "NextContinuationToken").filter(|t| !t.is_empty())
    } else {
        None
    };
    ListPage {
        keys,
        common_prefixes,
        next_token,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_v2_page() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name><Prefix>p/</Prefix><KeyCount>3</KeyCount><MaxKeys>2</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Contents><Key>p/a&amp;b</Key><LastModified>2026-11-10T00:00:00.000Z</LastModified>
    <ETag>&quot;abc&quot;</ETag><Size>5</Size></Contents>
  <Contents><Key>p/c</Key><Size>0</Size></Contents>
  <CommonPrefixes><Prefix>p/dir/</Prefix></CommonPrefixes>
  <NextContinuationToken>1/x+y=</NextContinuationToken>
  <KeyMarker>ignored</KeyMarker>
</ListBucketResult>"#;
        assert_eq!(
            parse_list(xml),
            ListPage {
                keys: vec!["p/a&b".into(), "p/c".into()],
                common_prefixes: vec!["p/dir/".into()],
                next_token: Some("1/x+y=".into()),
            }
        );
        let last = "<ListBucketResult><IsTruncated>false</IsTruncated>\
                    <NextContinuationToken>t</NextContinuationToken></ListBucketResult>";
        assert_eq!(parse_list(last).next_token, None);
    }

    #[test]
    fn entities_and_self_closing_elements() {
        assert_eq!(unescape("a&lt;b&#x41;&#66;&unknown;&"), "a<bAB&unknown;&");
        assert_eq!(elements("<A/><A>x</A><AB>y</AB>", "A"), vec!["", "x"]);
        assert_eq!(escape("\"<&>'"), "&quot;&lt;&amp;&gt;&apos;");
        assert_eq!(
            complete_multipart_body(&[(1, "\"e1\"".into())]),
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>\
             <ETag>&quot;e1&quot;</ETag></Part></CompleteMultipartUpload>"
        );
        let err = "<Error><Code>NoSuchKey</Code><Message>gone</Message></Error>";
        assert_eq!(first_text(err, "Code").as_deref(), Some("NoSuchKey"));
    }
}
