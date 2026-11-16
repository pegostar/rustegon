// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Minimal golden-file support (snapshot testing without an extra dependency).
//!
//! A golden file is a list of cases:
//! ```text
//! === name: tag tag …
//! <input lines>
//! --- <section>
//! <expected lines>
//! ```
//! Expected sections are compared with what the test produces. With `RGQL_BLESS=1` the file is
//! rewritten with the produced sections instead (review the diff before committing).

use std::{fmt::Write as _, fs, path::PathBuf};

/// One case of a golden file.
pub struct Case {
    pub name: String,
    pub tags: Vec<String>,
    pub input: String,
    /// Recorded sections `(title, body)`.
    pub sections: Vec<(String, String)>,
}

pub fn path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(file)
}

pub fn load(file: &str) -> Vec<Case> {
    let text = fs::read_to_string(path(file))
        .unwrap()
        .replace("\r\n", "\n");
    let mut cases: Vec<Case> = Vec::new();
    let mut section: Option<(String, String)> = None;
    for line in text.lines() {
        if let Some(header) = line.strip_prefix("=== ") {
            if let (Some(c), Some(s)) = (cases.last_mut(), section.take()) {
                c.sections.push(s);
            }
            let (name, tags) = header.split_once(':').unwrap_or((header, ""));
            cases.push(Case {
                name: name.trim().to_owned(),
                tags: tags.split_whitespace().map(str::to_owned).collect(),
                input: String::new(),
                sections: Vec::new(),
            });
        } else if let Some(title) = line.strip_prefix("--- ") {
            let c = cases.last_mut().unwrap();
            if let Some(s) = section.take() {
                c.sections.push(s);
            }
            section = Some((title.trim().to_owned(), String::new()));
        } else if let Some((_, body)) = section.as_mut() {
            body.push_str(line);
            body.push('\n');
        } else if let Some(c) = cases.last_mut() {
            c.input.push_str(line);
            c.input.push('\n');
        }
    }
    if let (Some(c), Some(s)) = (cases.last_mut(), section.take()) {
        c.sections.push(s);
    }
    for c in &mut cases {
        c.input = c.input.trim_end_matches('\n').to_owned();
        for (_, body) in &mut c.sections {
            *body = body.trim_end_matches('\n').to_owned();
        }
    }
    cases
}

pub fn blessing() -> bool {
    std::env::var("RGQL_BLESS").is_ok_and(|v| v == "1")
}

/// Compares produced sections with the recorded ones (or rewrites the file when blessing).
/// Returns the list of mismatch descriptions.
pub fn check(file: &str, cases: &[Case], produced: &[Vec<(String, String)>]) -> Vec<String> {
    if blessing() {
        let mut out = String::new();
        for (c, sections) in cases.iter().zip(produced) {
            let tags = if c.tags.is_empty() {
                String::new()
            } else {
                format!(": {}", c.tags.join(" "))
            };
            let _ = writeln!(out, "=== {}{tags}", c.name);
            let _ = writeln!(out, "{}", c.input);
            for (title, body) in sections {
                let _ = writeln!(out, "--- {title}\n{body}");
            }
        }
        fs::write(path(file), out).unwrap();
        return Vec::new();
    }
    let mut failures = Vec::new();
    for (c, sections) in cases.iter().zip(produced) {
        if &c.sections != sections {
            let mut msg = format!("golden mismatch in case `{}`:\n", c.name);
            for (title, body) in sections {
                let recorded = c
                    .sections
                    .iter()
                    .find(|(t, _)| t == title)
                    .map_or("<missing>", |(_, b)| b.as_str());
                if recorded != body {
                    let _ = writeln!(msg, "  [{title}] expected:\n{recorded}\n  actual:\n{body}");
                }
            }
            failures.push(msg);
        }
    }
    failures
}
