// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `THIRD-PARTY-LICENSES.txt` of an archive (PD-155), generated, never hand-written:
//! - the Rust crates linked into `rustegond` and `rustegon` for the archive's target triple,
//!   from `cargo metadata --filter-platform` (every non-dev edge reachable from the two
//!   binaries), each with the license files its published package ships; identical texts
//!   (most Apache-2.0 copies) are printed once with the list of crates using them;
//! - the npm packages bundled into the embedded web console, from the Angular build's own
//!   `gui/dist/3rdpartylicenses.txt` (`extractLicenses`, default of the production build).

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
    process::Command,
};

use serde_json::Value;

use crate::{Result, capture};

/// Workspace packages whose shipped dependency graph is reported.
const ROOTS: [&str; 2] = ["rustegond", "rustegon-cli"];

pub fn third_party_file(root: &Path, triple: &str) -> Result<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let json = capture(Command::new(cargo).current_dir(root).args([
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--filter-platform",
        triple,
    ]))?;
    let metadata: Value =
        serde_json::from_str(&json).map_err(|e| format!("cargo metadata: {e}"))?;
    let mut text = crates_report(&metadata, &ROOTS, triple)?;
    let gui = root.join("gui/dist/3rdpartylicenses.txt");
    let gui_text = fs::read_to_string(&gui).map_err(|e| format!("{}: {e}", gui.display()))?;
    text.push_str(
        "\n==============================================================================\n\
         Web console (embedded in rustegond): npm packages, from the Angular build's\n\
         3rdpartylicenses.txt\n\
         ==============================================================================\n\n",
    );
    text.push_str(&gui_text);
    Ok(text)
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// License files at the root of a crate package (LICENSE*, LICENCE*, COPYING*, NOTICE*,
/// UNLICENSE*), sorted by name.
fn license_files(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let upper = name.to_uppercase();
        let is_license = ["LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE"]
            .iter()
            .any(|p| upper.starts_with(p));
        if is_license && entry.path().is_file() {
            let text = fs::read_to_string(entry.path())
                .map_err(|e| format!("{}: {e}", entry.path().display()))?;
            files.push((name, text));
        }
    }
    files.sort();
    Ok(files)
}

/// The Rust part of the file from `cargo metadata` output.
pub fn crates_report(metadata: &Value, roots: &[&str], triple: &str) -> Result<String> {
    let packages: BTreeMap<&str, &Value> = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata: no packages")?
        .iter()
        .map(|p| (str_of(p, "id"), p))
        .collect();
    let nodes: BTreeMap<&str, &Value> = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata: no resolve graph")?
        .iter()
        .map(|n| (str_of(n, "id"), n))
        .collect();

    // Walk from the binaries over every edge that is not dev-only: normal and build
    // dependencies (build scripts and proc macros are not linked, but listing them errs on the
    // side of attribution).
    let mut todo: Vec<&str> = packages
        .values()
        .filter(|p| roots.contains(&str_of(p, "name")) && p["source"].is_null())
        .map(|p| str_of(p, "id"))
        .collect();
    if todo.len() != roots.len() {
        return Err(format!("cargo metadata: expected the packages {roots:?}"));
    }
    let mut seen = BTreeSet::new();
    while let Some(id) = todo.pop() {
        if !seen.insert(id) {
            continue;
        }
        let deps = nodes.get(id).and_then(|n| n["deps"].as_array());
        for dep in deps.into_iter().flatten() {
            let shipped = dep["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k["kind"].as_str() != Some("dev"));
            if shipped {
                todo.push(str_of(dep, "pkg"));
            }
        }
    }

    // Third-party = from a registry or git (workspace crates have no `source`).
    let mut listed = Vec::new();
    let mut texts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut without_files = Vec::new();
    for id in seen {
        let Some(p) = packages.get(id) else { continue };
        if p["source"].is_null() {
            continue;
        }
        let label = format!("{} {}", str_of(p, "name"), str_of(p, "version"));
        let license = match str_of(p, "license") {
            "" => "(no SPDX expression; see its license file)",
            l => l,
        };
        listed.push(format!("{label}  —  {license}"));
        let dir = Path::new(str_of(p, "manifest_path"))
            .parent()
            .ok_or(format!("{label}: no manifest path"))?;
        let files = license_files(dir)?;
        if files.is_empty() {
            without_files.push(label.clone());
        }
        for (name, text) in files {
            texts
                .entry(format!("[{name}]\n\n{}", text.trim_end()))
                .or_default()
                .insert(label.clone());
        }
    }
    listed.sort();

    let rule = "==============================================================================\n";
    let mut out = format!(
        "Third-party software in rustegond and rustegon ({triple})\n\n\
         Generated by `cargo xtask dist` from the dependency graph (`cargo metadata`) and the\n\
         license files shipped in each crate package; do not edit. Rustegon itself is licensed\n\
         under Apache-2.0 (LICENSE, NOTICE).\n\n{rule}Rust crates ({})\n{rule}\n",
        listed.len()
    );
    for line in &listed {
        out.push_str(line);
        out.push('\n');
    }
    if !without_files.is_empty() {
        out.push_str(
            "\nCrates whose package ships no license file (their SPDX expression above \
             applies; the standard text is in this file under another crate):\n",
        );
        for label in &without_files {
            let _ = writeln!(out, "  {label}");
        }
    }
    let _ = write!(out, "\n{rule}License texts of the Rust crates\n{rule}");
    for (text, users) in &texts {
        let users: Vec<&str> = users.iter().map(String::as_str).collect();
        let _ = write!(
            out,
            "\n------------------------------------------------------------------------------\n\
             Used by: {}\n\n{text}\n",
            users.join(", ")
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn fr_ins_003_licenses_follow_shipped_edges_and_dedup_texts() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let krate = |name: &str, license: Option<&str>| -> Result<String> {
            let d = dir.path().join(name);
            fs::create_dir_all(&d).map_err(|e| e.to_string())?;
            if let Some(text) = license {
                fs::write(d.join("LICENSE-MIT"), text).map_err(|e| e.to_string())?;
            }
            Ok(d.join("Cargo.toml").display().to_string())
        };
        let reg = "registry+https://github.com/rust-lang/crates.io-index";
        let metadata = json!({
            "packages": [
                {"id": "bin", "name": "rustegond", "version": "0.1.0", "source": null,
                 "license": "Apache-2.0", "manifest_path": krate("bin", None)?},
                {"id": "a", "name": "alpha", "version": "1.0.0", "source": reg,
                 "license": "MIT", "manifest_path": krate("a", Some("MIT text"))?},
                {"id": "b", "name": "beta", "version": "2.0.0", "source": reg,
                 "license": "MIT", "manifest_path": krate("b", Some("MIT text"))?},
                {"id": "c", "name": "gamma", "version": "3.0.0", "source": reg,
                 "license": "MIT", "manifest_path": krate("c", None)?},
                {"id": "t", "name": "testonly", "version": "1.0.0", "source": reg,
                 "license": "GPL-3.0", "manifest_path": krate("t", Some("GPL"))?},
            ],
            "resolve": {"nodes": [
                {"id": "bin", "deps": [
                    {"pkg": "a", "dep_kinds": [{"kind": null}]},
                    {"pkg": "c", "dep_kinds": [{"kind": "build"}]},
                    {"pkg": "t", "dep_kinds": [{"kind": "dev"}]},
                ]},
                {"id": "a", "deps": [{"pkg": "b", "dep_kinds": [{"kind": null}]}]},
                {"id": "b", "deps": []},
                {"id": "c", "deps": []},
                {"id": "t", "deps": []},
            ]},
        });
        let report = crates_report(&metadata, &["rustegond"], "x86_64-unknown-linux-gnu")?;
        assert!(report.contains("alpha 1.0.0  —  MIT\nbeta 2.0.0  —  MIT\ngamma 3.0.0  —  MIT\n"));
        assert!(!report.contains("testonly"), "dev-only dependency listed");
        assert!(
            !report.contains("rustegond 0.1.0"),
            "workspace crate listed"
        );
        assert_eq!(
            report.matches("MIT text").count(),
            1,
            "identical texts not merged"
        );
        assert!(report.contains("Used by: alpha 1.0.0, beta 2.0.0\n\n[LICENSE-MIT]\n\nMIT text\n"));
        assert!(report.contains("ships no license file") && report.contains("  gamma 3.0.0\n"));
        Ok(())
    }
}
