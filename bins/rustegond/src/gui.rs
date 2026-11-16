// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The GUI build output (`gui/dist/`, base href `/ui/`) embedded into the binary (ADR-027,
//! PD-130), served by `rustegon_server::rest::RestServer::with_gui` when `[gui] enabled`.
//!
//! Release builds embed the files present when this crate is compiled; a checkout without
//! `gui/dist/` still builds (`allow_missing`) and `/ui` then answers 503 "not built". Debug
//! builds read `gui/dist/` from the source tree at run time (rust-embed's default), so a
//! rebuilt GUI shows up on the next request without recompiling.
//!
//! shortcut: cargo does not notice files added to `gui/dist/` after `rustegond` was compiled;
//! packaging builds the GUI first (or `cargo clean -p rustegond`). Upgrade to a build script
//! tracking the folder if that ordering becomes a problem.

use rustegon_server::rest::{GuiAssets, GuiFile};

#[derive(rust_embed::RustEmbed)]
#[folder = "../../gui/dist/"]
#[allow_missing = true]
struct Dist;

/// The embedded `gui/dist/`.
pub struct EmbeddedGui;

impl GuiAssets for EmbeddedGui {
    fn get(&self, path: &str) -> Option<GuiFile> {
        Dist::get(path).map(|f| GuiFile {
            hash: f.metadata.sha256_hash(),
            data: f.data,
        })
    }
}

/// Whether this binary carries a GUI build (startup log).
pub fn is_built() -> bool {
    Dist::get("index.html").is_some()
}
