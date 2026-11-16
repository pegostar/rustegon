// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Causal-consistency sessions (rust-driver.md §6, consistency.md): a session remembers the last
//! `rgn-causality-token` returned by the server and sends it with every operation run in it, so a
//! read observes the session's earlier writes even on another node.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use tonic::metadata::MetadataMap;

use crate::{
    error::{Error, Result},
    transport::CAUSALITY_TOKEN_HEADER,
};

/// A causal-consistency session; cheap to clone (clones share the token). No I/O.
#[derive(Clone, Debug)]
pub struct Session {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    causal: bool,
    token: Mutex<Option<String>>,
    closed: AtomicBool,
}

impl Session {
    pub(crate) fn new(causal: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                causal,
                token: Mutex::new(None),
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// The last causality token seen, if any.
    #[must_use]
    pub fn causality_token(&self) -> Option<String> {
        self.inner.token.lock().map_or(None, |t| t.clone())
    }

    /// Whether the session sends its token (causal consistency).
    #[must_use]
    pub fn is_causal(&self) -> bool {
        self.inner.causal
    }

    /// Closes the session; later operations in it fail with [`Error::InvalidState`]. Idempotent.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
    }

    pub(crate) fn token_to_send(&self) -> Result<Option<String>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::closed("the session"));
        }
        Ok(if self.inner.causal {
            self.causality_token()
        } else {
            None
        })
    }

    pub(crate) fn observe(&self, md: &MetadataMap) {
        if let Some(v) = md.get(CAUSALITY_TOKEN_HEADER).and_then(|v| v.to_str().ok())
            && !v.is_empty()
            && let Ok(mut t) = self.inner.token.lock()
        {
            *t = Some(v.to_owned());
        }
    }
}
