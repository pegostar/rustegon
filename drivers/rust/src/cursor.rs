// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cursors over query results: the first batch comes with `Execute` (`max_batches = 1`), the
//! following ones with `GetMore`, which is never retried (R3: the server may already have
//! advanced the cursor). Closing (or dropping) a cursor with a server-side id kills it.

use std::{collections::VecDeque, time::Duration};

use crate::{
    codec::{Document, rdoc},
    database::DataContext,
    error::{Error, Result},
    options::OpOptions,
    pb::{self, ExecOptions, ExecuteRequest, GetMoreRequest, KillCursorRequest, ResultBatch},
    session::Session,
    transport::{CallSpec, OpKind, unary},
};

/// A cursor over documents; read with [`next`](Self::next).
#[allow(clippy::struct_field_names)]
pub struct Cursor {
    ctx: DataContext,
    session: Option<Session>,
    batch_size: Option<u32>,
    buffer: VecDeque<pb::Document>,
    cursor_id: Option<String>,
    closed: bool,
}

impl std::fmt::Debug for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cursor")
            .field("buffered", &self.buffer.len())
            .field("open_on_server", &self.cursor_id.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) fn decode_document(d: &pb::Document) -> Result<Document> {
    Ok(rdoc::decode(&d.rdoc)?)
}

impl Cursor {
    pub(crate) async fn open(
        ctx: &DataContext,
        mut req: ExecuteRequest,
        kind: OpKind,
        o: &OpOptions,
    ) -> Result<Self> {
        let options = req.options.get_or_insert_with(ExecOptions::default);
        options.max_batches = Some(1);
        let batch_size = options.batch_size;
        let batches = ctx.execute(req, ctx.spec(kind, o)).await?;
        let mut c = Self {
            ctx: ctx.clone(),
            session: if ctx.txn.is_none() {
                o.session.clone()
            } else {
                None
            },
            batch_size,
            buffer: VecDeque::new(),
            cursor_id: None,
            closed: false,
        };
        for b in batches {
            c.take(b);
        }
        Ok(c)
    }

    fn take(&mut self, b: ResultBatch) {
        self.buffer.extend(b.docs);
        if let Some(id) = b.cursor_id.filter(|i| !i.is_empty()) {
            self.cursor_id = Some(id);
        }
    }

    /// The next document, `None` at the end.
    pub async fn next(&mut self) -> Result<Option<Document>> {
        if self.closed {
            return Err(Error::closed("the cursor"));
        }
        while self.buffer.is_empty() {
            let Some(id) = self.cursor_id.take() else {
                return Ok(None);
            };
            let req = GetMoreRequest {
                cursor_id: id,
                batch_size: self.batch_size,
            };
            let spec = CallSpec {
                kind: OpKind::NoRetry,
                timeout: None,
                session: self.session.as_ref(),
            };
            let r = unary!(
                self.ctx.exec,
                spec,
                query_service_client::QueryServiceClient,
                get_more,
                req
            )?;
            self.take(r.batch.unwrap_or_default());
        }
        match self.buffer.pop_front() {
            Some(d) => decode_document(&d).map(Some),
            None => Ok(None),
        }
    }

    /// Every remaining document.
    pub async fn to_list(&mut self) -> Result<Vec<Document>> {
        let mut out = Vec::new();
        while let Some(d) = self.next().await? {
            out.push(d);
        }
        Ok(out)
    }

    /// Closes the cursor, killing it on the server when it is still open there. Idempotent.
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.buffer.clear();
        if let Some(id) = self.cursor_id.take() {
            kill(&self.ctx, id).await;
        }
        Ok(())
    }
}

async fn kill(ctx: &DataContext, id: String) {
    let spec = CallSpec {
        kind: OpKind::NoRetry,
        timeout: Some(Duration::from_secs(5)),
        session: None,
    };
    // Best effort: the server also reaps idle cursors.
    let _ = unary!(
        ctx.exec,
        spec,
        query_service_client::QueryServiceClient,
        kill_cursor,
        KillCursorRequest { cursor_id: id }
    );
}

impl Drop for Cursor {
    fn drop(&mut self) {
        // A cursor dropped while open on the server is killed in the background when a Tokio
        // runtime is available; otherwise the server reaps it after its idle timeout.
        if let Some(id) = self.cursor_id.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let ctx = self.ctx.clone();
            rt.spawn(async move { kill(&ctx, id).await });
        }
    }
}
