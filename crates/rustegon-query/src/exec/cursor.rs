// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cursors and keyset continuation tokens of read queries (FR-QL-006, FR-QL-007, TC-QL-007;
//! query-engine.md §7, query-language.md §5.2).
//!
//! A [`QueryCursor`] keeps the operator pipeline of one read between calls: each
//! [`QueryCursor::next_batch`] (`getMore`) pulls operator batches until the cursor batch is
//! full (rows or bytes), so memory is bounded by one operator batch plus one cursor batch,
//! except for a blocking `Sort` (bounded by the memory limit). The caller owns the snapshot:
//! every call must run in the same transaction (the embedded cursor keeps it open).
//!
//! **Continuation tokens.** A query with `ORDER BY` has a total stream order
//! `(ORDER BY keys, _id)` (ties are ordered by `_id`), so after any batch the cursor can return
//! a token holding the position of the last row returned. Opening the same query with the token
//! inserts a `Resume` operator that drops every row up to that position and returns the
//! remaining `LIMIT` (the `OFFSET` was consumed by the first page): no row is returned twice
//! and, at the same snapshot, none is skipped. Queries without `ORDER BY` have no stable order
//! across executions (the access path may change) and get no token.
//!
//! *Token format 1* (*Provisional (PD-041)*): `rdoc({v: 1, q: fingerprint, n: rows returned,
//! k: [{v: key} | {} (missing)], id: {v: _id} | {}}) ‖ xxh3_64(rdoc) (u64 BE)`. The
//! fingerprint (XXH3-64 of the session database, the printed statement and the parameters)
//! binds a token to its query (`RGN-1001` otherwise). The checksum detects corruption only: the
//! AES-GCM sealing of query-engine.md §7 needs the cluster secret and is applied by the gateway
//! (M4); the embedded API hands the token to its own caller. No read timestamp is carried:
//! a resumed query reads a fresh snapshot (keyset semantics) until `AS OF SYSTEM TIME` reads
//! exist.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use rustegon_common::Error;
use rustegon_doc::{Document, Value, rdoc};
use twox_hash::XxHash3_64;

use super::{
    ExecCtx, ExecOptions, Interrupt, QueryStore,
    project::project,
    read::{Position, RowStream, StreamConfig, order_keys},
    statement_max_time,
};
use crate::{
    ast::Statement,
    bind::{Binder, BoundStatement, CatalogView, SortKey},
    error::{ExecResult, invalid},
    expr::{EvalCtx, ops::approx_size},
    params::Params,
    plan::{OrderStrategy, PhysicalPlan},
    print::print_statement,
};

/// Default rows per cursor batch (query-engine.md §7 `batchSize`).
pub const DEFAULT_CURSOR_BATCH_ROWS: usize = 1000;
/// Default bytes per cursor batch (query-engine.md §7: 4 MiB).
pub const DEFAULT_CURSOR_BATCH_BYTES: usize = 4 << 20;
/// Version of the continuation token format.
const TOKEN_VERSION: i64 = 1;
/// Bytes of the trailing checksum.
const CHECKSUM_LEN: usize = 8;

/// Size of the batches a cursor returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorLimits {
    /// Rows per batch (at least 1).
    pub batch_rows: usize,
    /// Approximate bytes per batch (a batch always has at least one row).
    pub batch_bytes: usize,
}

impl Default for CursorLimits {
    fn default() -> Self {
        Self {
            batch_rows: DEFAULT_CURSOR_BATCH_ROWS,
            batch_bytes: DEFAULT_CURSOR_BATCH_BYTES,
        }
    }
}

/// One batch of a cursor.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CursorBatch {
    /// Result rows (projected).
    pub rows: Vec<Value>,
    /// Resumes the query after the last row of this batch (ordered queries with more rows).
    pub continuation_token: Option<Vec<u8>>,
    /// No row follows.
    pub exhausted: bool,
}

/// A read query's pipeline kept between `getMore` calls (module docs).
pub struct QueryCursor {
    plan: Arc<PhysicalPlan>,
    stream: RowStream,
    eval: EvalCtx,
    interrupt: Interrupt,
    keys: Vec<SortKey>,
    ordered: bool,
    /// Unprojected rows pulled from the pipeline but not returned yet (at most one operator
    /// batch).
    pending: VecDeque<Value>,
    exhausted: bool,
    returned: u64,
    last: Option<Position>,
    fingerprint: u64,
}

impl std::fmt::Debug for QueryCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryCursor")
            .field("plan", &self.plan.render())
            .field("returned", &self.returned)
            .field("exhausted", &self.exhausted)
            .finish_non_exhaustive()
    }
}

/// Binds and plans the read `stmt` and opens a cursor on it, after the position of `token` when
/// given (module docs). `OPTIONS (max_time_ms = …)` sets a deadline for the whole cursor,
/// counted from now (*Provisional (PD-041)*).
///
/// # Errors
/// `RGN-1001` for a statement that is not a read query or an invalid / foreign token, bind and
/// planning errors, transaction errors.
pub fn open_cursor(
    store: &mut dyn QueryStore,
    session_db: &str,
    stmt: &Statement,
    params: &Params,
    opts: &ExecOptions,
    token: Option<&[u8]>,
) -> ExecResult<QueryCursor> {
    let bound = {
        let mut binder = Binder {
            catalog: store as &mut dyn CatalogView,
            session_db,
            params,
        };
        binder.bind(stmt)?
    };
    let mut interrupt = opts.interrupt.clone();
    if let (Some(ms), Some(clock)) = (statement_max_time(&bound), &opts.clock) {
        let at = clock.monotonic() + Duration::from_millis(ms);
        interrupt = interrupt.with_deadline(Arc::clone(clock), at);
    }
    interrupt.check()?;
    let BoundStatement::Query(q) = bound else {
        return Err(invalid("a cursor serves read queries (FROM …) only").into());
    };
    let mut plan = super::plan_read(store, &q, opts)?;
    let fingerprint = fingerprint(session_db, stmt, params)?;
    let keys = order_keys(&plan).to_vec();
    let ordered = !keys.is_empty();
    let (resume, returned) = match token {
        None => (None, 0),
        Some(t) => {
            let (n, pos) = decode_token(t, fingerprint, keys.len())?;
            if !ordered {
                return Err(invalid("continuation tokens need a query with ORDER BY").into());
            }
            // The first page consumed the OFFSET; the rest of the LIMIT remains.
            plan.offset = 0;
            plan.limit = plan.limit.map(|l| l.saturating_sub(n));
            if let (OrderStrategy::TopK { k, .. }, Some(l)) = (&mut plan.order, plan.limit) {
                *k = l;
            }
            (Some(pos), n)
        }
    };
    let plan = Arc::new(plan);
    let stream = RowStream::new(
        &plan,
        false,
        StreamConfig {
            resume,
            profile: None,
        },
    );
    Ok(QueryCursor {
        stream,
        eval: EvalCtx::new(store.now_ms()),
        interrupt,
        keys,
        ordered,
        pending: VecDeque::new(),
        exhausted: false,
        returned,
        last: None,
        fingerprint,
        plan,
    })
}

impl QueryCursor {
    /// The next batch (`getMore`), read through `store` — the transaction the cursor was opened
    /// in. An exhausted cursor returns an empty batch with `exhausted` set.
    ///
    /// # Errors
    /// `RGN-5005` / `RGN-5006` (interrupt), `RGN-5004`, evaluation and transaction errors; the
    /// cursor must not be used after an error.
    pub fn next_batch(
        &mut self,
        store: &mut dyn QueryStore,
        opts: &ExecOptions,
        limits: &CursorLimits,
    ) -> ExecResult<CursorBatch> {
        let mut cx = ExecCtx {
            store,
            eval: &self.eval,
            opts,
            interrupt: self.interrupt.clone(),
            profile: None,
        };
        cx.interrupt.check()?;
        let (max_rows, max_bytes) = (limits.batch_rows.max(1), limits.batch_bytes.max(1));
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let mut last_raw: Option<Value> = None;
        while rows.len() < max_rows && bytes < max_bytes {
            if self.pending.is_empty()
                && !refill(
                    &mut self.stream,
                    &mut self.pending,
                    &mut self.exhausted,
                    &mut cx,
                )?
            {
                break;
            }
            let Some(raw) = self.pending.pop_front() else {
                break;
            };
            let out = project(&self.plan.select, &raw, cx.eval)?;
            bytes = bytes.saturating_add(approx_size(&out));
            rows.push(out);
            last_raw = Some(raw);
        }
        // Look ahead one operator batch so that the last batch says it is the last.
        if self.pending.is_empty() {
            refill(
                &mut self.stream,
                &mut self.pending,
                &mut self.exhausted,
                &mut cx,
            )?;
        }
        self.returned += u64::try_from(rows.len()).unwrap_or(u64::MAX);
        if let (true, Some(raw)) = (self.ordered, &last_raw) {
            self.last = Some(Position::of(raw, &self.keys, cx.eval)?);
        }
        let exhausted = self.is_exhausted();
        let continuation_token = if exhausted {
            None
        } else {
            self.continuation_token()?
        };
        Ok(CursorBatch {
            rows,
            continuation_token,
            exhausted,
        })
    }

    /// No row follows.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted && self.pending.is_empty()
    }

    /// Rows returned so far (including those returned before the token this cursor resumed).
    #[must_use]
    pub fn returned(&self) -> u64 {
        self.returned
    }

    /// Warnings of the evaluation so far (§4.2).
    #[must_use]
    pub fn warnings(&self) -> u64 {
        self.eval.warnings()
    }

    /// A token resuming after the last row returned; `None` for queries without `ORDER BY`,
    /// before the first row and once exhausted.
    ///
    /// # Errors
    /// `RGN-1002`-class encoding errors for sort keys too large to encode.
    pub fn continuation_token(&self) -> Result<Option<Vec<u8>>, Error> {
        match (&self.last, self.ordered && !self.is_exhausted()) {
            (Some(p), true) => encode_token(self.fingerprint, self.returned, p).map(Some),
            _ => Ok(None),
        }
    }
}

/// Pulls one operator batch into `pending`; `false` once the pipeline is exhausted.
fn refill(
    stream: &mut RowStream,
    pending: &mut VecDeque<Value>,
    exhausted: &mut bool,
    cx: &mut ExecCtx<'_>,
) -> ExecResult<bool> {
    if *exhausted {
        return Ok(false);
    }
    if let Some(batch) = stream.next_batch(cx)? {
        pending.extend(batch.into_iter().map(|r| r.value));
        Ok(true)
    } else {
        *exhausted = true;
        Ok(false)
    }
}

/// XXH3-64 of the session database, the printed statement and the parameters.
fn fingerprint(session_db: &str, stmt: &Statement, params: &Params) -> Result<u64, Error> {
    let mut d = Document::new();
    d.insert("db", Value::String(session_db.to_owned()));
    d.insert("stmt", Value::String(print_statement(stmt)));
    d.insert("params", Value::Object(params.to_document()));
    Ok(XxHash3_64::oneshot(&rdoc::encode(&d)?))
}

fn boxed(v: Option<&Value>) -> Value {
    let mut d = Document::new();
    if let Some(v) = v {
        d.insert("v", v.clone());
    }
    Value::Object(d)
}

fn unboxed(v: &Value) -> Result<Option<Value>, Error> {
    match v {
        Value::Object(d) => Ok(d.get("v").cloned()),
        _ => Err(bad_token()),
    }
}

fn bad_token() -> Error {
    invalid("invalid continuation token")
}

fn encode_token(fingerprint: u64, returned: u64, pos: &Position) -> Result<Vec<u8>, Error> {
    let mut d = Document::new();
    d.insert("v", Value::Int64(TOKEN_VERSION));
    // Bit-preserving u64 → i64 (the fingerprint is compared, never interpreted).
    d.insert(
        "q",
        Value::Int64(i64::from_be_bytes(fingerprint.to_be_bytes())),
    );
    d.insert(
        "n",
        Value::Int64(i64::try_from(returned).unwrap_or(i64::MAX)),
    );
    d.insert(
        "k",
        Value::Array(pos.keys.iter().map(|k| boxed(k.as_ref())).collect()),
    );
    d.insert("id", boxed(pos.id.as_ref()));
    let mut out = rdoc::encode(&d)?;
    let sum = XxHash3_64::oneshot(&out);
    out.extend_from_slice(&sum.to_be_bytes());
    Ok(out)
}

/// `(rows returned, position)` of a token of the query `fingerprint` with `keys` sort keys.
fn decode_token(token: &[u8], fingerprint: u64, keys: usize) -> Result<(u64, Position), Error> {
    let split = token
        .len()
        .checked_sub(CHECKSUM_LEN)
        .ok_or_else(bad_token)?;
    let (body, sum) = token.split_at(split);
    let sum: [u8; CHECKSUM_LEN] = sum.try_into().map_err(|_| bad_token())?;
    if XxHash3_64::oneshot(body) != u64::from_be_bytes(sum) {
        return Err(bad_token());
    }
    let d = rdoc::decode(body).map_err(|_| bad_token())?;
    if d.get("v") != Some(&Value::Int64(TOKEN_VERSION)) {
        return Err(bad_token().with_detail("reason", "unsupported token version"));
    }
    if d.get("q") != Some(&Value::Int64(i64::from_be_bytes(fingerprint.to_be_bytes()))) {
        return Err(invalid("the continuation token belongs to another query"));
    }
    let returned = match d.get("n") {
        Some(Value::Int64(n)) => u64::try_from(*n).map_err(|_| bad_token())?,
        _ => return Err(bad_token()),
    };
    let Some(Value::Array(ks)) = d.get("k") else {
        return Err(bad_token());
    };
    if ks.len() != keys {
        return Err(bad_token());
    }
    let keys = ks.iter().map(unboxed).collect::<Result<Vec<_>, _>>()?;
    let id = unboxed(d.get("id").ok_or_else(bad_token)?)?;
    Ok((returned, Position { keys, id }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_ql_007_token_round_trip_and_tamper_detection() {
        let pos = Position {
            keys: vec![Some(Value::Int64(5)), None, Some(Value::Null)],
            id: Some(Value::String("x".into())),
        };
        let t = encode_token(42, 7, &pos).unwrap();
        assert_eq!(decode_token(&t, 42, 3).unwrap(), (7, pos.clone()));
        // Another query, another key count, a flipped byte, a truncated token.
        assert!(decode_token(&t, 43, 3).is_err());
        assert!(decode_token(&t, 42, 2).is_err());
        for i in 0..t.len() {
            let mut bad = t.clone();
            bad[i] ^= 0x01;
            assert!(decode_token(&bad, 42, 3).is_err(), "byte {i}");
        }
        assert!(decode_token(&t[..t.len() - 1], 42, 3).is_err());
        assert!(decode_token(&[], 42, 3).is_err());
    }
}
