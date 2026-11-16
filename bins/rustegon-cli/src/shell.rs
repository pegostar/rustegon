// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon shell`: an RGQL REPL over gRPC (FR-QL-001, FR-TXN-001, protocol.md §3; PD-058).
//!
//! - Input: interactive lines (plain stdin, no line editing), `-c STATEMENTS` (repeatable) or
//!   `--file PATH`. Statements end with `;` (the last one of `-c`/`--file` may omit it); the
//!   splitter honours strings, backtick identifiers and comments (query-language.md §2), so a
//!   `;` inside them does not end a statement.
//! - `BEGIN …`, `COMMIT`, `ROLLBACK` map to `TransactionService` (an interactive transaction
//!   across statements, FR-TXN-001); every other statement is sent as RGQL text to
//!   `QueryService.Execute` with the open transaction id and its streamed batches are drained.
//!   Savepoints are not part of the v1 API and are refused locally.
//! - Output: every result row as one JSON line on stdout (`rustegon_doc::json`, canonical
//!   extended JSON by default, `--json extended` wraps every number); a status line per
//!   statement (`-- 3 row(s)`, `-- 1 affected`, `-- BEGIN <txn>`) and warnings on stderr, so
//!   stdout stays machine-readable.
//! - Errors: interactive mode reports and continues; `-c`/`--file` stop at the first error with
//!   exit code 1. A transaction still open at the end of the input is rolled back (and, outside
//!   interactive mode, reported as an error): nothing is committed implicitly.
//! - Meta commands (interactive, at the start of a statement): `\q` quits, `\c <db>` switches
//!   the default database, `\?` prints help.

use std::{
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    path::PathBuf,
};

use clap::{Args, ValueEnum};
use rustegon_doc::{
    json::{JsonMode, to_json},
    rdoc,
};
use rustegon_proto::v1::{
    AstIsolation, AstPriority, BeginRequest, CommitRequest, ExecuteRequest, RollbackRequest,
    execute_request::Query, query_service_client::QueryServiceClient,
    transaction_service_client::TransactionServiceClient,
};
use rustegon_query::{
    Statement,
    ast::stmt::{Isolation, Priority},
    parse_statement,
};

use crate::{
    client::{Client, ConnArgs},
    output::{CliError, CliResult, err, fail, io_err, out},
    secrets::read_file,
};

/// Largest `--file` script.
const MAX_SCRIPT: u64 = 64 << 20;

/// JSON output mode of result rows.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum JsonOutput {
    /// Plain JSON where lossless, `$`-wrappers elsewhere (data-model.md §2).
    #[default]
    Canonical,
    /// Every int64 and float64 wrapped (`{"$int64":"1"}`).
    Extended,
}

/// `rustegon shell`.
#[derive(Debug, Args)]
pub struct ShellArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Default database of unqualified collection names.
    #[arg(long, short = 'd', value_name = "DB")]
    database: Option<String>,
    /// Statements to run instead of the REPL (repeatable, run in order).
    #[arg(long, short = 'c', value_name = "STATEMENTS", conflicts_with = "file")]
    command: Vec<String>,
    /// Script file to run instead of the REPL.
    #[arg(long, short = 'f', value_name = "PATH")]
    file: Option<PathBuf>,
    /// JSON mode of result rows.
    #[arg(long, value_enum, default_value_t)]
    json: JsonOutput,
}

/// Lexer state of [`Splitter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lex {
    Code,
    /// `'…'`; `escape` after a backslash.
    Single {
        escape: bool,
    },
    Backtick,
    LineComment,
    /// `/* … */`; `star` after a `*`.
    BlockComment {
        star: bool,
    },
}

/// Incremental statement splitter (module docs).
#[derive(Debug)]
struct Splitter {
    buf: String,
    state: Lex,
    /// Whether the current statement has a character outside whitespace and comments.
    has_code: bool,
}

impl Splitter {
    fn new() -> Self {
        Self {
            buf: String::new(),
            state: Lex::Code,
            has_code: false,
        }
    }

    /// Whether nothing but whitespace and comments is pending.
    fn is_empty(&self) -> bool {
        !self.has_code
    }

    /// Feeds text; returns the statements completed by a `;` (without it, trimmed).
    fn feed(&mut self, text: &str) -> Vec<String> {
        let mut done = Vec::new();
        let mut chars = text.chars().peekable();
        let comment = |s: Lex| matches!(s, Lex::LineComment | Lex::BlockComment { .. });
        while let Some(c) = chars.next() {
            let before = self.state;
            match self.state {
                Lex::Code => match c {
                    ';' => {
                        if self.has_code {
                            done.push(self.buf.trim().to_owned());
                        }
                        self.buf.clear();
                        self.has_code = false;
                        continue;
                    }
                    '\'' => self.state = Lex::Single { escape: false },
                    '`' => self.state = Lex::Backtick,
                    '-' if chars.peek() == Some(&'-') => self.state = Lex::LineComment,
                    '/' if chars.peek() == Some(&'*') => {
                        self.buf.push(c);
                        if let Some(star) = chars.next() {
                            self.buf.push(star);
                        }
                        self.state = Lex::BlockComment { star: false };
                        continue;
                    }
                    _ => {}
                },
                Lex::Single { escape: true } => self.state = Lex::Single { escape: false },
                Lex::Single { escape: false } => match c {
                    '\\' => self.state = Lex::Single { escape: true },
                    // `''` is an escaped quote: closing then reopening is equivalent.
                    '\'' => self.state = Lex::Code,
                    _ => {}
                },
                Lex::Backtick => {
                    if c == '`' {
                        self.state = Lex::Code;
                    }
                }
                Lex::LineComment => {
                    if c == '\n' {
                        self.state = Lex::Code;
                    }
                }
                Lex::BlockComment { star } => {
                    self.state = if star && c == '/' {
                        Lex::Code
                    } else {
                        Lex::BlockComment { star: c == '*' }
                    };
                }
            }
            // The character that closes a comment belongs to the comment too.
            if !comment(before) && !comment(self.state) && !c.is_whitespace() {
                self.has_code = true;
            }
            self.buf.push(c);
        }
        done
    }

    /// The pending statement at the end of the input, if any.
    fn finish(&mut self) -> Option<String> {
        let rest = self.has_code.then(|| self.buf.trim().to_owned());
        self.buf.clear();
        self.has_code = false;
        self.state = Lex::Code;
        rest
    }
}

/// What the shell does with one statement.
enum Action {
    Begin(BeginRequest),
    Commit,
    Rollback,
    Unsupported(&'static str),
    Execute,
}

fn classify(text: &str) -> Action {
    // A statement the local parser rejects is still sent: the server's error is the
    // authoritative one (and the server may be newer than this CLI).
    match parse_statement(text) {
        Ok(Statement::Begin(b)) => {
            if b.as_of.is_some() {
                return Action::Unsupported("BEGIN … AS OF SYSTEM TIME");
            }
            let isolation = match b.isolation {
                None => AstIsolation::Unspecified,
                Some(Isolation::Serializable) => AstIsolation::Serializable,
                Some(Isolation::Snapshot) => AstIsolation::Snapshot,
                Some(Isolation::ReadCommitted) => AstIsolation::ReadCommitted,
            };
            let priority = match b.priority {
                None => AstPriority::Unspecified,
                Some(Priority::High) => AstPriority::High,
                Some(Priority::Normal) => AstPriority::Normal,
                Some(Priority::Low) => AstPriority::Low,
            };
            Action::Begin(BeginRequest {
                isolation: isolation as i32,
                read_only: b.read_only,
                priority: priority as i32,
                ..BeginRequest::default()
            })
        }
        Ok(Statement::Commit) => Action::Commit,
        Ok(Statement::Rollback) => Action::Rollback,
        Ok(
            Statement::Savepoint { .. }
            | Statement::RollbackToSavepoint { .. }
            | Statement::ReleaseSavepoint { .. },
        ) => Action::Unsupported("savepoints"),
        _ => Action::Execute,
    }
}

/// A connected shell session.
struct Session {
    client: Client,
    database: String,
    txn: Option<String>,
    mode: JsonMode,
}

impl Session {
    /// Runs one statement and prints its results.
    fn run(&mut self, text: &str) -> CliResult<()> {
        match classify(text) {
            Action::Unsupported(what) => fail(format!("{what} are not supported by the shell")),
            Action::Begin(request) => {
                if let Some(t) = &self.txn {
                    return fail(format!("transaction {t} is already open"));
                }
                let mut txn = TransactionServiceClient::new(self.client.channel());
                let begun = self
                    .client
                    .call(txn.begin(self.client.request(request)))?
                    .into_inner();
                err(&format!("-- BEGIN {}", begun.txn_id));
                self.txn = Some(begun.txn_id);
                Ok(())
            }
            Action::Commit => {
                let Some(txn_id) = self.txn.take() else {
                    return fail("no open transaction");
                };
                let mut txn = TransactionServiceClient::new(self.client.channel());
                self.client
                    .call(txn.commit(self.client.request(CommitRequest { txn_id })))?;
                err("-- COMMIT");
                Ok(())
            }
            Action::Rollback => {
                let Some(txn_id) = self.txn.take() else {
                    return fail("no open transaction");
                };
                self.rollback(txn_id)?;
                err("-- ROLLBACK");
                Ok(())
            }
            Action::Execute => self.execute(text),
        }
    }

    fn rollback(&self, txn_id: String) -> CliResult<()> {
        let mut txn = TransactionServiceClient::new(self.client.channel());
        self.client
            .call(txn.rollback(self.client.request(RollbackRequest { txn_id })))?;
        Ok(())
    }

    fn execute(&self, text: &str) -> CliResult<()> {
        let request = self.client.request(ExecuteRequest {
            database: self.database.clone(),
            query: Some(Query::Rgql(text.to_owned())),
            txn_id: self.txn.clone(),
            ..ExecuteRequest::default()
        });
        let mut query = QueryServiceClient::new(self.client.channel());
        let mode = self.mode;
        let (rows, affected) = self.client.call(async move {
            let mut stream = query.execute(request).await?.into_inner();
            let (mut rows, mut affected) = (0u64, 0u64);
            while let Some(response) = stream.message().await? {
                let Some(batch) = response.batch else {
                    continue;
                };
                for doc in &batch.docs {
                    let doc = rdoc::decode(&doc.rdoc).map_err(|e| {
                        CliError(format!("the server sent an undecodable document: {e}"))
                    })?;
                    out(&to_json(&doc, mode))?;
                    rows += 1;
                }
                for w in &batch.warnings {
                    err(&format!("-- warning {}: {}", w.kind, w.message));
                }
                if let Some(stats) = &batch.stats {
                    affected += stats.docs_affected;
                }
            }
            Ok::<_, CliError>((rows, affected))
        })?;
        if rows > 0 || affected == 0 {
            err(&format!("-- {rows} row(s)"));
        }
        if affected > 0 {
            err(&format!("-- {affected} affected"));
        }
        Ok(())
    }

    /// Rolls back a transaction left open; returns whether there was one.
    fn abandon(&mut self) -> bool {
        let Some(txn_id) = self.txn.take() else {
            return false;
        };
        match self.rollback(txn_id.clone()) {
            Ok(()) => err(&format!(
                "-- transaction {txn_id} rolled back (not committed)"
            )),
            Err(e) => err(&format!("-- rollback of {txn_id} failed: {e}")),
        }
        true
    }
}

/// Runs `rustegon shell`.
///
/// # Errors
/// Connection failures; in `-c`/`--file` mode the first failed statement or a transaction left
/// open.
pub fn run(args: ShellArgs) -> CliResult<()> {
    // The script is read before connecting: a missing file must not cost a login.
    let script = match &args.file {
        Some(path) => {
            let raw = read_file(path, MAX_SCRIPT)?;
            let Ok(text) = String::from_utf8(raw.to_vec()) else {
                return fail(format!("{}: not UTF-8", path.display()));
            };
            Some(text)
        }
        None if !args.command.is_empty() => Some(args.command.join(";\n")),
        None => None,
    };
    let client = Client::connect(&args.conn)?;
    let mut session = Session {
        client,
        database: args.database.unwrap_or_default(),
        txn: None,
        mode: match args.json {
            JsonOutput::Canonical => JsonMode::Canonical,
            JsonOutput::Extended => JsonMode::Extended,
        },
    };
    let result = match script {
        Some(text) => run_script(&mut session, &text),
        None => repl(&mut session),
    };
    let Session { client, .. } = session;
    client.close();
    result
}

fn run_script(session: &mut Session, text: &str) -> CliResult<()> {
    let mut splitter = Splitter::new();
    let mut statements = splitter.feed(text);
    statements.extend(splitter.finish());
    for statement in statements {
        if let Err(e) = session.run(&statement) {
            session.abandon();
            return Err(e);
        }
    }
    if session.abandon() {
        return fail("the input ended inside a transaction; it was rolled back");
    }
    Ok(())
}

const HELP: &str = "statements end with ';'  |  BEGIN / COMMIT / ROLLBACK  |  \\c <db> switch \
                    database  |  \\q quit";

fn prompt(session: &Session, continuation: bool) {
    let db = if session.database.is_empty() {
        "rustegon"
    } else {
        &session.database
    };
    let marker = if session.txn.is_some() { "*" } else { "" };
    let text = if continuation {
        format!("{}...> ", " ".repeat(db.len() + marker.len()))
    } else {
        format!("{db}{marker}> ")
    };
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

fn repl(session: &mut Session) -> CliResult<()> {
    let terminal = io::stdin().is_terminal();
    if terminal {
        err(&format!("rustegon shell — {HELP}"));
    }
    let mut splitter = Splitter::new();
    let mut stdin = io::stdin().lock();
    let mut line = String::new();
    let mut failed = false;
    loop {
        if terminal {
            prompt(session, !splitter.is_empty());
        }
        line.clear();
        let n = stdin
            .read_line(&mut line)
            .map_err(|e| io_err("stdin", &e))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if splitter.is_empty() && trimmed.starts_with('\\') {
            let mut parts = trimmed.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("\\q"), _) => break,
                (Some("\\c"), Some(db)) => {
                    db.clone_into(&mut session.database);
                    err(&format!("-- database {db}"));
                }
                (Some("\\?"), _) => err(HELP),
                _ => err(&format!("unknown command {trimmed}; {HELP}")),
            }
            continue;
        }
        for statement in splitter.feed(&line) {
            if let Err(e) = session.run(&statement) {
                failed = true;
                err(&format!("error: {e}"));
            }
        }
    }
    if let Some(rest) = splitter.finish()
        && let Err(e) = session.run(&rest)
    {
        failed = true;
        err(&format!("error: {e}"));
    }
    let abandoned = session.abandon();
    if !terminal && (failed || abandoned) {
        // Piped input is a script: report failure through the exit code.
        return fail(if abandoned {
            "the input ended inside a transaction; it was rolled back"
        } else {
            "at least one statement failed"
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(text: &str) -> Vec<String> {
        let mut s = Splitter::new();
        let mut v = s.feed(text);
        v.extend(s.finish());
        v
    }

    #[test]
    fn fr_ql_001_splitter_honours_strings_identifiers_and_comments() {
        assert_eq!(
            split("FROM a.b; INSERT INTO a.b VALUE {s: 'x;y'};"),
            ["FROM a.b", "INSERT INTO a.b VALUE {s: 'x;y'}"]
        );
        assert_eq!(split("FROM `we;ird`.c"), ["FROM `we;ird`.c"]);
        assert_eq!(split("FROM a.b -- c; d\n;"), ["FROM a.b -- c; d"]);
        assert_eq!(split("/* ; */ FROM a.b"), ["/* ; */ FROM a.b"]);
        assert_eq!(split("VALUE 'it''s; ok'"), ["VALUE 'it''s; ok'"]);
        assert_eq!(split(r"VALUE 'a\';b'"), [r"VALUE 'a\';b'"]);
        assert_eq!(
            split(" ; -- only a comment\n ; /* x */"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn fr_ql_001_splitter_is_incremental() {
        let mut s = Splitter::new();
        assert_eq!(s.feed("FROM a.b\n"), Vec::<String>::new());
        assert!(!s.is_empty());
        assert_eq!(s.feed("LIMIT 1;\n"), ["FROM a.b\nLIMIT 1"]);
        assert!(s.is_empty());
        assert_eq!(s.feed("VALUE 'open;\n"), Vec::<String>::new());
        assert_eq!(s.feed("still';"), ["VALUE 'open;\nstill'"]);
    }

    #[test]
    fn fr_txn_001_transaction_statements_are_classified() {
        assert!(matches!(classify("BEGIN"), Action::Begin(_)));
        let Action::Begin(b) = classify("BEGIN ISOLATION LEVEL SNAPSHOT READ ONLY") else {
            panic!("not a begin");
        };
        assert_eq!(b.isolation, AstIsolation::Snapshot as i32);
        assert!(b.read_only);
        assert!(matches!(classify("commit"), Action::Commit));
        assert!(matches!(classify("ROLLBACK"), Action::Rollback));
        assert!(matches!(classify("SAVEPOINT s1"), Action::Unsupported(_)));
        assert!(matches!(classify("FROM a.b"), Action::Execute));
        assert!(matches!(classify("not rgql at all"), Action::Execute));
    }
}
