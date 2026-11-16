// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Seeded campaigns over generated cases, with reproducible failure reports.
//!
//! Case `i` of a campaign uses seed `base_seed + i`; a failure prints that seed, so
//! `RGQL_DIFF_SEED=<seed> RGQL_DIFF_CASES=1` replays exactly the failing case. The AC-QL-002 exit
//! run is `RGQL_DIFF_SECONDS=3600` (one hour of differential testing).

use std::fmt;

use super::{
    QueryEngine,
    casegen::{COLLECTION, Case, Step, generate},
    datagen::GenConfig,
    oracle::{self, Verdict},
    row_key,
};
use crate::ast::Statement;

/// Default base seed when `RGQL_DIFF_SEED` is not set.
pub const DEFAULT_SEED: u64 = 0x5EED_C0DE_0F0E_7A11;

/// How many cases a campaign runs.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Seed of case 0.
    pub base_seed: u64,
    /// Maximum number of cases.
    pub max_cases: u64,
    /// Wall-clock limit in seconds.
    pub seconds: Option<u64>,
}

impl Budget {
    /// `max_cases` cases from [`DEFAULT_SEED`].
    #[must_use]
    pub fn cases(max_cases: u64) -> Self {
        Self {
            base_seed: DEFAULT_SEED,
            max_cases,
            seconds: None,
        }
    }

    /// Budget from `RGQL_DIFF_SEED`, `RGQL_DIFF_CASES` and `RGQL_DIFF_SECONDS` (test-only
    /// knobs, hence read here rather than through the settings registry). With only a time
    /// limit the case count is unbounded.
    #[must_use]
    pub fn from_env(default_cases: u64) -> Self {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        let seconds = var("RGQL_DIFF_SECONDS");
        let max_cases = var("RGQL_DIFF_CASES").unwrap_or(if seconds.is_some() {
            u64::MAX
        } else {
            default_cases
        });
        Self {
            base_seed: var("RGQL_DIFF_SEED").unwrap_or(DEFAULT_SEED),
            max_cases,
            seconds,
        }
    }
}

/// Counters of a campaign.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Cases run.
    pub cases: u64,
    /// Statements executed through the differential oracle.
    pub statements: u64,
    /// Statements whose results were compared and agreed.
    pub agreed: u64,
    /// Statements where both sides failed with the same code.
    pub same_error: u64,
    /// Statements / checks skipped as unsupported.
    pub unsupported: u64,
    /// TLP checks that compared results.
    pub tlp: u64,
    /// `NoREC` checks that compared results.
    pub norec: u64,
}

/// A detected disagreement, with everything needed to reproduce it.
#[derive(Debug, Clone)]
pub struct Mismatch {
    /// Seed of the case.
    pub seed: u64,
    /// Index of the failing statement in the case.
    pub step: usize,
    /// Oracle that failed (`differential`, `tlp`, `norec`, `roundtrip`, `setup`).
    pub oracle: &'static str,
    /// Statement text.
    pub text: String,
    /// Parameters as extended JSON.
    pub params: String,
    /// What differed.
    pub detail: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RGQL oracle `{}` failed (seed {}, step {})\n  statement: {}\n  params: {}\n  {}\n  \
             replay: RGQL_DIFF_SEED={} RGQL_DIFF_CASES=1",
            self.oracle, self.seed, self.step, self.text, self.params, self.detail, self.seed
        )
    }
}

impl std::error::Error for Mismatch {}

/// Differential campaign: `engine` against the `reference`, plus TLP and `NoREC` on `engine`.
///
/// # Errors
/// The first [`Mismatch`].
pub fn run_differential(
    budget: &Budget,
    config: &GenConfig,
    reference: &mut dyn QueryEngine,
    engine: &mut dyn QueryEngine,
) -> Result<Stats, Mismatch> {
    campaign(budget, config, |case, stats| {
        differential_case(case, reference, engine, stats)
    })
}

/// TLP and `NoREC` campaign on one engine (no second engine needed).
///
/// # Errors
/// The first [`Mismatch`].
pub fn run_self_oracles(
    budget: &Budget,
    config: &GenConfig,
    engine: &mut dyn QueryEngine,
) -> Result<Stats, Mismatch> {
    campaign(budget, config, |case, stats| {
        self_oracle_case(case, engine, stats)
    })
}

#[allow(clippy::disallowed_methods)] // Wall-clock budget of a test campaign, not engine time.
fn campaign(
    budget: &Budget,
    config: &GenConfig,
    mut per_case: impl FnMut(&Case, &mut Stats) -> Result<(), Mismatch>,
) -> Result<Stats, Mismatch> {
    let start = std::time::Instant::now();
    let mut stats = Stats::default();
    for i in 0..budget.max_cases {
        if budget
            .seconds
            .is_some_and(|s| start.elapsed().as_secs() >= s)
        {
            break;
        }
        let case = generate(budget.base_seed.wrapping_add(i), config);
        per_case(&case, &mut stats)?;
        stats.cases += 1;
    }
    Ok(stats)
}

fn mismatch(case: &Case, step: usize, oracle: &'static str, detail: String) -> Mismatch {
    let (text, params) = case.steps.get(step).map_or_else(
        || (String::new(), String::new()),
        |s| {
            let params: Vec<String> = s
                .params
                .iter()
                .map(|(k, v)| format!("${k} = {}", row_key(v)))
                .collect();
            (s.text.clone(), params.join(", "))
        },
    );
    Mismatch {
        seed: case.seed,
        step,
        oracle,
        text,
        params,
        detail,
    }
}

fn setup(case: &Case, engine: &mut dyn QueryEngine) -> Result<(), Mismatch> {
    engine
        .reset()
        .and_then(|()| engine.load(COLLECTION, &case.documents))
        .map_err(|e| mismatch(case, 0, "setup", format!("{}: {e}", engine.name())))
}

fn statement<'c>(case: &Case, i: usize, step: &'c Step) -> Result<&'c Statement, Mismatch> {
    step.statement.as_ref().map_err(|e| {
        mismatch(
            case,
            i,
            "roundtrip",
            format!("printed text does not parse: {e}"),
        )
    })
}

/// One case through the differential oracle (and TLP/`NoREC` on `engine`).
///
/// # Errors
/// The first [`Mismatch`].
pub fn differential_case(
    case: &Case,
    reference: &mut dyn QueryEngine,
    engine: &mut dyn QueryEngine,
    stats: &mut Stats,
) -> Result<(), Mismatch> {
    setup(case, reference)?;
    setup(case, engine)?;
    for (i, step) in case.steps.iter().enumerate() {
        let stmt = statement(case, i, step)?;
        stats.statements += 1;
        let verdict = oracle::differential(reference, engine, stmt, &step.params)
            .map_err(|d| mismatch(case, i, "differential", d))?;
        count(stats, verdict);
        if verdict == Verdict::Unsupported && !matches!(stmt, Statement::Query(_)) {
            // A write skipped on one side only would leave the states diverged.
            break;
        }
        partition_oracles(case, i, step, engine, stats)?;
    }
    Ok(())
}

/// One case through TLP and `NoREC` only; writes are executed to evolve the state.
///
/// # Errors
/// The first [`Mismatch`].
pub fn self_oracle_case(
    case: &Case,
    engine: &mut dyn QueryEngine,
    stats: &mut Stats,
) -> Result<(), Mismatch> {
    setup(case, engine)?;
    for (i, step) in case.steps.iter().enumerate() {
        let stmt = statement(case, i, step)?;
        stats.statements += 1;
        if matches!(stmt, Statement::Query(_)) {
            partition_oracles(case, i, step, engine, stats)?;
        } else {
            // The outcome is irrelevant here; only the state change matters.
            let _ = engine.run(stmt, &step.params);
        }
    }
    Ok(())
}

fn partition_oracles(
    case: &Case,
    i: usize,
    step: &Step,
    engine: &mut dyn QueryEngine,
    stats: &mut Stats,
) -> Result<(), Mismatch> {
    let (Ok(Statement::Query(q)), Some(p)) = (&step.statement, &step.predicate) else {
        return Ok(());
    };
    let v = oracle::tlp(engine, q, p, &step.params).map_err(|d| mismatch(case, i, "tlp", d))?;
    if v == Verdict::Agreed {
        stats.tlp += 1;
    }
    let v = oracle::norec(engine, q, p, &step.params).map_err(|d| mismatch(case, i, "norec", d))?;
    if v == Verdict::Agreed {
        stats.norec += 1;
    }
    Ok(())
}

fn count(stats: &mut Stats, v: Verdict) {
    match v {
        Verdict::Agreed => stats.agreed += 1,
        Verdict::SameError => stats.same_error += 1,
        Verdict::Unsupported => stats.unsupported += 1,
    }
}
