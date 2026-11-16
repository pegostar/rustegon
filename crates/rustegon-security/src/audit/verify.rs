// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Offline verification of a node's audit chain (`rustegon audit verify`, security.md §4).
//!
//! Detects any edited, removed, inserted or reordered line and any removed or renamed segment
//! *between* the first and the last record present. What a hash chain alone cannot detect, and
//! the report therefore exposes for external anchoring (PD-048): removal of a suffix (compare
//! [`VerifyReport::last_seq`] / [`VerifyReport::head_hash`] with a previously anchored value),
//! removal of a prefix (reported as [`VerifyReport::first_seq`] > 1, which is also what
//! retention produces), and a rewrite of the whole chain by someone with write access to every
//! file (the chain is unkeyed).

use std::path::Path;

use rustegon_sim_api::FileSystem;

use super::{
    AuditError, ChainFault,
    log::{check_lines, complete_prefix, list_segments, read_all},
    record::GENESIS_HASH,
};

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Segment files checked.
    pub files: usize,
    /// Records checked.
    pub records: u64,
    /// Sequence number of the first record present (1 unless retention removed segments).
    pub first_seq: u64,
    /// Sequence number of the last record (0 for an empty log).
    pub last_seq: u64,
    /// Hash of the last record ([`GENESIS_HASH`] for an empty log).
    pub head_hash: String,
    /// The newest segment ends with a newline-less tail (an unsynced append, repaired by the
    /// next [`super::AuditLog::open`]).
    pub torn_tail: bool,
}

/// Verifies every segment of `dir` in sequence order.
///
/// # Errors
/// I/O errors; [`AuditError::Corrupt`] at the first line that breaks the chain.
pub fn verify_dir(fs: &dyn FileSystem, dir: &Path) -> Result<VerifyReport, AuditError> {
    let segments = list_segments(fs, dir)?;
    let mut report = VerifyReport {
        files: segments.len(),
        records: 0,
        first_seq: 0,
        last_seq: 0,
        head_hash: GENESIS_HASH.to_owned(),
        torn_tail: false,
    };
    let mut prev: Option<(u64, String)> = None;
    let count = segments.len();
    for (i, (first_seq, path)) in segments.iter().enumerate() {
        let bytes = read_all(fs, path)?;
        let (prefix, torn) = complete_prefix(&bytes);
        let newest = i + 1 == count;
        if torn > 0 {
            if !newest {
                return Err(AuditError::Corrupt {
                    path: path.clone(),
                    // Lines of the complete prefix plus the torn one.
                    line: prefix.split(|&b| b == b'\n').count(),
                    fault: ChainFault::TornTail,
                });
            }
            report.torn_tail = true;
        }
        let expected_prev = match &prev {
            Some((last_seq, hash)) => {
                // A missing segment shows up as a gap between the last record of the previous
                // segment and the first record (= file name) of this one.
                if *first_seq != last_seq.saturating_add(1) {
                    return Err(AuditError::Corrupt {
                        path: path.clone(),
                        line: 1,
                        fault: ChainFault::SeqMismatch {
                            expected: last_seq.saturating_add(1),
                            found: *first_seq,
                        },
                    });
                }
                Some(hash.clone())
            }
            // The very first record of a node starts from the genesis hash; a later first
            // record (retention) is accepted as the anchor.
            None if *first_seq == 1 => Some(GENESIS_HASH.to_owned()),
            None => None,
        };
        match check_lines(path, prefix, *first_seq, expected_prev.as_deref())? {
            Some((last_seq, hash)) => {
                if prev.is_none() {
                    report.first_seq = *first_seq;
                }
                report.records += last_seq - first_seq + 1;
                report.last_seq = last_seq;
                report.head_hash.clone_from(&hash);
                prev = Some((last_seq, hash));
            }
            // Only the newest segment can be empty (rotation crashed before its first record).
            None if newest => {}
            None => {
                return Err(AuditError::Corrupt {
                    path: path.clone(),
                    line: 1,
                    fault: ChainFault::Malformed("empty sealed segment".into()),
                });
            }
        }
    }
    Ok(report)
}
