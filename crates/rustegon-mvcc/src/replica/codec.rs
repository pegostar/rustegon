// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Big-endian helpers shared by the replica formats (command v1, `RangeAppliedState` v1). They
//! follow the conventions of the MVCC value encodings (transaction-management.md §3): fixed-width
//! big-endian integers, `bytes = len u32 ‖ bytes`, every decode bounds-checked.

use crate::{
    error::{MvccError, Result},
    hlc::Timestamp,
};

/// Appends `v` as `u32 BE`.
pub(super) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Appends `v` as `u64 BE`.
pub(super) fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Appends `len u32 BE ‖ b`.
///
/// # Errors
/// [`MvccError::InvalidArgument`] when `b` is 4 GiB or longer (it cannot be encoded; batches
/// are bounded far below that by the transaction limits, §11).
pub(super) fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    let len = u32::try_from(b.len())
        .map_err(|_| MvccError::InvalidArgument("byte string of 4 GiB or more".into()))?;
    put_u32(out, len);
    out.extend_from_slice(b);
    Ok(())
}

/// Bounds-checked big-endian decoder over a borrowed buffer; every error is
/// [`MvccError::Corruption`] naming `what`.
pub(super) struct Reader<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(super) fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, what }
    }

    pub(super) fn corruption(&self, reason: &str) -> MvccError {
        MvccError::Corruption(format!("{}: {reason}", self.what))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(self.corruption("truncated"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(super) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(super) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn ts(&mut self) -> Result<Timestamp> {
        Ok(Timestamp::from_be_bytes(self.array()?))
    }

    pub(super) fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// A count of items each at least `min_item` bytes long; a count the remaining input cannot
    /// hold is rejected, so a corrupt count never triggers a huge allocation.
    pub(super) fn count(&mut self, min_item: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_item) > self.buf.len() {
            return Err(self.corruption("count too large"));
        }
        Ok(n)
    }

    pub(super) fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(self.corruption("trailing bytes"))
        }
    }
}
