// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Heap diagnostics of a running node (PD-233, feature `heap-stats`): the soak's working set
//! holds 150–370 MiB that neither the block cache nor the memtables account for. A counting
//! allocator says how much of the working set is live and in allocations of which size; the
//! rest is memory the node's allocator keeps. [`log`] writes it as one `heap summary` line.
//!
//! Diagnostic builds only: every allocation pays two atomic updates on shared counters.

use std::{
    alloc::{GlobalAlloc, Layout},
    fmt::Write as _,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::allocator::NodeAlloc;

/// Size classes: class `c` holds the allocations of `2^(c-1) <= size < 2^c` bytes.
const CLASSES: usize = 40;
/// Live bytes and live allocations of every class.
static LIVE: [[AtomicUsize; 2]; CLASSES] = [const { [const { AtomicUsize::new(0) }; 2] }; CLASSES];

fn class(size: usize) -> usize {
    (size.bit_width() as usize).min(CLASSES - 1)
}

fn add(size: usize) {
    let live = &LIVE[class(size)];
    live[0].fetch_add(size, Ordering::Relaxed);
    live[1].fetch_add(1, Ordering::Relaxed);
}

fn sub(size: usize) {
    let live = &LIVE[class(size)];
    live[0].fetch_sub(size, Ordering::Relaxed);
    live[1].fetch_sub(1, Ordering::Relaxed);
}

struct Counting;

// SAFETY: every call is forwarded to the node's allocator with the same arguments; the
// counters do not affect allocation.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as `NodeAlloc.alloc`.
        let p = unsafe { NodeAlloc.alloc(layout) };
        if !p.is_null() {
            add(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as `NodeAlloc.alloc_zeroed`.
        let p = unsafe { NodeAlloc.alloc_zeroed(layout) };
        if !p.is_null() {
            add(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as `NodeAlloc.dealloc`.
        unsafe { NodeAlloc.dealloc(ptr, layout) };
        sub(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as `NodeAlloc.realloc`.
        let p = unsafe { NodeAlloc.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            sub(layout.size());
            add(new_size);
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Logs the live heap: bytes and allocations in total, and `class:bytes/count` for every class
/// in use (module docs).
pub fn log() {
    let mut by_class = String::new();
    let (mut bytes, mut count) = (0, 0);
    for (class, live) in LIVE.iter().enumerate() {
        let (b, n) = (
            live[0].load(Ordering::Relaxed),
            live[1].load(Ordering::Relaxed),
        );
        if n > 0 {
            let _ = write!(by_class, "{class}:{b}/{n} ");
        }
        bytes += b;
        count += n;
    }
    tracing::info!(
        live_bytes = bytes,
        live_count = count,
        by_class = by_class.trim_end(),
        "heap summary"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PD-233: an allocation is counted in the class of its size while it lives.
    #[test]
    fn pd_233_live_heap_is_counted_by_size_class() {
        assert_eq!(
            [0, 1, 4095, 4096, 8191, 8192].map(class),
            [0, 1, 12, 13, 13, 14]
        );
        // A class no other test allocates in (128-256 MiB), so it holds this buffer alone.
        let size = (1 << 27) + 17;
        let before = LIVE[class(size)][0].load(Ordering::Relaxed);
        let buffer = Vec::<u8>::with_capacity(size);
        assert_eq!(LIVE[class(size)][0].load(Ordering::Relaxed), before + size);
        drop(buffer);
        assert_eq!(LIVE[class(size)][0].load(Ordering::Relaxed), before);
    }
}
