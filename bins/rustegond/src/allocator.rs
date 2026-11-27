// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The node's memory allocator (database-engine.md §5, PD-010).
//!
//! Windows: mimalloc. The process heap kept the memory the node freed: in the R1 soak the
//! working set stood 170–250 MiB above the live heap and did not follow it down when a memtable
//! was dropped (PD-233). Elsewhere the system allocator; jemalloc on Linux waits for the M15
//! benchmark (PD-010).

#[cfg(windows)]
pub(crate) use mimalloc::MiMalloc as NodeAlloc;
#[cfg(not(windows))]
pub(crate) use std::alloc::System as NodeAlloc;

// With `heap-stats` the counting allocator of `heap_stats` is the global one and forwards here.
#[cfg(not(feature = "heap-stats"))]
#[global_allocator]
static GLOBAL: NodeAlloc = NodeAlloc;

#[cfg(all(test, windows))]
mod tests {
    /// PD-010, PD-233: on Windows the node's allocations come from mimalloc.
    #[test]
    fn pd_010_windows_node_allocates_from_mimalloc() {
        let boxed = Box::new([0_u8; 4096]);
        // SAFETY: the call only looks the address up in mimalloc's own page map.
        assert!(unsafe { libmimalloc_sys::mi_is_in_heap_region((&raw const *boxed).cast()) });
    }
}
