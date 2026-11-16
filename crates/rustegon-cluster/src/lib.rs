// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cluster membership: gossip, liveness, meta ranges, range cache, routing, allocation, splits and merges.
//!
//! M2 provides the Raft-less single-voter [`LocalReplica`] implementing
//! [`rustegon_mvcc::Replica`]; the Raft replica and the cluster services arrive in M5/M6.

pub mod local_replica;

pub use local_replica::{
    CHECKPOINT_FLUSH_ATTEMPTS, LOCAL_REPLICA_ID, LOCAL_TERM, LocalReplica, LocalReplicaConfig,
    ReplicaCheckpoint,
};
