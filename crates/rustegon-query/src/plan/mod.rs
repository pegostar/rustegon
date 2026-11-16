// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Planning (query-engine.md §1–§4): rule rewrites, logical plans, access-path analysis and
//! physical plans.

pub mod access;
pub mod cbo;
pub mod logical;
pub mod physical;
pub mod rewrite;

pub use self::{
    access::KeyRange,
    cbo::CostBasedChooser,
    logical::LogicalPlan,
    physical::{
        AccessPath, AccessPathChooser, Candidate, OrderStrategy, PhysicalPlan, PlanEstimate,
        RuleBasedChooser, plan_query,
    },
};
