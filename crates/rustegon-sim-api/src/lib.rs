// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! I/O abstraction traits (`Clock`, `Rng`, `FileSystem`, `Network`, `Spawner`) and their
//! production implementations; simulation implementations live in `rustegon-sim` (ADR-029).
//!
//! Every component receives these traits by injection instead of calling the OS directly, so
//! `rustegon-sim` can run whole clusters deterministically from a seed. Direct use of OS time,
//! randomness or sockets elsewhere is rejected by `clippy.toml` (`disallowed-methods`); this crate
//! is the only place allowed to call them, and only inside the production implementations.

use std::{future::Future, pin::Pin};

pub mod clock;
pub mod fs;
pub mod net;
pub mod rng;
pub mod spawn;

pub use clock::{Clock, SystemClock};
pub use fs::{File, FileLock, FileSystem, OpenMode, StdFileSystem};
pub use net::{Connection, Listener, Network, TokioNetwork};
pub use rng::{OsRng, Rng};
pub use spawn::{JoinHandle, Spawner, TaskError, TokioSpawner};

/// Boxed, sendable future: keeps the traits object-safe (`Arc<dyn Clock>` etc.).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
