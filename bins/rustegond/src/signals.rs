// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process signals of the daemon (PD-054).
//!
//! | Platform | Graceful shutdown | Certificate reload |
//! |---|---|---|
//! | Unix | SIGTERM, SIGINT | SIGHUP |
//! | Windows | Ctrl-C, Ctrl-Break, console close, system shutdown | change check only |
//!
//! Optionally (`--stop-on-stdin-eof`) the end of standard input also requests a shutdown: a
//! supervisor or test harness that owns the pipe can stop the server gracefully on every
//! platform (Windows has no signal a parent can send to a console-less child).

use std::{io::Read as _, sync::Arc};

use tokio::sync::{Notify, oneshot};

/// Installed signal handlers. Installed before the server reports ready, so a signal sent
/// right after readiness is never handled by the default action (immediate termination).
pub struct Signals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hup: tokio::signal::unix::Signal,
    #[cfg(windows)]
    interrupt: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    brk: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    shutdown: tokio::signal::windows::CtrlShutdown,
}

impl Signals {
    /// Installs the handlers. Must run inside the Tokio runtime.
    ///
    /// # Errors
    /// The handlers cannot be installed.
    #[cfg(unix)]
    pub fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
            hup: signal(SignalKind::hangup())?,
        })
    }

    /// Installs the handlers. Must run inside the Tokio runtime.
    ///
    /// # Errors
    /// The handlers cannot be installed.
    #[cfg(windows)]
    pub fn install() -> std::io::Result<Self> {
        use tokio::signal::windows;
        Ok(Self {
            interrupt: windows::ctrl_c()?,
            brk: windows::ctrl_break()?,
            close: windows::ctrl_close()?,
            shutdown: windows::ctrl_shutdown()?,
        })
    }

    /// Waits until a shutdown is requested (an OS signal, or `stop`: stdin EOF or the Windows
    /// service, with its reason); SIGHUP (Unix) notifies `reload` meanwhile.
    /// Returns the reason, for the log.
    pub async fn wait_for_shutdown(
        mut self,
        reload: Arc<Notify>,
        stop: Option<oneshot::Receiver<&'static str>>,
    ) -> &'static str {
        let stop = async move {
            match stop {
                // A dropped sender (stdin reader thread gone without EOF) also means stop.
                Some(rx) => rx.await.unwrap_or("stop channel closed"),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            reason = self.os_signal(reload) => reason,
            reason = stop => reason,
        }
    }

    #[cfg(unix)]
    async fn os_signal(&mut self, reload: Arc<Notify>) -> &'static str {
        loop {
            tokio::select! {
                _ = self.term.recv() => return "SIGTERM",
                _ = self.int.recv() => return "SIGINT",
                _ = self.hup.recv() => reload.notify_one(),
            }
        }
    }

    #[cfg(windows)]
    async fn os_signal(&mut self, reload: Arc<Notify>) -> &'static str {
        // No SIGHUP equivalent: certificate changes are found by the change check.
        drop(reload);
        tokio::select! {
            _ = self.interrupt.recv() => "Ctrl-C",
            _ = self.brk.recv() => "Ctrl-Break",
            _ = self.close.recv() => "console closed",
            _ = self.shutdown.recv() => "system shutdown",
        }
    }
}

/// Starts a thread reading standard input to its end; the receiver completes at EOF. A
/// dedicated OS thread, because reading stdin blocks and must not occupy an async worker or
/// the bounded blocking pool for the process lifetime.
///
/// # Errors
/// The thread cannot be spawned.
pub fn stdin_eof() -> std::io::Result<oneshot::Receiver<&'static str>> {
    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("stdin-eof".into())
        .spawn(move || {
            let mut sink = [0u8; 256];
            let mut stdin = std::io::stdin().lock();
            loop {
                match stdin.read(&mut sink) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = tx.send("standard input closed");
        })?;
    Ok(rx)
}
