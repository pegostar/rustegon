// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegond --service`: the node as the Windows service `Rustegon` (windows.md §3, PD-054,
//! PD-206).
//!
//! The process is started by the Service Control Manager with the command line the installer
//! registered (`--service --config <file>`). [`run`] hands the main thread to the SCM
//! dispatcher; the SCM calls `service_main` on another thread, which reports `START_PENDING`,
//! runs the node exactly like the console mode and reports `RUNNING` once both listeners are
//! bound (the `ready` line). Stop, shutdown and preshutdown controls send the stop reason into
//! the same graceful shutdown path as Ctrl-C (`signals`), reporting `STOP_PENDING` with a wait
//! hint meanwhile; the exit is reported as `STOPPED` (service-specific exit code 2 when the
//! node failed, the reason being in the log file, since a service has no console).

#[cfg(windows)]
use std::time::Duration;

/// Name of the Windows service, as registered by the MSI.
#[cfg(windows)]
pub const SERVICE_NAME: &str = "Rustegon";
/// Wait hint while starting: opening a large store replays its log.
#[cfg(windows)]
pub const START_WAIT_HINT: Duration = Duration::from_secs(120);
/// Wait hint while stopping: drain (`listen.shutdown_grace_secs`, default 30 s) plus the
/// shutdown checkpoint and the PITR final pass (windows.md §3: ≤ 60 s drain).
#[cfg(windows)]
pub const STOP_WAIT_HINT: Duration = Duration::from_secs(90);

/// The SCM controls that stop the node, and the reason logged for each.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// `SERVICE_CONTROL_STOP` (`Stop-Service`, `sc stop`, the installer).
    Stop,
    /// `SERVICE_CONTROL_PRESHUTDOWN` (system shutdown, with the preshutdown timeout).
    Preshutdown,
    /// `SERVICE_CONTROL_SHUTDOWN` (system shutdown, when preshutdown was not delivered).
    Shutdown,
}

#[cfg(windows)]
impl Control {
    /// The shutdown reason for the log.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Stop => "service stop",
            Self::Preshutdown => "system preshutdown",
            Self::Shutdown => "system shutdown",
        }
    }
}

#[cfg(windows)]
pub use imp::run;

/// Without an SCM there is no service mode.
///
/// # Errors
/// Always.
#[cfg(not(windows))]
pub fn run(_args: crate::Args) -> rustegon_common::Result<()> {
    Err(rustegon_common::Error::new(
        rustegon_common::ErrorCode::InvalidArgument,
        "--service is only available on Windows (use the systemd unit on Linux)",
    ))
}

#[cfg(windows)]
mod imp {
    use std::{
        ffi::OsString,
        sync::{Mutex, OnceLock},
        time::Duration,
    };

    use rustegon_common::{Error, ErrorCode, Result};
    use tokio::sync::oneshot;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
    };

    use super::{Control, SERVICE_NAME, START_WAIT_HINT, STOP_WAIT_HINT};

    /// The parsed command line, handed from `main` to `service_main` (the SCM passes only the
    /// start parameters, not the registered command line).
    static ARGS: Mutex<Option<crate::Args>> = Mutex::new(None);
    /// The outcome of the node, read by `run` after the dispatcher returns.
    static OUTCOME: OnceLock<std::result::Result<(), String>> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Runs the node under the SCM (module docs); returns when the service has stopped.
    ///
    /// # Errors
    /// Not started by the SCM (e.g. run from a console), or the node failed.
    pub fn run(args: crate::Args) -> Result<()> {
        *ARGS
            .lock()
            .map_err(|_| internal("service arguments lock poisoned"))? = Some(args);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "cannot connect to the Service Control Manager ({e}); --service is for the \
                     Windows service `{SERVICE_NAME}` only, run without it in a console"
                ),
            )
        })?;
        match OUTCOME.get() {
            Some(Err(e)) => Err(Error::new(ErrorCode::Internal, e.clone())),
            _ => Ok(()),
        }
    }

    fn internal(message: &str) -> Error {
        Error::new(ErrorCode::Internal, message.to_owned())
    }

    fn control_of(control: ServiceControl) -> Option<Control> {
        match control {
            ServiceControl::Stop => Some(Control::Stop),
            ServiceControl::Preshutdown => Some(Control::Preshutdown),
            ServiceControl::Shutdown => Some(Control::Shutdown),
            _ => None,
        }
    }

    fn status(state: ServiceState, wait_hint: Duration, exit: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
                    | ServiceControlAccept::SHUTDOWN
                    | ServiceControlAccept::PRESHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: if exit == 0 {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(exit)
            },
            checkpoint: 0,
            wait_hint,
            process_id: None,
        }
    }

    fn report(handle: ServiceStatusHandle, state: ServiceState, wait_hint: Duration, exit: u32) {
        // A failed report cannot be reported anywhere but the log.
        if let Err(e) = handle.set_service_status(status(state, wait_hint, exit)) {
            tracing::error!(error = %e, "cannot report the service status to the SCM");
        }
    }

    fn service_main(_start_parameters: Vec<OsString>) {
        let outcome = serve();
        let _ = OUTCOME.set(outcome.map_err(|e| e.to_string()));
    }

    fn serve() -> Result<()> {
        let args = ARGS
            .lock()
            .map_err(|_| internal("service arguments lock poisoned"))?
            .take()
            .ok_or_else(|| internal("service started twice"))?;
        let (stop_tx, stop_rx) = oneshot::channel::<&'static str>();
        let stop_tx = Mutex::new(Some(stop_tx));
        let handle_cell: std::sync::Arc<OnceLock<ServiceStatusHandle>> = std::sync::Arc::default();
        let cell = std::sync::Arc::clone(&handle_cell);
        let handle = service_control_handler::register(SERVICE_NAME, move |control| {
            match control_of(control) {
                Some(c) => {
                    // Only the first stop control counts; later ones find the sender gone.
                    if let Some(tx) = stop_tx.lock().ok().and_then(|mut g| g.take()) {
                        if let Some(h) = cell.get() {
                            report(*h, ServiceState::StopPending, STOP_WAIT_HINT, 0);
                        }
                        let _ = tx.send(c.reason());
                    }
                    ServiceControlHandlerResult::NoError
                }
                None if control == ServiceControl::Interrogate => {
                    ServiceControlHandlerResult::NoError
                }
                None => ServiceControlHandlerResult::NotImplemented,
            }
        })
        .map_err(|e| internal(&format!("cannot register the service control handler: {e}")))?;
        let _ = handle_cell.set(handle);
        report(handle, ServiceState::StartPending, START_WAIT_HINT, 0);
        let result = crate::run(
            args,
            crate::Supervisor {
                stop: Some(stop_rx),
                on_ready: Some(Box::new(move || {
                    report(handle, ServiceState::Running, Duration::ZERO, 0);
                })),
            },
        );
        report(
            handle,
            ServiceState::Stopped,
            Duration::ZERO,
            if result.is_ok() { 0 } else { 2 },
        );
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// TC-INS-014: every stop-like SCM control maps to a graceful shutdown with its reason;
        /// anything else is not a stop.
        #[test]
        fn tc_ins_014_scm_controls_map_to_shutdown_reasons() {
            assert_eq!(control_of(ServiceControl::Stop), Some(Control::Stop));
            assert_eq!(
                control_of(ServiceControl::Preshutdown),
                Some(Control::Preshutdown)
            );
            assert_eq!(
                control_of(ServiceControl::Shutdown),
                Some(Control::Shutdown)
            );
            assert_eq!(control_of(ServiceControl::Interrogate), None);
            assert_eq!(control_of(ServiceControl::Pause), None);
        }

        /// TC-INS-014: only a running service accepts stop controls, and a failed node reports
        /// a service-specific exit code.
        #[test]
        fn tc_ins_014_status_reports() {
            let running = status(ServiceState::Running, Duration::ZERO, 0);
            assert!(
                running
                    .controls_accepted
                    .contains(ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN)
            );
            let pending = status(ServiceState::StartPending, START_WAIT_HINT, 0);
            assert!(pending.controls_accepted.is_empty());
            assert_eq!(pending.wait_hint, START_WAIT_HINT);
            let failed = status(ServiceState::Stopped, Duration::ZERO, 2);
            assert_eq!(failed.exit_code, ServiceExitCode::ServiceSpecific(2));
        }

        /// TC-INS-014: started from a console, `--service` fails with a clear error instead of
        /// hanging (the dispatcher refuses a process the SCM did not start).
        #[test]
        fn tc_ins_014_service_mode_outside_the_scm_is_refused() {
            use clap::Parser as _;
            let args = crate::Args::try_parse_from(["rustegond", "--service"]).unwrap();
            let e = run(args).unwrap_err();
            assert!(e.to_string().contains("Service Control Manager"), "{e}");
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::Control;

    #[test]
    fn tc_ins_014_stop_reasons_are_distinct() {
        let reasons = [Control::Stop, Control::Preshutdown, Control::Shutdown].map(Control::reason);
        assert_eq!(
            reasons,
            ["service stop", "system preshutdown", "system shutdown"]
        );
    }
}
