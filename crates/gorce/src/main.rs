#![forbid(unsafe_code)]

use std::process::Command;
use std::sync::mpsc::{RecvTimeoutError, TrySendError};
use std::time::Duration;

use gorce_sdk::{
    run_diagnostics, CancellationToken, Client, DiagnosticOptions, EventStreamItem,
    EventStreamLifecycle, EventStreamOptions, EventStreamUpdate, LazyDaemon, ProcessLauncher,
    ProjectId, PublicEvent, ReconciliationMode as SdkReconciliationMode, RetrySignal, SdkError,
};
use gorce_tui::{
    App, ConfirmedEvent, ConfirmedEventId, ConfirmedPresentation, ConfirmedPresentationKind,
    ConfirmedTimestamp, ConnectionEvent, CrosstermInput, CrosstermSurface, LocalNotice,
    LocalNoticeKind, OfflineReason, ReconciliationMode as TuiReconciliationMode, Retryability,
    TerminalRunner, UiCapabilities, UiEvent, UiEventSender, UiIntent, UiIntentReceiver,
};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Json,
    Ndjson,
}

#[derive(Debug)]
struct Cli {
    command: CommandLine,
    output: OutputMode,
}

#[derive(Debug)]
enum CommandLine {
    Help,
    Version,
    Init,
    Daemon {
        action: String,
    },
    Doctor {
        project: Option<String>,
    },
    StoreVerify,
    IndexRebuild,
    Run {
        project: Option<String>,
        name: String,
        arguments: Value,
    },
    Attach {
        project: ProjectId,
    },
}

fn main() {
    let cli = match parse_args(std::env::args().skip(1).collect()) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("gorce: {error}");
            std::process::exit(2);
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("gorce: cannot initialize runtime: {error}");
            std::process::exit(1);
        }
    };
    let output = cli.output;
    if let Err(error) = runtime.block_on(run(cli)) {
        if output == OutputMode::Human {
            eprintln!("gorce: {error}");
        } else {
            println!(
                "{}",
                json!({"event": "error", "data": {"message": error.to_string()}})
            );
        }
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), SdkError> {
    match cli.command {
        CommandLine::Help => println!("{}", usage()),
        CommandLine::Version => println!("{}", gorce_sdk::SDK_VERSION),
        CommandLine::Init => {
            return Err(SdkError::Unsupported(
                "project creation is not exposed by the current daemon".to_owned(),
            ));
        }
        CommandLine::Daemon { action } => match action.as_str() {
            "status" => {
                let client = attach().await?;
                let health = client.health().await?;
                let status = health.status;
                let version = if health.version == "unknown" {
                    client
                        .meta()
                        .await
                        .map(|meta| meta.daemon_version)
                        .unwrap_or(health.version)
                } else {
                    health.version
                };
                emit(
                    cli.output,
                    "daemon.status",
                    json!({"status": status, "version": version, "endpoint": client.endpoint()}),
                    format!("daemon is {:?} ({})", status, version),
                );
            }
            "stop" => {
                return Err(SdkError::Unsupported(
                    "daemon stop is not exposed by the current daemon".to_owned(),
                ));
            }
            "foreground" => run_foreground(cli.output).await?,
            _ => {
                return Err(SdkError::InvalidConfiguration(
                    "daemon action must be foreground, status, or stop".to_owned(),
                ))
            }
        },
        CommandLine::Doctor { project } => {
            let project_id = project
                .as_deref()
                .map(gorce_sdk::parse_project_id)
                .transpose()?;
            let report = run_diagnostics(DiagnosticOptions {
                project_id,
                ..DiagnosticOptions::default()
            })
            .await;
            let healthy = report.is_healthy();
            if cli.output == OutputMode::Human {
                for check in &report.checks {
                    println!("{:?}: {} - {}", check.status, check.name, check.message);
                }
            } else {
                emit(
                    cli.output,
                    "doctor.report",
                    json!({"checks": &report.checks}),
                    String::new(),
                );
            }
            if !healthy {
                return Err(SdkError::Unsupported(
                    "doctor found failing checks".to_owned(),
                ));
            }
        }
        CommandLine::StoreVerify => {
            return Err(SdkError::Unsupported(
                "store verification is not exposed by the current daemon".to_owned(),
            ));
        }
        CommandLine::IndexRebuild => {
            return Err(SdkError::Unsupported(
                "index rebuild is not exposed by the current daemon".to_owned(),
            ));
        }
        CommandLine::Run {
            project,
            name,
            arguments,
        } => {
            let _ = (project, name, arguments);
            return Err(SdkError::Unsupported(
                "command execution is not exposed by the current daemon".to_owned(),
            ));
        }
        CommandLine::Attach { project } => run_attach(project).await?,
    }
    Ok(())
}

async fn attach() -> Result<Client, SdkError> {
    let daemon = LazyDaemon::default();
    if let Some(program) = std::env::var_os("GORCE_DAEMON_BIN") {
        daemon
            .with_launcher(ProcessLauncher::new(program).arg("foreground"))
            .client()
            .await
    } else {
        daemon.client().await
    }
}

const UI_CHANNEL_CAPACITY: usize = 128;
const STREAM_OFFLINE_REASON: &str = "event stream is unavailable";
const EVENT_MAPPING_NOTICE: &str =
    "A daemon event could not be displayed; the read-only stream was stopped.";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct TimestampState {
    committed: Option<ConfirmedTimestamp>,
    staged: Option<ConfirmedTimestamp>,
    reconciliation_active: bool,
}

impl TimestampState {
    fn begin_reconciliation(&mut self, mode: SdkReconciliationMode) {
        self.reconciliation_active = true;
        self.staged = match mode {
            SdkReconciliationMode::Delta => self.committed.clone(),
            SdkReconciliationMode::Replace => None,
        };
    }

    fn record_confirmed(&mut self, confirmed_at: ConfirmedTimestamp) {
        if self.reconciliation_active {
            self.staged = Some(confirmed_at);
        } else {
            self.committed = Some(confirmed_at);
        }
    }

    fn promote_staged(&mut self) {
        if self.reconciliation_active {
            self.committed = self.staged.take();
            self.reconciliation_active = false;
        }
    }

    fn discard_staged(&mut self) {
        self.staged = None;
        self.reconciliation_active = false;
    }

    fn restore(&mut self, previous: Self) {
        *self = previous;
    }
}

/// Run the read-only composition lane. The SDK client, credentials, and
/// stream remain in this crate; only typed UI DTOs cross into the TUI.
async fn run_attach(project: ProjectId) -> Result<(), SdkError> {
    let client = attach().await?;
    let cancellation = CancellationToken::new();
    let retry_signal = RetrySignal::new();
    let (events_tx, events_rx, intents_tx, intents_rx) = gorce_tui::channels(UI_CHANNEL_CAPACITY);
    let stream = client.event_stream_with_options(
        project,
        None,
        EventStreamOptions {
            // A terminal failure leaves the user with an inspectable offline
            // view instead of an indefinitely retrying terminal session.
            max_reconnects: Some(3),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            cancellation: Some(cancellation.clone()),
            retry_signal: Some(retry_signal.clone()),
        },
    );
    let pump_cancellation = cancellation.clone();
    let pump = tokio::spawn(async move {
        pump_event_stream(stream, events_tx, pump_cancellation).await;
    });
    let intent_cancellation = cancellation.clone();
    let intent_forwarder = tokio::task::spawn_blocking(move || {
        forward_ui_intents(intents_rx, retry_signal, intent_cancellation);
    });

    // Crossterm terminal ownership and all terminal I/O stay on the blocking
    // side. The async runtime remains free to advance the SDK stream pump.
    let terminal = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let surface = CrosstermSurface::new()?;
        let input = CrosstermInput;
        let mut runner = TerminalRunner::new(surface, input, events_rx, intents_tx);
        let mut app = App::default();
        app.set_capabilities(UiCapabilities::READ_ONLY);
        runner.run(&mut app)
    });

    let terminal_result = match terminal.await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("terminal task failed")),
    };
    cancellation.cancel();
    let (pump_result, intent_result) = tokio::join!(pump, intent_forwarder);

    if pump_result.is_err() && terminal_result.is_ok() {
        return Err(SdkError::Unsupported("event stream task failed".to_owned()));
    }
    if intent_result.is_err() && terminal_result.is_ok() {
        return Err(SdkError::Unsupported(
            "intent forwarding task failed".to_owned(),
        ));
    }
    terminal_result.map_err(SdkError::from)
}

/// Keep the TUI intent receiver owned by the composition layer. The receiver
/// is deliberately not handed to the SDK: retry is the only intent that has
/// an SDK effect in the read-only attach lane.
fn forward_ui_intents(
    receiver: UiIntentReceiver,
    retry_signal: RetrySignal,
    cancellation: CancellationToken,
) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(UiIntent::RetryConnection) => {
                if cancellation.is_cancelled() {
                    return;
                }
                retry_signal.request();
            }
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

async fn pump_event_stream(
    mut stream: gorce_sdk::EventStream,
    sender: UiEventSender,
    cancellation: CancellationToken,
) {
    let mut timestamps = TimestampState::default();
    if !send_ui(
        &sender,
        UiEvent::Capabilities(UiCapabilities::READ_ONLY),
        &cancellation,
    )
    .await
    {
        timestamps.discard_staged();
        return;
    }

    loop {
        let update = match stream.next_update().await {
            Ok(update) => update,
            Err(SdkError::Cancelled) => {
                timestamps.discard_staged();
                return;
            }
            Err(_) => {
                shutdown_permanently(&sender, &cancellation, &mut timestamps).await;
                return;
            }
        };

        match update {
            EventStreamUpdate::Lifecycle(lifecycle) => {
                if matches!(lifecycle, EventStreamLifecycle::TerminalFailure) {
                    shutdown_permanently(&sender, &cancellation, &mut timestamps).await;
                    return;
                }
                let previous_timestamps = if matches!(lifecycle, EventStreamLifecycle::Reconciled) {
                    Some(timestamps.clone())
                } else {
                    None
                };
                if let EventStreamLifecycle::Reconciling { mode } = lifecycle {
                    timestamps.begin_reconciliation(mode);
                } else if matches!(lifecycle, EventStreamLifecycle::Reconciled) {
                    timestamps.promote_staged();
                }
                let Some(event) = connection_event(lifecycle, timestamps.committed.clone()) else {
                    // SnapshotPage and Replaying are transport markers with no
                    // corresponding UI DTO in this slice.
                    if let Some(previous) = previous_timestamps {
                        timestamps.restore(previous);
                    }
                    continue;
                };
                if !send_ui(&sender, UiEvent::Connection(event), &cancellation).await {
                    if let Some(previous) = previous_timestamps {
                        timestamps.restore(previous);
                    } else {
                        timestamps.discard_staged();
                    }
                    return;
                }
            }
            EventStreamUpdate::Item(EventStreamItem::Snapshot(batch)) => {
                for event in batch.events {
                    if !send_confirmed(event, &sender, &cancellation, &mut timestamps).await {
                        timestamps.discard_staged();
                        return;
                    }
                }
            }
            EventStreamUpdate::Item(EventStreamItem::Event(event)) => {
                if !send_confirmed(event, &sender, &cancellation, &mut timestamps).await {
                    timestamps.discard_staged();
                    return;
                }
            }
        }
    }
}

async fn send_confirmed(
    event: PublicEvent,
    sender: &UiEventSender,
    cancellation: &CancellationToken,
    timestamps: &mut TimestampState,
) -> bool {
    let confirmed = match map_confirmed_event(&event) {
        Ok(confirmed) => confirmed,
        Err(_) => {
            // Do not expose the event type, payload, or SDK validation text.
            let notice = UiEvent::LocalNotice(LocalNotice::new(
                LocalNoticeKind::Info,
                EVENT_MAPPING_NOTICE,
            ));
            let _ = send_ui(sender, notice, cancellation).await;
            shutdown_permanently(sender, cancellation, timestamps).await;
            return false;
        }
    };
    let confirmed_at = confirmed.confirmed_at.clone();
    if !send_ui(sender, UiEvent::Confirmed(confirmed), cancellation).await {
        return false;
    }
    timestamps.record_confirmed(confirmed_at);
    true
}

async fn shutdown_permanently(
    sender: &UiEventSender,
    cancellation: &CancellationToken,
    timestamps: &mut TimestampState,
) {
    timestamps.discard_staged();
    let _ = send_offline(sender, cancellation).await;
    cancellation.cancel();
}

async fn send_offline(sender: &UiEventSender, cancellation: &CancellationToken) -> bool {
    send_ui(
        sender,
        UiEvent::Connection(ConnectionEvent::Offline {
            reason: OfflineReason::new(STREAM_OFFLINE_REASON),
            retryability: Retryability::Permanent,
        }),
        cancellation,
    )
    .await
}

/// Send through the bounded synchronous TUI channel without dropping an
/// update. `try_send` plus a cancellation-aware wait keeps the async pump
/// responsive while still applying backpressure to confirmed events.
async fn send_ui(sender: &UiEventSender, event: UiEvent, cancellation: &CancellationToken) -> bool {
    let mut pending = event;
    loop {
        if cancellation.is_cancelled() {
            return false;
        }
        match sender.try_send(pending) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(event)) => {
                pending = event;
                tokio::select! {
                    _ = cancellation.cancelled() => return false,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        }
    }
}

#[allow(deprecated)]
fn connection_event(
    lifecycle: EventStreamLifecycle,
    committed_at: Option<ConfirmedTimestamp>,
) -> Option<ConnectionEvent> {
    Some(match lifecycle {
        EventStreamLifecycle::Connecting => ConnectionEvent::Connecting,
        EventStreamLifecycle::Connected => ConnectionEvent::Connected,
        EventStreamLifecycle::Reconnecting { attempt, .. } => ConnectionEvent::Reconnecting {
            attempt,
            last_confirmed_at: committed_at,
        },
        EventStreamLifecycle::RetryPaused { attempt } => ConnectionEvent::RetryPaused { attempt },
        EventStreamLifecycle::Reconciling { mode } => ConnectionEvent::Reconciling {
            mode: map_reconciliation_mode(mode),
        },
        EventStreamLifecycle::Reconciled => ConnectionEvent::ReconciliationComplete,
        EventStreamLifecycle::TerminalFailure => ConnectionEvent::Offline {
            reason: OfflineReason::new(STREAM_OFFLINE_REASON),
            retryability: Retryability::Permanent,
        },
        EventStreamLifecycle::SnapshotPage | EventStreamLifecycle::Replaying => return None,
    })
}

fn map_reconciliation_mode(mode: SdkReconciliationMode) -> TuiReconciliationMode {
    match mode {
        SdkReconciliationMode::Delta => TuiReconciliationMode::Delta,
        SdkReconciliationMode::Replace => TuiReconciliationMode::Replace,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventMappingError {
    UnknownEventType,
    MalformedEvent,
}

/// Convert only the daemon's public allowlisted event types to fixed
/// presentation DTOs. The event payload is deliberately never inspected or
/// copied into the TUI boundary.
fn map_confirmed_event(event: &PublicEvent) -> Result<ConfirmedEvent, EventMappingError> {
    let (kind, text) = match event.event_type.as_str() {
        "project.created" => (ConfirmedPresentationKind::Status, "Project created"),
        "project.updated" => (ConfirmedPresentationKind::Status, "Project updated"),
        "workstream.created" => (ConfirmedPresentationKind::Activity, "Workstream created"),
        "workstream.updated" => (ConfirmedPresentationKind::Activity, "Workstream updated"),
        "workstream.archived" => (ConfirmedPresentationKind::Activity, "Workstream archived"),
        "goal.created" => (ConfirmedPresentationKind::Activity, "Goal created"),
        "goal.revised" => (ConfirmedPresentationKind::Activity, "Goal revised"),
        "plan.created" => (ConfirmedPresentationKind::Activity, "Plan created"),
        "plan.revised" => (ConfirmedPresentationKind::Activity, "Plan revised"),
        "task.created" => (ConfirmedPresentationKind::Activity, "Task created"),
        "task.updated" => (ConfirmedPresentationKind::Activity, "Task updated"),
        "task.lifecycle_changed" => (
            ConfirmedPresentationKind::Activity,
            "Task lifecycle changed",
        ),
        "task.edge_created" => (
            ConfirmedPresentationKind::Activity,
            "Task dependency created",
        ),
        "task.edge_updated" => (
            ConfirmedPresentationKind::Activity,
            "Task dependency updated",
        ),
        _ => return Err(EventMappingError::UnknownEventType),
    };

    event
        .validate()
        .map_err(|_| EventMappingError::MalformedEvent)?;
    Ok(ConfirmedEvent::new(
        ConfirmedEventId::from_opaque_bytes(event.id.as_bytes()),
        ConfirmedTimestamp::new(event.occurred_at.clone()),
        ConfirmedPresentation::new(kind, text),
    ))
}

async fn run_foreground(mode: OutputMode) -> Result<(), SdkError> {
    let binary = std::env::var_os("GORCE_DAEMON_BIN").ok_or_else(|| {
        SdkError::Unsupported(
            "daemon foreground requires GORCE_DAEMON_BIN from the daemon installation".to_owned(),
        )
    })?;
    let status =
        tokio::task::spawn_blocking(move || Command::new(binary).arg("foreground").status())
            .await
            .map_err(|_| SdkError::Unsupported("daemon foreground task failed".to_owned()))??;
    let value = json!({"exit_code": status.code(), "success": status.success()});
    emit(
        mode,
        "daemon.foreground",
        value,
        "daemon foreground process exited".to_owned(),
    );
    if status.success() {
        Ok(())
    } else {
        Err(SdkError::Unsupported(
            "daemon foreground process failed".to_owned(),
        ))
    }
}

fn emit(mode: OutputMode, event: &str, data: Value, human: String) {
    match mode {
        OutputMode::Human => {
            if !human.is_empty() {
                println!("{human}");
            }
        }
        OutputMode::Json => println!("{}", json!({"event": event, "data": data})),
        OutputMode::Ndjson => println!("{}", json!({"event": event, "data": data})),
    }
}

fn parse_args(arguments: Vec<String>) -> Result<Cli, String> {
    let mut args = arguments.into_iter();
    let mut output = OutputMode::Human;
    let mut positional = Vec::new();
    let mut project = None;
    let mut name = None;
    let mut command_arguments = Vec::new();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" | "-h" => positional.push("help".to_owned()),
            "--version" | "-V" => positional.push("version".to_owned()),
            "--json" => output = OutputMode::Json,
            "--ndjson" => output = OutputMode::Ndjson,
            "--project" => project = Some(args.next().ok_or("--project needs a value")?),
            "--name" => name = Some(args.next().ok_or("--name needs a value")?),
            "--arg" => command_arguments.push(args.next().ok_or("--arg needs a value")?),
            value => positional.push(value.to_owned()),
        }
    }
    let command = match positional.first().map(String::as_str) {
        None => parse_attach_command(project, output)?,
        Some("help") => CommandLine::Help,
        Some("version") => CommandLine::Version,
        Some("init") => {
            let _ = name;
            CommandLine::Init
        }
        Some("daemon") => CommandLine::Daemon {
            action: positional
                .get(1)
                .cloned()
                .unwrap_or_else(|| "status".to_owned()),
        },
        Some("doctor") => CommandLine::Doctor { project },
        Some("store") if positional.get(1).map(String::as_str) == Some("verify") => {
            CommandLine::StoreVerify
        }
        Some("index") if positional.get(1).map(String::as_str) == Some("rebuild") => {
            CommandLine::IndexRebuild
        }
        Some("run") => {
            let command_name = positional
                .get(1)
                .cloned()
                .ok_or("run needs a command name")?;
            let arguments = if command_arguments.is_empty() {
                json!({})
            } else {
                Value::Array(command_arguments.into_iter().map(Value::String).collect())
            };
            CommandLine::Run {
                project,
                name: command_name,
                arguments,
            }
        }
        Some("attach") => parse_attach_command(project, output)?,
        Some(value) => return Err(format!("unknown command {value}")),
    };
    Ok(Cli { command, output })
}

fn parse_attach_command(
    project: Option<String>,
    output: OutputMode,
) -> Result<CommandLine, String> {
    if output != OutputMode::Human {
        return Err("interactive attach does not support --json or --ndjson".to_owned());
    }
    let project = project.ok_or("attach requires an explicit --project UUID")?;
    let project = gorce_sdk::parse_project_id(&project)
        .map_err(|_| "attach requires a valid explicit --project UUID".to_owned())?;
    Ok(CommandLine::Attach { project })
}

fn usage() -> &'static str {
    "gorce [--project UUID] [attach]\n\ncommands:\n  attach --project UUID       attach the read-only TUI\n  daemon foreground|status\n  doctor [--project UUID]\n  (no command)                attach the TUI (requires --project UUID)\n\n--json and --ndjson are for headless commands only.\nUnavailable until daemon routes are implemented: init, daemon stop, store verify, index rebuild, run.\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_requires_an_explicit_project() {
        let error = parse_args(Vec::new()).unwrap_err();
        assert!(error.contains("explicit --project UUID"));
    }

    #[test]
    fn parses_default_tui_attach_with_project() {
        let cli = parse_args(vec![
            "--project".to_owned(),
            "00000000-0000-0000-0000-000000000000".to_owned(),
        ])
        .unwrap();
        assert!(matches!(cli.command, CommandLine::Attach { .. }));
        assert_eq!(cli.output, OutputMode::Human);
    }

    #[test]
    fn parses_explicit_attach_with_project() {
        let cli = parse_args(vec![
            "attach".to_owned(),
            "--project".to_owned(),
            "00000000-0000-0000-0000-000000000000".to_owned(),
        ])
        .unwrap();
        assert!(matches!(cli.command, CommandLine::Attach { .. }));
    }

    #[test]
    fn attach_rejects_invalid_project_and_non_human_output() {
        assert!(parse_args(vec![
            "attach".to_owned(),
            "--project".to_owned(),
            "not-a-uuid".to_owned(),
        ])
        .is_err());
        assert!(parse_args(vec![
            "--json".to_owned(),
            "attach".to_owned(),
            "--project".to_owned(),
            "00000000-0000-0000-0000-000000000000".to_owned(),
        ])
        .is_err());
    }

    #[test]
    fn parses_headless_run() {
        let cli = parse_args(vec![
            "--ndjson".to_owned(),
            "run".to_owned(),
            "task.run".to_owned(),
            "--project".to_owned(),
            "00000000-0000-0000-0000-000000000000".to_owned(),
            "--arg".to_owned(),
            "value".to_owned(),
        ])
        .unwrap();
        assert_eq!(cli.output, OutputMode::Ndjson);
        assert!(matches!(cli.command, CommandLine::Run { .. }));
    }

    #[test]
    fn composition_dependencies_are_available() {
        assert_eq!(gorce_daemon::daemon_version(), "0.1");
        assert_eq!(gorce_tui::tui_version(), "0.1.0");
        assert_eq!(gorce_sdk::sdk_version(), "0.1");
    }

    fn public_event(event_type: &str, payload: Value) -> PublicEvent {
        PublicEvent {
            id: gorce_sdk::parse_project_id("00000000-0000-0000-0000-000000000001").unwrap(),
            project_id: gorce_sdk::parse_project_id("00000000-0000-0000-0000-000000000002")
                .unwrap(),
            sequence: 1,
            event_type: event_type.to_owned(),
            occurred_at: "2026-01-01T00:00:00Z".to_owned(),
            payload,
        }
    }

    #[test]
    fn maps_known_event_to_static_presentation_without_payload() {
        let event = public_event(
            "task.created",
            json!({"title": "secret payload text", "token": "do-not-display"}),
        );
        let mapped = super::map_confirmed_event(&event).unwrap();
        assert_eq!(
            mapped.presentation.kind,
            ConfirmedPresentationKind::Activity
        );
        assert_eq!(mapped.presentation.text.as_str(), "Task created");
        assert!(!mapped.presentation.text.as_str().contains("secret"));
        assert_eq!(mapped.confirmed_at.as_str(), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn omits_unknown_or_malformed_event_with_safe_diagnostic_kind() {
        let unknown = public_event("task.deleted", json!({"payload": "hidden"}));
        assert_eq!(
            super::map_confirmed_event(&unknown),
            Err(super::EventMappingError::UnknownEventType)
        );

        let mut malformed = public_event("task.created", json!({}));
        malformed.sequence = 0;
        assert_eq!(
            super::map_confirmed_event(&malformed),
            Err(super::EventMappingError::MalformedEvent)
        );
        assert!(!super::EVENT_MAPPING_NOTICE.contains("task.created"));
        assert!(!super::EVENT_MAPPING_NOTICE.contains("hidden"));
    }

    #[test]
    fn maps_delta_and_replace_reconciliation_modes_without_transport_data() {
        assert_eq!(
            super::connection_event(
                EventStreamLifecycle::Reconciling {
                    mode: SdkReconciliationMode::Delta,
                },
                None,
            ),
            Some(ConnectionEvent::Reconciling {
                mode: TuiReconciliationMode::Delta,
            })
        );
        assert_eq!(
            super::connection_event(
                EventStreamLifecycle::Reconciling {
                    mode: SdkReconciliationMode::Replace,
                },
                None,
            ),
            Some(ConnectionEvent::Reconciling {
                mode: TuiReconciliationMode::Replace,
            })
        );
    }

    #[test]
    fn maps_retry_paused_to_a_retryable_tui_state() {
        assert_eq!(
            super::connection_event(EventStreamLifecycle::RetryPaused { attempt: 4 }, None),
            Some(ConnectionEvent::RetryPaused { attempt: 4 })
        );
    }

    #[test]
    fn permanent_terminal_failure_is_not_retryable() {
        assert_eq!(
            super::connection_event(EventStreamLifecycle::TerminalFailure, None),
            Some(ConnectionEvent::Offline {
                reason: OfflineReason::new(STREAM_OFFLINE_REASON),
                retryability: Retryability::Permanent,
            })
        );
    }

    #[test]
    fn delta_stages_from_committed_and_promotes_only_on_reconciled() {
        let mut timestamps = TimestampState {
            committed: Some(ConfirmedTimestamp::new("committed")),
            ..TimestampState::default()
        };
        timestamps.begin_reconciliation(SdkReconciliationMode::Delta);
        assert_eq!(
            timestamps.staged,
            Some(ConfirmedTimestamp::new("committed"))
        );

        timestamps.record_confirmed(ConfirmedTimestamp::new("replayed"));
        assert_eq!(
            timestamps.committed,
            Some(ConfirmedTimestamp::new("committed"))
        );
        assert_eq!(timestamps.staged, Some(ConfirmedTimestamp::new("replayed")));

        timestamps.promote_staged();
        assert_eq!(
            timestamps.committed,
            Some(ConfirmedTimestamp::new("replayed"))
        );
        assert_eq!(timestamps.staged, None);
        assert!(!timestamps.reconciliation_active);
    }

    #[test]
    fn empty_replace_promotes_none_without_changing_timestamps_by_order() {
        let mut timestamps = TimestampState {
            committed: Some(ConfirmedTimestamp::new("old")),
            ..TimestampState::default()
        };
        timestamps.begin_reconciliation(SdkReconciliationMode::Replace);
        assert_eq!(timestamps.staged, None);
        assert_eq!(timestamps.committed, Some(ConfirmedTimestamp::new("old")));

        timestamps.promote_staged();
        assert_eq!(timestamps.committed, None);
        assert_eq!(timestamps.staged, None);
        assert!(!timestamps.reconciliation_active);
    }

    #[tokio::test]
    async fn timestamp_changes_only_after_successful_typed_delivery() {
        let mut timestamps = TimestampState {
            committed: Some(ConfirmedTimestamp::new("old")),
            ..TimestampState::default()
        };
        timestamps.begin_reconciliation(SdkReconciliationMode::Replace);

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        let event = public_event("task.created", json!({"hidden": "payload"}));
        assert!(
            !super::send_confirmed(event, &sender, &CancellationToken::new(), &mut timestamps,)
                .await
        );
        assert_eq!(timestamps.committed, Some(ConfirmedTimestamp::new("old")));
        assert_eq!(timestamps.staged, None);
    }

    #[tokio::test]
    async fn permanent_shutdown_emits_static_offline_and_stops_forwarder() {
        let (events_tx, events_rx) = std::sync::mpsc::sync_channel(1);
        let (intents_tx, intents_rx) = std::sync::mpsc::sync_channel(1);
        let cancellation = CancellationToken::new();
        let retry_signal = RetrySignal::new();
        let observed_signal = retry_signal.clone();
        let worker_cancellation = cancellation.clone();
        let worker = std::thread::spawn(move || {
            super::forward_ui_intents(intents_rx, observed_signal, worker_cancellation);
        });
        let mut timestamps = TimestampState {
            committed: Some(ConfirmedTimestamp::new("committed")),
            staged: Some(ConfirmedTimestamp::new("staged")),
            reconciliation_active: true,
        };

        super::shutdown_permanently(&events_tx, &cancellation, &mut timestamps).await;

        assert_eq!(
            events_rx.recv().unwrap(),
            UiEvent::Connection(ConnectionEvent::Offline {
                reason: OfflineReason::new(STREAM_OFFLINE_REASON),
                retryability: Retryability::Permanent,
            })
        );
        assert_eq!(timestamps.staged, None);
        assert!(!timestamps.reconciliation_active);
        assert!(cancellation.is_cancelled());
        worker.join().unwrap();
        assert_eq!(retry_signal.generation(), 0);
        assert!(intents_tx.send(UiIntent::RetryConnection).is_err());
    }

    #[test]
    fn forwards_only_retry_connection_to_the_stream_signal() {
        let (intent_tx, intent_rx) = std::sync::mpsc::sync_channel(4);
        let retry_signal = RetrySignal::new();
        let observed_signal = retry_signal.clone();
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let worker = std::thread::spawn(move || {
            super::forward_ui_intents(intent_rx, observed_signal, worker_cancellation);
        });

        intent_tx
            .send(UiIntent::Submit("must remain local".to_owned()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(retry_signal.generation(), 0);

        intent_tx.send(UiIntent::RetryConnection).unwrap();
        for _ in 0..100 {
            if retry_signal.generation() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(retry_signal.generation(), 1);

        cancellation.cancel();
        worker.join().unwrap();
    }

    #[test]
    fn intent_forwarding_shuts_down_when_attach_is_cancelled() {
        let (_intent_tx, intent_rx) = std::sync::mpsc::sync_channel(1);
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let worker = std::thread::spawn(move || {
            super::forward_ui_intents(intent_rx, RetrySignal::new(), worker_cancellation);
        });

        cancellation.cancel();
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn bounded_ui_send_exits_on_cancellation_without_dropping_first_event() {
        let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
        sender
            .try_send(UiEvent::Capabilities(UiCapabilities::READ_ONLY))
            .unwrap();
        let cancellation = CancellationToken::new();
        let cancellation_trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation_trigger.cancel();
        });

        assert!(
            !super::send_ui(
                &sender,
                UiEvent::Connection(ConnectionEvent::Connected),
                &cancellation,
            )
            .await
        );
    }
}
