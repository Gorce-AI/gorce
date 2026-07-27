#![forbid(unsafe_code)]

mod auth;
mod cancellation;
mod client;
mod diagnostics;
mod discovery;
mod error;
mod lifecycle;
mod models;
mod retry;
mod stream;

pub use auth::{config_dir, default_token_path, Token, TokenLoader};
pub use cancellation::CancellationToken;
pub use client::{
    timestamp_now, Client, ClientConfig, RequestOptions, AUTHORIZATION_HEADER, CANCELLATION_HEADER,
    IDEMPOTENCY_HEADER, PROTOCOL_VERSION_HEADER, REQUEST_ID_HEADER,
};
pub use diagnostics::{run_diagnostics, DiagnosticOptions};
pub use discovery::{
    read_descriptor, write_descriptor, DaemonDiscovery, DiscoveredDaemon, DESCRIPTOR_FILE_NAME,
    TOKEN_FILE_NAME,
};
pub use error::SdkError;
pub use lifecycle::{configured_client, DaemonLauncher, LazyDaemon, ProcessLauncher};
pub use models::{
    ApiFailure, DaemonDescriptor, DaemonMeta, DiagnosticCheck, DiagnosticReport, DiagnosticStatus,
    EventStreamItem, Health, HealthStatus, OperationResponse, ProjectContext, ProjectSnapshot,
};
pub use retry::RetrySignal;
pub use stream::{
    EventStream, EventStreamLifecycle, EventStreamOptions, EventStreamUpdate, ReconciliationMode,
    ReconciliationOrigin, MAX_SSE_FRAME_BYTES,
};

pub use gorce_protocol::*;

pub const SDK_VERSION: &str = "0.1";

pub fn sdk_version() -> &'static str {
    let _ = gorce_protocol::protocol_version();
    SDK_VERSION
}

pub fn parse_project_id(value: &str) -> Result<ProjectId, SdkError> {
    uuid::Uuid::parse_str(value)
        .map_err(|error| SdkError::InvalidConfiguration(format!("invalid project id: {error}")))
}

pub fn new_project(name: impl Into<String>) -> Project {
    let now = timestamp_now();
    Project {
        id: uuid::Uuid::now_v7(),
        name: name.into(),
        description: None,
        created_at: now.clone(),
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use super::{
        new_project, sdk_version, CancellationToken, Client, ClientConfig, EventStreamItem,
        EventStreamLifecycle, EventStreamUpdate, PublicEventCursor, ReconciliationMode,
        RequestOptions, RetrySignal, SdkError, Token, MAX_SSE_FRAME_BYTES, SDK_VERSION,
    };
    #[test]
    fn exposes_the_sdk_version() {
        assert_eq!(sdk_version(), SDK_VERSION);
    }

    #[test]
    fn creates_versioned_project_identifiers() {
        assert_eq!(new_project("demo").name, "demo");
    }

    #[tokio::test]
    async fn http_methods_use_authentication_headers() {
        let body = serde_json::json!({"status": "ok", "version": "0.1"}).to_string();
        let (endpoint, server) = one_shot_server(201, "application/json", &body);
        let client =
            Client::new(ClientConfig::new(endpoint, Token::new("secret").unwrap())).unwrap();
        let returned = client
            .health_with_options(
                RequestOptions::default()
                    .cancellation_token("cancel-1")
                    .request_id("request-1"),
            )
            .await
            .unwrap();
        assert_eq!(returned.version, "0.1");
        let request = server.join().unwrap().to_ascii_lowercase();
        assert!(request.contains("authorization: bearer secret"));
        assert!(request.contains("x-gorce-cancellation-token: cancel-1"));
        assert!(request.contains("x-request-id: request-1"));
    }

    #[tokio::test]
    async fn typed_api_errors_are_returned() {
        let error = serde_json::json!({
            "code": "service_not_ready",
            "message": "not ready",
            "request_id": "req-1"
        });
        let (endpoint, server) = one_shot_server(503, "application/json", &error.to_string());
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        match client.health().await.unwrap_err() {
            SdkError::Api(failure) => {
                assert_eq!(failure.status, 503);
                assert_eq!(failure.error.message, "not ready");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        server.join().unwrap();
    }

    #[tokio::test]
    async fn commands_require_and_retain_the_caller_idempotency_key() {
        let project_id = uuid::Uuid::new_v4();
        let command = gorce_protocol::AuthorityCommandRequest {
            version: gorce_protocol::COMMAND_ENVELOPE_FORMAT.to_owned(),
            command: gorce_protocol::AuthorityCommandKind::ProfileRegister {
                arguments: gorce_protocol::EmptyCommandArguments {},
            },
        };
        let client = Client::new(ClientConfig::unauthenticated("http://127.0.0.1:9")).unwrap();
        assert!(matches!(
            client
                .run_command(project_id, &command, RequestOptions::default())
                .await,
            Err(SdkError::InvalidConfiguration(_))
        ));

        let error = serde_json::json!({
            "code": "idempotency_conflict",
            "message": "different command body",
            "request_id": "req-1"
        });
        let (endpoint, server) = one_shot_server(409, "application/json", &error.to_string());
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let failure = client
            .run_command(
                project_id,
                &command,
                RequestOptions::default().idempotency_key("retained-key"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            failure,
            SdkError::Command { status: 409, error } if error.code == gorce_protocol::CommandErrorCode::IdempotencyConflict
        ));
        let request = server.join().unwrap();
        assert!(request.contains("idempotency-key: retained-key"));
    }

    #[tokio::test]
    async fn routes_not_exposed_by_the_daemon_fail_closed() {
        let client = Client::new(ClientConfig::unauthenticated("http://127.0.0.1:9")).unwrap();
        let error = client.list_projects().await.unwrap_err();
        assert!(matches!(error, SdkError::Unsupported(_)));
    }

    #[test]
    fn diagnostics_do_not_format_token_or_path_details() {
        let error = SdkError::Token("secret-token at /home/user/.ssh/id_rsa".to_owned());
        assert!(!error.to_string().contains("secret-token"));
        assert!(!format!("{error:?}").contains("id_rsa"));
    }

    #[tokio::test]
    async fn event_stream_resumes_and_resyncs_after_a_gap() {
        let project_id = uuid::Uuid::new_v4();
        let first = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let second = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 3,
            "event_type": "task.updated",
            "occurred_at": "2026-01-01T00:00:01Z",
            "payload": {}
        });
        let snapshot = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {first}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", snapshot.to_string()),
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-1-0\ndata: {second}\n\n"),
            ),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, None);
        assert!(matches!(
            stream.next().await.unwrap(),
            EventStreamItem::Event(_)
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            EventStreamItem::Snapshot(_)
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            EventStreamItem::Event(_)
        ));
        let requests = server.join().unwrap();
        assert!(requests[1].contains(&format!("/v0/projects/{project_id}/events?cursor=g1-0-0")));
        assert!(requests[2].contains(&format!(
            "/v0/events/stream?project_id={project_id}&cursor=g1-1-0"
        )));
    }

    #[tokio::test]
    async fn event_resync_paginates_opaque_cursors_without_sequence_assumptions() {
        let project_id = uuid::Uuid::new_v4();
        let page_one = serde_json::json!({
            "project_id": project_id,
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": true
        });
        let page_two = serde_json::json!({
            "project_id": project_id,
            "cursor": "g1-1-0",
            "events": [],
            "next_cursor": "g1-99-1",
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(200, "application/json", page_one.to_string()),
            ScriptedResponse::new(200, "application/json", page_two.to_string()),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, None);
        assert!(matches!(
            stream.next().await.unwrap(),
            EventStreamItem::Snapshot(_)
        ));
        assert_eq!(stream.cursor(), None);
        assert!(matches!(
            stream.next().await.unwrap(),
            EventStreamItem::Snapshot(_)
        ));
        assert_eq!(stream.cursor(), None);
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        assert_eq!(stream.cursor(), Some("g1-99-1"));
        let requests = server.join().unwrap();
        assert!(requests[3].contains("cursor=g1-99-1"));
    }

    #[tokio::test]
    async fn event_stream_reports_initial_connection_before_data() {
        let project_id = uuid::Uuid::new_v4();
        let (endpoint, server) = one_shot_server(200, "text/event-stream", "");
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, None);

        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connecting)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn established_reconnect_reconciles_before_reopening_without_replaying() {
        let project_id = uuid::Uuid::new_v4();
        let first_event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let race_event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 2,
            "event_type": "task.updated",
            "occurred_at": "2026-01-01T00:00:01Z",
            "payload": {}
        });
        let page_one = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": true
        });
        let page_two = serde_json::json!({
            "cursor": "g1-1-0",
            "events": [],
            "next_cursor": "g1-99-1",
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {first_event}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", page_one.to_string()),
            ScriptedResponse::new(200, "application/json", page_two.to_string()),
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-99-2\ndata: {race_event}\n\n"),
            ),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                ..Default::default()
            },
        );

        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connecting)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Item(EventStreamItem::Event(_))
        ));
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Delta,
            })
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Item(EventStreamItem::Snapshot(_))
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Item(EventStreamItem::Snapshot(_))
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Item(EventStreamItem::Event(_))
        ));
        let requests = server.join().unwrap();
        assert!(requests[1].contains("cursor=g1-0-0"));
        assert!(requests[2].contains("cursor=g1-1-0"));
        assert!(requests[3].contains("cursor=g1-99-1"));
    }

    #[tokio::test]
    async fn failed_reopen_keeps_one_reconciliation_candidate() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let page = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-7-4",
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {event}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", page.to_string()),
            ScriptedResponse::new(503, "application/json", ""),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                max_reconnects: Some(3),
                ..Default::default()
            },
        );

        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Delta,
            })
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        assert_eq!(stream.cursor(), Some("g1-7-4"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[1].contains("cursor=g1-0-0"));
        assert!(requests[2].contains("cursor=g1-7-4"));
        assert!(requests[3].contains("cursor=g1-7-4"));
    }

    #[tokio::test]
    async fn cancellation_before_reconciliation_completion_never_reconciles() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let (endpoint, server) = scripted_server(vec![ScriptedResponse::new(
            200,
            "text/event-stream",
            format!("id: g1-0-0\ndata: {event}\n\n"),
        )]);
        let cancellation = CancellationToken::new();
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::from_secs(60),
                max_backoff: Duration::from_secs(60),
                cancellation: Some(cancellation.clone()),
                ..Default::default()
            },
        );

        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        let mut retry = Box::pin(stream.next_update());
        tokio::select! {
            result = &mut retry => panic!("retry unexpectedly completed: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => cancellation.cancel(),
        }
        assert_eq!(
            retry.await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::Cancelled)
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn event_stream_reports_reconnecting_before_backoff() {
        let project_id = uuid::Uuid::new_v4();
        let (endpoint, server) = one_shot_server(200, "text/event-stream", "");
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                max_reconnects: Some(1),
                initial_backoff: Duration::from_secs(60),
                max_backoff: Duration::from_secs(60),
                cancellation: None,
                retry_signal: None,
            },
        );

        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting {
                attempt: 1,
                backoff
            }) if backoff == Duration::from_secs(60)
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn event_stream_retry_wait_is_interruptible() {
        let project_id = uuid::Uuid::new_v4();
        let (endpoint, server) = one_shot_server(200, "text/event-stream", "");
        let cancellation = CancellationToken::new();
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                max_reconnects: None,
                initial_backoff: Duration::from_secs(60),
                max_backoff: Duration::from_secs(60),
                cancellation: Some(cancellation.clone()),
                retry_signal: None,
            },
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();

        let mut retry = Box::pin(stream.next_update());
        tokio::select! {
            result = &mut retry => panic!("retry unexpectedly completed: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => cancellation.cancel(),
        }
        assert_eq!(
            retry.await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::Cancelled)
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn invalid_live_frame_does_not_advance_checkpoint() {
        let project_id = uuid::Uuid::new_v4();
        let (endpoint, server) = one_shot_server(
            200,
            "text/event-stream",
            "id: new-opaque-cursor\ndata: {not-json}\n\n",
        );
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, Some(PublicEventCursor("g1-4-1".into())));
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert_eq!(stream.cursor(), Some("g1-4-1"));
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::Decode { .. })
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn data_bearing_live_frame_without_id_fails_closed() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let body = format!("data: {}\n\n", event);
        let (endpoint, server) = one_shot_server(200, "text/event-stream", &body);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, Some(PublicEventCursor("g1-4-1".into())));
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert_eq!(stream.cursor(), Some("g1-4-1"));
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn event_stream_reports_reconciliation_and_snapshot_pages() {
        let project_id = uuid::Uuid::new_v4();
        let page_one = serde_json::json!({
            "project_id": project_id,
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": true
        });
        let page_two = serde_json::json!({
            "project_id": project_id,
            "cursor": "g1-1-0",
            "events": [],
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(200, "application/json", page_one.to_string()),
            ScriptedResponse::new(200, "application/json", page_two.to_string()),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, None);

        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connecting)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Replace,
            })
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Item(EventStreamItem::Snapshot(_))
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Item(EventStreamItem::Snapshot(_))
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn established_disconnect_without_a_cursor_reconciles_from_origin() {
        let project_id = uuid::Uuid::new_v4();
        let page = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(200, "text/event-stream", ""),
            ScriptedResponse::new(200, "application/json", page.to_string()),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                ..Default::default()
            },
        );

        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connecting)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Delta,
            })
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Item(EventStreamItem::Snapshot(_))
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        let requests = server.join().unwrap();
        assert!(!requests[1].contains("cursor="));
        assert!(requests[2].contains("cursor=g1-0-0"));
    }

    #[tokio::test]
    async fn rejected_reopen_uses_replace_reconciliation_mode() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let page = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "has_more": false
        });
        let replacement_page = serde_json::json!({
            "cursor": "g1-1-0",
            "events": [],
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {event}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", page.to_string()),
            ScriptedResponse::new(410, "application/json", ""),
            ScriptedResponse::new(200, "application/json", replacement_page.to_string()),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                ..Default::default()
            },
        );

        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Delta,
            })
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Replace,
            })
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        let requests = server.join().unwrap();
        assert!(requests[1].contains("/v0/projects/") && requests[1].contains("cursor=g1-0-0"));
        assert!(requests[2].contains("/v0/events/stream") && requests[2].contains("cursor=g1-0-0"));
        assert!(!requests[3].contains("cursor="));
        assert!(requests[4].contains("cursor=g1-1-0"));
    }

    #[tokio::test]
    async fn retry_signal_skips_an_active_backoff() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let page = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "has_more": false
        });
        let signal = RetrySignal::new();
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {event}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", page.to_string()),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::from_secs(60),
                max_backoff: Duration::from_secs(60),
                retry_signal: Some(signal.clone()),
                ..Default::default()
            },
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));

        let waiting = Box::pin(stream.next_update());
        tokio::time::sleep(Duration::from_millis(10)).await;
        signal.request_retry();
        assert_eq!(
            waiting.await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Delta,
            })
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn retry_signal_resumes_after_failed_reopen_without_repeating_pages() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let page = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-9-9",
            "has_more": false
        });
        let signal = RetrySignal::new();
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {event}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", page.to_string()),
            ScriptedResponse::new(503, "application/json", ""),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                max_reconnects: Some(1),
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                retry_signal: Some(signal.clone()),
                ..Default::default()
            },
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::RetryPaused { .. })
        ));

        let paused = Box::pin(stream.next_update());
        tokio::time::sleep(Duration::from_millis(10)).await;
        signal.retry();
        assert!(matches!(
            paused.await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        let requests = server.join().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("/v0/projects/") && request.contains("/events"))
                .count(),
            1
        );
        assert!(requests[3].contains("cursor=g1-9-9"));
    }

    #[tokio::test]
    async fn retry_signal_and_cancellation_race_prefers_cancellation() {
        let project_id = uuid::Uuid::new_v4();
        let cancellation = CancellationToken::new();
        let signal = RetrySignal::new();
        let (endpoint, server) = one_shot_server(200, "text/event-stream", "");
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::from_secs(60),
                max_backoff: Duration::from_secs(60),
                cancellation: Some(cancellation.clone()),
                retry_signal: Some(signal.clone()),
                ..Default::default()
            },
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        signal.request();
        cancellation.cancel();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::Cancelled)
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn retryable_middle_page_failure_retries_the_same_page() {
        let project_id = uuid::Uuid::new_v4();
        let page_one = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": true
        });
        let page_two = serde_json::json!({
            "cursor": "g1-1-0",
            "events": [],
            "next_cursor": "g1-2-0",
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(200, "application/json", page_one.to_string()),
            ScriptedResponse::new(503, "application/json", ""),
            ScriptedResponse::new(200, "application/json", page_two.to_string()),
            ScriptedResponse::new(200, "text/event-stream", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                ..Default::default()
            },
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert!(matches!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconnecting { .. })
        ));
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let requests = server.join().unwrap();
        assert!(requests[1].contains("/events"));
        assert!(requests[2].contains("cursor=g1-1-0"));
        assert!(requests[3].contains("cursor=g1-1-0"));
    }

    #[tokio::test]
    async fn permanent_middle_page_failure_terminalizes_without_retry() {
        let project_id = uuid::Uuid::new_v4();
        let page_one = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": true
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(200, "application/json", page_one.to_string()),
            ScriptedResponse::new(401, "application/json", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, None);
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::HttpStatus { status: 401 })
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn oversized_unterminated_sse_frame_fails_closed() {
        let project_id = uuid::Uuid::new_v4();
        let body = format!("data: {}", "x".repeat(MAX_SSE_FRAME_BYTES));
        let (endpoint, server) = one_shot_server(200, "text/event-stream", &body);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(project_id, None);
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn malformed_opaque_sse_id_retains_the_prior_checkpoint() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let (endpoint, server) = one_shot_server(
            200,
            "text/event-stream",
            &format!("id: not-a-public-cursor\ndata: {event}\n\n"),
        );
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream =
            client.event_stream(project_id, Some(PublicEventCursor("g1-4-2".to_owned())));
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert_eq!(stream.cursor(), Some("g1-4-2"));
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn delta_page_reset_to_replace_discards_staged_delta_traversal() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let page_one = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": true
        });
        let page_two = serde_json::json!({
            "cursor": "g1-1-0",
            "events": [],
            "next_cursor": "g1-2-0",
            "has_more": true
        });
        let replacement = serde_json::json!({
            "cursor": "g1-50-0",
            "events": [],
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {event}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", page_one.to_string()),
            ScriptedResponse::new(200, "application/json", page_two.to_string()),
            ScriptedResponse::new(410, "application/json", ""),
            ScriptedResponse::new(200, "application/json", replacement.to_string()),
            ScriptedResponse::new(200, "text/event-stream; charset=utf-8", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                ..Default::default()
            },
        );

        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Delta,
            })
        );
        for _ in 0..2 {
            assert_eq!(
                stream.next_update().await.unwrap(),
                EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
            );
            let _ = stream.next_update().await.unwrap();
        }
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciling {
                mode: ReconciliationMode::Replace,
            })
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::SnapshotPage)
        );
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Reconciled)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connected)
        );
        assert_eq!(stream.cursor(), Some("g1-50-0"));
        let requests = server.join().unwrap();
        assert!(requests[1].contains("cursor=g1-0-0"));
        assert!(requests[2].contains("cursor=g1-1-0"));
        assert!(requests[3].contains("cursor=g1-2-0"));
        assert!(!requests[4].contains("cursor="));
        assert!(requests[5].contains("cursor=g1-50-0"));
    }

    #[tokio::test]
    async fn malformed_initial_cursor_fails_before_any_retry_or_request() {
        let client = Client::new(ClientConfig::unauthenticated("http://127.0.0.1:9")).unwrap();
        let mut stream = client.event_stream(
            uuid::Uuid::new_v4(),
            Some(PublicEventCursor("not-a-valid-cursor".to_owned())),
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::Connecting)
        );
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
    }

    #[tokio::test]
    async fn successful_non_sse_responses_fail_closed_without_committing_candidate() {
        for (status, content_type, body) in [
            (204, "application/json", ""),
            (200, "application/json", "{}"),
        ] {
            let (endpoint, server) = one_shot_server(status, content_type, body);
            let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
            let mut stream = client.event_stream(
                uuid::Uuid::new_v4(),
                Some(PublicEventCursor("g1-4-1".to_owned())),
            );
            let _ = stream.next_update().await.unwrap();
            assert_eq!(
                stream.next_update().await.unwrap(),
                EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
            );
            assert_eq!(stream.cursor(), Some("g1-4-1"));
            assert!(matches!(
                stream.next_update().await,
                Err(SdkError::EventGap(_))
            ));
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_sse_reopen_does_not_commit_a_staged_candidate() {
        let page = serde_json::json!({
            "cursor": "g1-9-0",
            "events": [],
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(200, "application/json", page.to_string()),
            ScriptedResponse::new(200, "application/json", "{}"),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(
            uuid::Uuid::new_v4(),
            Some(PublicEventCursor("g1-4-1".to_owned())),
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert_eq!(stream.cursor(), Some("g1-4-1"));
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn reconciliation_rejects_a_same_cursor_continuation() {
        let page = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-0-0",
            "has_more": true
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(200, "application/json", page.to_string()),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(uuid::Uuid::new_v4(), None);
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn replace_reconciliation_409_fails_closed() {
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(409, "application/json", ""),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(uuid::Uuid::new_v4(), None);
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::HttpStatus { status: 409 })
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn reconciliation_rejects_an_opaque_cursor_cycle() {
        let page_one = serde_json::json!({
            "cursor": "g1-0-0",
            "events": [],
            "next_cursor": "g1-1-0",
            "has_more": true
        });
        let page_two = serde_json::json!({
            "cursor": "g1-1-0",
            "events": [],
            "next_cursor": "g1-0-0",
            "has_more": true
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                "event: resync_required\ndata: {}\n\n",
            ),
            ScriptedResponse::new(200, "application/json", page_one.to_string()),
            ScriptedResponse::new(200, "application/json", page_two.to_string()),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream(uuid::Uuid::new_v4(), None);
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn delta_reconciliation_rejects_a_returned_cursor_mismatch() {
        let project_id = uuid::Uuid::new_v4();
        let event = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "project_id": project_id,
            "sequence": 1,
            "event_type": "task.created",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {}
        });
        let mismatch = serde_json::json!({
            "cursor": "g1-9-0",
            "events": [],
            "has_more": false
        });
        let (endpoint, server) = scripted_server(vec![
            ScriptedResponse::new(
                200,
                "text/event-stream",
                format!("id: g1-0-0\ndata: {event}\n\n"),
            ),
            ScriptedResponse::new(200, "application/json", mismatch.to_string()),
        ]);
        let client = Client::new(ClientConfig::unauthenticated(endpoint)).unwrap();
        let mut stream = client.event_stream_with_options(
            project_id,
            None,
            super::EventStreamOptions {
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                ..Default::default()
            },
        );
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        let _ = stream.next_update().await.unwrap();
        assert_eq!(
            stream.next_update().await.unwrap(),
            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
        );
        assert_eq!(stream.cursor(), Some("g1-0-0"));
        assert!(matches!(
            stream.next_update().await,
            Err(SdkError::EventGap(_))
        ));
        let requests = server.join().unwrap();
        assert!(requests[1].contains("cursor=g1-0-0"));
    }

    struct ScriptedResponse {
        status: u16,
        content_type: String,
        body: String,
    }

    impl ScriptedResponse {
        fn new(status: u16, content_type: impl Into<String>, body: impl Into<String>) -> Self {
            Self {
                status,
                content_type: content_type.into(),
                body: body.into(),
            }
        }
    }

    fn scripted_server(
        responses: Vec<ScriptedResponse>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                write_response(
                    &mut stream,
                    response.status,
                    &response.content_type,
                    &response.body,
                );
            }
            requests
        });
        (endpoint, server)
    }

    fn one_shot_server(
        status: u16,
        content_type: &str,
        body: &str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let content_type = content_type.to_owned();
        let body = body.to_owned();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            write_response(&mut stream, status, &content_type, &body);
            request
        });
        (endpoint, server)
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
        let reason = if status >= 400 { "Error" } else { "OK" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }
}
