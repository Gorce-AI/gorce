use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gorce_protocol::{
    ApiError, GoalRevision, Lease, Message, OperatorProfile, PermissionRequest, PlanRevision,
    Project, PublicEvent, PublicEventBatch, PublicEventCursor, SkillManifest, Task, TaskAttempt,
    TaskEdge, TaskRevision, Workstream,
};
use reqwest::{Method, RequestBuilder, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::Token;
use crate::discovery::validate_loopback_endpoint;
use crate::discovery::{DaemonDiscovery, DiscoveredDaemon};
use crate::error::{decode_error, SdkError};
use crate::models::{
    ApiFailure, CommandRequest, CommandResponse, DaemonMeta, Health, ProjectSnapshot,
};

pub const AUTHORIZATION_HEADER: &str = "Authorization";
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";
pub const CANCELLATION_HEADER: &str = "X-Gorce-Cancellation-Token";
pub const REQUEST_ID_HEADER: &str = "X-Request-ID";
pub const PROTOCOL_VERSION_HEADER: &str = "X-Gorce-Protocol-Version";

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub endpoint: String,
    pub token: Option<Token>,
    pub timeout: Duration,
}

impl ClientConfig {
    pub fn new(endpoint: impl Into<String>, token: Token) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: Some(token),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn unauthenticated(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: None,
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestOptions {
    pub idempotency_key: Option<String>,
    pub cancellation_token: Option<String>,
    pub request_id: Option<String>,
}

impl RequestOptions {
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub fn cancellation_token(mut self, token: impl Into<String>) -> Self {
        self.cancellation_token = Some(token.into());
        self
    }

    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    stream_http: reqwest::Client,
    endpoint: String,
    token: Option<Token>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Client")
            .field("endpoint", &self.endpoint)
            .field("authenticated", &self.token.is_some())
            .finish()
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self, SdkError> {
        let raw_endpoint = config.endpoint.trim_end_matches('/');
        let endpoint = if raw_endpoint.contains("://") {
            raw_endpoint.to_owned()
        } else {
            format!("http://{raw_endpoint}")
        };
        let endpoint_url = Url::parse(&endpoint).map_err(|error| {
            SdkError::InvalidConfiguration(format!("endpoint is not a URL: {error}"))
        })?;
        validate_loopback_endpoint(endpoint_url.as_str()).map_err(|_| {
            SdkError::InvalidConfiguration("endpoint must be loopback HTTP".to_owned())
        })?;
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(format!("gorce-sdk/{SDK_VERSION}"))
            .build()?;
        let stream_http = reqwest::Client::builder()
            .user_agent(format!("gorce-sdk/{SDK_VERSION}"))
            .build()?;
        Ok(Self {
            http,
            stream_http,
            endpoint,
            token: config.token,
        })
    }

    pub fn from_discovered(daemon: DiscoveredDaemon) -> Result<Self, SdkError> {
        if daemon.descriptor.protocol_version != gorce_protocol::PROTOCOL_VERSION {
            return Err(SdkError::Discovery(
                "unsupported daemon protocol version".to_owned(),
            ));
        }
        Self::new(ClientConfig::new(daemon.descriptor.endpoint, daemon.token))
    }

    pub fn discover() -> Result<Self, SdkError> {
        Self::from_discovered(DaemonDiscovery::new().discover()?)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn health(&self) -> Result<Health, SdkError> {
        self.health_with_options(RequestOptions::default()).await
    }

    pub async fn health_with_options(&self, options: RequestOptions) -> Result<Health, SdkError> {
        self.get_json("/v0/health", &options).await
    }

    pub async fn meta(&self) -> Result<DaemonMeta, SdkError> {
        self.get_json("/v0/meta", &RequestOptions::default()).await
    }

    pub async fn list_projects(&self) -> Result<Vec<Project>, SdkError> {
        self.list_projects_with_options(RequestOptions::default())
            .await
    }

    pub async fn list_projects_with_options(
        &self,
        options: RequestOptions,
    ) -> Result<Vec<Project>, SdkError> {
        self.get_json("/v0/projects", &options).await
    }

    pub async fn get_project(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Project, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_workstreams(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<Workstream>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/workstreams"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_goal_revisions(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<GoalRevision>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/goals/revisions"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_plan_revisions(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<PlanRevision>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/plans/revisions"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_tasks(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<Task>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/tasks"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn get_task(
        &self,
        project_id: gorce_protocol::ProjectId,
        task_id: gorce_protocol::TaskId,
    ) -> Result<Task, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/tasks/{task_id}"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_task_revisions(
        &self,
        project_id: gorce_protocol::ProjectId,
        task_id: gorce_protocol::TaskId,
    ) -> Result<Vec<TaskRevision>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/tasks/{task_id}/revisions"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_task_edges(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<TaskEdge>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/task-edges"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_task_attempts(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<TaskAttempt>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/task-attempts"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_leases(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<Lease>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/leases"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_operators(&self) -> Result<Vec<OperatorProfile>, SdkError> {
        self.get_json("/v0/operators", &RequestOptions::default())
            .await
    }

    pub async fn list_skill_manifests(
        &self,
        operator_id: gorce_protocol::OperatorId,
    ) -> Result<Vec<SkillManifest>, SdkError> {
        self.get_json(
            &format!("/v0/operators/{operator_id}/skill-manifests"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_permission_requests(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<PermissionRequest>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/permission-requests"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_messages(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<Vec<Message>, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/messages"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn project_snapshot(
        &self,
        project_id: gorce_protocol::ProjectId,
    ) -> Result<ProjectSnapshot, SdkError> {
        self.get_json(
            &format!("/v0/projects/{project_id}/snapshot"),
            &RequestOptions::default(),
        )
        .await
    }

    pub async fn list_public_events(
        &self,
        project_id: gorce_protocol::ProjectId,
        cursor: Option<&PublicEventCursor>,
        limit: Option<u16>,
    ) -> Result<PublicEventBatch, SdkError> {
        self.list_public_events_with_options(project_id, cursor, limit, RequestOptions::default())
            .await
    }

    pub async fn list_public_events_with_options(
        &self,
        project_id: gorce_protocol::ProjectId,
        cursor: Option<&PublicEventCursor>,
        limit: Option<u16>,
        options: RequestOptions,
    ) -> Result<PublicEventBatch, SdkError> {
        let mut path = format!("/v0/projects/{project_id}/events");
        let mut query = Vec::new();
        if let Some(cursor) = cursor {
            query.push(format!("cursor={}", percent_encode(&cursor.0)));
        }
        if let Some(limit) = limit {
            query.push(format!("limit={limit}"));
        }
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query.join("&"));
        }
        let response: EventPageResponse = self.get_json(&path, &options).await?;
        let page = response.into_batch();
        page.validate()
            .map_err(|error| SdkError::EventGap(error.to_string()))?;
        Ok(page)
    }

    pub async fn run_command(
        &self,
        project_id: gorce_protocol::ProjectId,
        command: &CommandRequest,
        options: RequestOptions,
    ) -> Result<CommandResponse, SdkError> {
        if options.idempotency_key.is_none() {
            return Err(SdkError::InvalidConfiguration(
                "command retries require an explicit retained idempotency key".to_owned(),
            ));
        }
        self.post_json(
            &format!("/v0/projects/{project_id}/commands"),
            command,
            &options,
        )
        .await
    }

    pub(crate) async fn open_event_stream(
        &self,
        project_id: gorce_protocol::ProjectId,
        cursor: Option<&PublicEventCursor>,
        options: &RequestOptions,
    ) -> Result<reqwest::Response, SdkError> {
        let mut path = format!("/v0/events/stream?project_id={project_id}");
        if let Some(cursor) = cursor {
            path.push_str("&cursor=");
            path.push_str(&percent_encode(cursor.as_str()));
        }
        let request = self.stream_request(Method::GET, &path, options)?;
        let response = request
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header(
                "Last-Event-ID",
                cursor.map(PublicEventCursor::as_str).unwrap_or_default(),
            )
            .send()
            .await?;
        Ok(response)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        options: &RequestOptions,
    ) -> Result<T, SdkError> {
        let response = self.request(Method::GET, path, options)?.send().await?;
        self.decode_response(response, "JSON").await
    }

    async fn post_json<T, R>(
        &self,
        path: &str,
        value: &T,
        options: &RequestOptions,
    ) -> Result<R, SdkError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let response = self
            .request(Method::POST, path, options)?
            .json(value)
            .send()
            .await?;
        let context = if path.ends_with("/commands") {
            "command"
        } else {
            "JSON"
        };
        self.decode_response(response, context).await
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        options: &RequestOptions,
    ) -> Result<RequestBuilder, SdkError> {
        self.request_with(&self.http, method, path, options)
    }

    fn stream_request(
        &self,
        method: Method,
        path: &str,
        options: &RequestOptions,
    ) -> Result<RequestBuilder, SdkError> {
        self.request_with(&self.stream_http, method, path, options)
    }

    fn request_with(
        &self,
        http: &reqwest::Client,
        method: Method,
        path: &str,
        options: &RequestOptions,
    ) -> Result<RequestBuilder, SdkError> {
        if !supported_route(method.clone(), path) {
            return Err(SdkError::Unsupported(
                "the requested daemon route is not implemented by the current server".to_owned(),
            ));
        }
        if options
            .cancellation_token
            .as_deref()
            .is_some_and(|token| token.is_empty())
        {
            return Err(SdkError::InvalidConfiguration(
                "cancellation token cannot be empty".to_owned(),
            ));
        }
        let url = self.url(path)?;
        let mut request = http
            .request(method, url)
            .header(PROTOCOL_VERSION_HEADER, gorce_protocol::PROTOCOL_VERSION)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(token) = &self.token {
            request = request.header(AUTHORIZATION_HEADER, format!("Bearer {}", token.as_str()));
        }
        if let Some(key) = &options.idempotency_key {
            if key.is_empty() || key.len() > gorce_protocol::MAX_IDEMPOTENCY_KEY_BYTES {
                return Err(SdkError::InvalidConfiguration(
                    "idempotency key must contain 1..=256 bytes".to_owned(),
                ));
            }
            request = request.header(IDEMPOTENCY_HEADER, key);
        }
        if let Some(token) = &options.cancellation_token {
            request = request.header(CANCELLATION_HEADER, token);
        }
        if let Some(request_id) = &options.request_id {
            request = request.header(REQUEST_ID_HEADER, request_id);
        }
        Ok(request)
    }

    fn url(&self, path: &str) -> Result<Url, SdkError> {
        let path = if self.endpoint.ends_with("/v0") && path.starts_with("/v0") {
            &path[3..]
        } else {
            path
        };
        Url::parse(&format!("{}{}", self.endpoint, path)).map_err(|error| {
            SdkError::InvalidConfiguration(format!("invalid request URL: {error}"))
        })
    }

    async fn decode_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
        context: &'static str,
    ) -> Result<T, SdkError> {
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            if context == "command" {
                if let Ok(error) = serde_json::from_slice::<gorce_protocol::CommandError>(&bytes) {
                    return Err(SdkError::Command {
                        status: status.as_u16(),
                        error,
                    });
                }
            }
            if let Ok(error) = serde_json::from_slice::<ApiError>(&bytes) {
                return Err(SdkError::Api(ApiFailure {
                    status: status.as_u16(),
                    error,
                }));
            }
            return Err(SdkError::HttpStatus {
                status: status.as_u16(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|source| decode_error(context, source))
    }
}

fn supported_route(method: Method, path: &str) -> bool {
    let route = path.split('?').next().unwrap_or(path);
    if matches!(route, "/v0/health" | "/v0/meta") {
        return method == Method::GET;
    }
    if route == "/v0/events/stream" || route == "/v0/events" {
        return method == Method::GET;
    }
    let is_project_route = route.starts_with("/v0/projects/");
    if !is_project_route {
        return false;
    }
    if route.ends_with("/commands") {
        return method == Method::POST;
    }
    (route.ends_with("/snapshot") || route.ends_with("/events")) && method == Method::GET
}

#[derive(Debug, serde::Deserialize)]
struct EventPageResponse {
    cursor: PublicEventCursor,
    events: Vec<PublicEvent>,
    #[serde(default)]
    next_cursor: Option<PublicEventCursor>,
    has_more: bool,
}

impl EventPageResponse {
    fn into_batch(self) -> PublicEventBatch {
        PublicEventBatch {
            cursor: self.cursor,
            events: self.events,
            next_cursor: self.next_cursor,
            has_more: self.has_more,
        }
    }
}

pub(crate) const SDK_VERSION: &str = "0.1";

pub fn timestamp_now() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            byte => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    encoded
}
