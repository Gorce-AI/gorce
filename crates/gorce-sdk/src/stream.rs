use std::collections::VecDeque;
use std::time::Duration;

use gorce_protocol::{ProjectId, PublicEvent, PublicEventBatch, PublicEventCursor};
use serde_json::Value;

use crate::cancellation::CancellationToken;
use crate::client::{Client, RequestOptions};
use crate::error::SdkError;
use crate::models::EventStreamItem;
use crate::retry::RetrySignal;

/// Maximum size of one SSE frame, including its delimiter.
///
/// An unterminated frame is held in memory while the response is read. The
/// bound makes an untrusted stream fail closed instead of allowing that buffer
/// to grow without limit.
pub const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;

impl Client {
    pub fn event_stream(
        &self,
        project_id: ProjectId,
        cursor: Option<PublicEventCursor>,
    ) -> EventStream {
        EventStream::new(self.clone(), project_id, cursor)
    }

    pub fn event_stream_with_options(
        &self,
        project_id: ProjectId,
        cursor: Option<PublicEventCursor>,
        options: EventStreamOptions,
    ) -> EventStream {
        EventStream::with_options(self.clone(), project_id, cursor, options)
    }
}

#[derive(Debug, Clone)]
pub struct EventStreamOptions {
    pub max_reconnects: Option<u32>,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub cancellation: Option<CancellationToken>,
    pub retry_signal: Option<RetrySignal>,
}

impl Default for EventStreamOptions {
    fn default() -> Self {
        Self {
            max_reconnects: None,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            cancellation: None,
            retry_signal: None,
        }
    }
}

impl EventStreamOptions {
    pub fn with_retry_signal(mut self, signal: RetrySignal) -> Self {
        self.retry_signal = Some(signal);
        self
    }
}

/// Transport state changes emitted by [`EventStream`].
///
/// The lifecycle is deliberately transport-shaped. It contains no terminal,
/// rendering, or application state and carries no secret-bearing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationMode {
    /// Reconcile from the last checkpoint retained by the stream. The
    /// checkpoint may be `None` when the established stream has not emitted
    /// an event yet; that is a valid origin checkpoint.
    Delta,
    /// Replace the origin after the daemon reported that the retained
    /// checkpoint cannot be used.
    Replace,
}

/// Compatibility name for callers that describe the mode as an origin.
pub type ReconciliationOrigin = ReconciliationMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStreamLifecycle {
    Connecting,
    Connected,
    Reconnecting {
        attempt: u32,
        backoff: Duration,
    },
    /// A retryable stream is waiting for an explicit [`RetrySignal`]. No
    /// reconnect attempt is active while this lifecycle is outstanding.
    RetryPaused {
        attempt: u32,
    },
    /// Kept for source compatibility. Event streams no longer emit an
    /// ordinary replay lifecycle; reconciliation is always explicit.
    #[deprecated(note = "event streams use Reconciling with a mode")]
    Replaying,
    Reconciling {
        mode: ReconciliationMode,
    },
    SnapshotPage,
    Reconciled,
    TerminalFailure,
}

/// An observable update from an [`EventStream`].
#[derive(Debug, Clone, PartialEq)]
pub enum EventStreamUpdate {
    Lifecycle(EventStreamLifecycle),
    Item(EventStreamItem),
}

struct RetryState {
    backoff: Duration,
    generation: u64,
    paused: bool,
}

enum ConnectionResult {
    Connected,
    Reconcile,
}

pub struct EventStream {
    client: Client,
    project_id: ProjectId,
    // Keep the protocol cursor opaque all the way through the stream. The
    // string view is only used by Client's URL/header transport boundary.
    cursor: Option<PublicEventCursor>,
    options: EventStreamOptions,
    response: Option<reqwest::Response>,
    buffer: Vec<u8>,
    pending: VecDeque<EventStreamUpdate>,
    reconnects: u32,
    started: bool,
    connected_once: bool,
    retry_signal: RetrySignal,
    retry: Option<RetryState>,
    reconciliation_requested: bool,
    reconciliation_started: bool,
    reconciliation_mode: Option<ReconciliationMode>,
    // This is a staged resume candidate. It is never committed to `cursor`
    // until SSE has reopened successfully after reconciliation.
    reconciliation_cursor: Option<PublicEventCursor>,
    // Cursor identities observed in the current reconciliation. This is
    // intentionally equality-only: protocol cursors remain opaque.
    reconciliation_seen_cursors: Vec<PublicEventCursor>,
    reconciliation_ready: bool,
    terminal: bool,
    terminal_error: Option<SdkError>,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventStream")
            .field("project_id", &self.project_id)
            .field("cursor", &self.cursor)
            .field("reconnects", &self.reconnects)
            .finish()
    }
}

impl EventStream {
    pub fn new(client: Client, project_id: ProjectId, cursor: Option<PublicEventCursor>) -> Self {
        Self::with_options(client, project_id, cursor, EventStreamOptions::default())
    }

    pub fn with_options(
        client: Client,
        project_id: ProjectId,
        cursor: Option<PublicEventCursor>,
        options: EventStreamOptions,
    ) -> Self {
        let retry_signal = options.retry_signal.clone().unwrap_or_default();
        Self {
            client,
            project_id,
            cursor,
            options,
            response: None,
            buffer: Vec::new(),
            pending: VecDeque::new(),
            reconnects: 0,
            started: false,
            connected_once: false,
            retry_signal,
            retry: None,
            reconciliation_requested: false,
            reconciliation_started: false,
            reconciliation_mode: None,
            reconciliation_cursor: None,
            reconciliation_seen_cursors: Vec::new(),
            reconciliation_ready: false,
            terminal: false,
            terminal_error: None,
        }
    }

    /// Return the opaque resume checkpoint as protocol data.
    pub fn public_cursor(&self) -> Option<&PublicEventCursor> {
        self.cursor.as_ref()
    }

    /// Return the resume checkpoint in the legacy string view.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_ref().map(PublicEventCursor::as_str)
    }

    /// Return the signal associated with this stream. Keeping a clone before
    /// calling [`Self::next_update`] allows another task to wake a paused
    /// stream without using the cancellation control.
    pub fn retry_signal(&self) -> RetrySignal {
        self.retry_signal.clone()
    }

    /// Read the next transport or data update.
    ///
    /// Lifecycle updates are returned before the operation they describe. In
    /// particular, `Reconnecting` is returned before any retry backoff starts.
    pub async fn next_update(&mut self) -> Result<EventStreamUpdate, SdkError> {
        loop {
            if self.is_cancelled() {
                if self.terminal {
                    self.pending.retain(|update| {
                        matches!(
                            update,
                            EventStreamUpdate::Lifecycle(EventStreamLifecycle::TerminalFailure)
                        )
                    });
                } else {
                    self.mark_terminal(SdkError::Cancelled);
                }
            }
            if let Some(update) = self.pending.pop_front() {
                return Ok(update);
            }
            if self.terminal {
                return Err(self.terminal_error.take().unwrap_or_else(|| {
                    SdkError::EventGap("event stream has terminated".to_owned())
                }));
            }
            if self.is_cancelled() {
                self.mark_terminal(SdkError::Cancelled);
                continue;
            }

            if !self.started {
                self.started = true;
                self.queue_lifecycle(EventStreamLifecycle::Connecting);
                continue;
            }

            if let Some(retry) = self.retry.as_ref().filter(|retry| retry.paused) {
                let retry = RetryState {
                    backoff: retry.backoff,
                    generation: retry.generation,
                    paused: retry.paused,
                };
                if let Err(error) = self.wait_for_retry(&retry).await {
                    self.mark_terminal(error);
                } else {
                    self.retry = None;
                    self.queue_lifecycle(EventStreamLifecycle::Reconnecting {
                        attempt: self.reconnects,
                        backoff: Duration::ZERO,
                    });
                    // A manual retry starts a fresh automatic retry budget,
                    // but it does not alter any cursor or staged page state.
                    self.reconnects = 0;
                }
                continue;
            }

            if self.reconciliation_requested && self.retry.is_none() {
                if !self.reconciliation_started {
                    self.reconciliation_started = true;
                    self.queue_lifecycle(EventStreamLifecycle::Reconciling {
                        mode: self
                            .reconciliation_mode
                            .unwrap_or(ReconciliationMode::Delta),
                    });
                    continue;
                }
                match self.read_snapshot_page().await {
                    Ok(()) => {}
                    Err(error)
                        if is_cursor_reset_error(&error)
                            && self.reconciliation_mode == Some(ReconciliationMode::Delta) =>
                    {
                        self.begin_origin_reconciliation();
                    }
                    Err(error) if is_cursor_reset_error(&error) => self.mark_terminal(error),
                    Err(error) if is_cancelled_error(&error) => self.mark_terminal(error),
                    Err(error) if is_retryable_error(&error) => self.schedule_retry(error),
                    Err(error) => self.mark_terminal(error),
                }
                continue;
            }

            if self.response.is_none() {
                if let Some(retry) = self.retry.take() {
                    if let Err(error) = self.wait_for_retry(&retry).await {
                        self.mark_terminal(error);
                        continue;
                    }
                    if self.reconciliation_requested {
                        continue;
                    }
                }

                match self.connect_once().await {
                    Ok(ConnectionResult::Connected) => continue,
                    Ok(ConnectionResult::Reconcile) => {
                        continue;
                    }
                    Err(error) if is_cancelled_error(&error) => {
                        self.mark_terminal(error);
                        continue;
                    }
                    Err(error) => {
                        if is_retryable_error(&error) {
                            self.schedule_retry(error);
                        } else {
                            self.mark_terminal(error);
                        }
                        continue;
                    }
                }
            }

            let frame_result = self.read_next_frame().await;
            let frame = match frame_result {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    self.response = None;
                    self.begin_reconnect_reconciliation();
                    self.schedule_retry(SdkError::EventGap(
                        "event stream disconnected without a snapshot".to_owned(),
                    ));
                    continue;
                }
                Err(error) if is_cancelled_error(&error) => {
                    self.response = None;
                    self.mark_terminal(error);
                    continue;
                }
                Err(error) => {
                    self.response = None;
                    self.begin_reconnect_reconciliation();
                    if is_retryable_error(&error) {
                        self.schedule_retry(error);
                    } else {
                        self.mark_terminal(error);
                    }
                    continue;
                }
            };

            if frame.data.is_empty() && frame.event.as_deref() != Some("resync_required") {
                // An id-only SSE frame is not a decoded data update and must
                // not advance the resume checkpoint.
                continue;
            }

            match self.consume_frame(frame).await {
                Ok(()) => {}
                Err(error) => self.mark_terminal(error),
            }
        }
    }

    /// Read the next data item, skipping lifecycle updates.
    ///
    /// This retains the pre-lifecycle API for consumers that do not need
    /// transport state. Composition clients should use [`Self::next_update`].
    pub async fn next(&mut self) -> Result<EventStreamItem, SdkError> {
        loop {
            match self.next_update().await? {
                EventStreamUpdate::Lifecycle(_) => {}
                EventStreamUpdate::Item(item) => return Ok(item),
            }
        }
    }

    /// Alias for [`Self::next`] for callers that want to make the data-only
    /// behavior explicit.
    pub async fn next_item(&mut self) -> Result<EventStreamItem, SdkError> {
        self.next().await
    }

    async fn connect_once(&mut self) -> Result<ConnectionResult, SdkError> {
        let cursor = if self.reconciliation_ready {
            self.reconciliation_cursor.as_ref()
        } else {
            self.cursor.as_ref()
        };
        if !self.reconciliation_ready {
            if let Some(cursor) = cursor {
                cursor
                    .validate()
                    .map_err(|error| SdkError::EventGap(error.to_string()))?;
            }
        }
        let cancellation = self.options.cancellation.clone();
        let request_options = cancellation
            .as_ref()
            .map(|token| RequestOptions::default().cancellation_token(token.value()))
            .unwrap_or_default();
        let request = self
            .client
            .open_event_stream(self.project_id, cursor, &request_options);
        let response = if let Some(token) = cancellation {
            tokio::select! {
                result = request => result?,
                _ = token.cancelled() => return Err(SdkError::Cancelled),
            }
        } else {
            request.await?
        };

        if self.is_cancelled() {
            return Err(SdkError::Cancelled);
        }

        if response.status().is_success() && !is_valid_sse_response(&response) {
            return Err(SdkError::EventGap(
                "successful event-stream response was not valid SSE".to_owned(),
            ));
        }

        if response.status() == reqwest::StatusCode::OK {
            self.response = Some(response);
            self.buffer.clear();
            self.reconnects = 0;
            self.connected_once = true;
            if self.reconciliation_ready {
                let candidate = self.reconciliation_cursor.take().ok_or_else(|| {
                    SdkError::EventGap(
                        "reconciliation completed without a candidate cursor".to_owned(),
                    )
                })?;
                self.cursor = Some(candidate);
                self.reconciliation_ready = false;
                self.reconciliation_mode = None;
                self.queue_lifecycle(EventStreamLifecycle::Reconciled);
            }
            self.queue_lifecycle(EventStreamLifecycle::Connected);
            return Ok(ConnectionResult::Connected);
        }

        let status = response.status().as_u16();
        if status == 409 || status == 410 {
            self.response = None;
            self.begin_origin_reconciliation();
            return Ok(ConnectionResult::Reconcile);
        }
        Err(SdkError::HttpStatus { status })
    }

    async fn read_next_frame(&mut self) -> Result<Option<SseFrame>, SdkError> {
        let cancellation = self.options.cancellation.clone();
        let response = self.response.as_mut().ok_or_else(|| {
            SdkError::EventGap("event stream disconnected without a snapshot".to_owned())
        })?;
        if let Some(token) = cancellation {
            tokio::select! {
                result = read_frame(response, &mut self.buffer) => result,
                _ = token.cancelled() => Err(SdkError::Cancelled),
            }
        } else {
            read_frame(response, &mut self.buffer).await
        }
    }

    async fn consume_frame(&mut self, frame: SseFrame) -> Result<(), SdkError> {
        if frame.event.as_deref() == Some("resync_required") {
            self.response = None;
            self.begin_origin_reconciliation();
            return Ok(());
        }

        let value: Value =
            serde_json::from_str(&frame.data).map_err(|source| SdkError::Decode {
                context: "SSE event",
                source,
            })?;

        if frame.event.as_deref() == Some("snapshot") || value.get("events").is_some() {
            let batch: PublicEventBatch =
                serde_json::from_value(value).map_err(|source| SdkError::Decode {
                    context: "SSE snapshot",
                    source,
                })?;
            batch
                .validate()
                .map_err(|error| SdkError::EventGap(error.to_string()))?;
            self.update_from_snapshot(&batch);
            self.queue_lifecycle(EventStreamLifecycle::SnapshotPage);
            self.pending
                .push_back(EventStreamUpdate::Item(EventStreamItem::Snapshot(batch)));
            return Ok(());
        }

        let event: PublicEvent =
            serde_json::from_value(value).map_err(|source| SdkError::Decode {
                context: "SSE event",
                source,
            })?;
        event
            .validate()
            .map_err(|error| SdkError::EventGap(error.to_string()))?;

        let id = frame.id.filter(|value| !value.is_empty()).ok_or_else(|| {
            SdkError::EventGap("data-bearing live event omitted its SSE event ID".to_owned())
        })?;
        let checkpoint = PublicEventCursor(id);
        checkpoint
            .validate()
            .map_err(|error| SdkError::EventGap(error.to_string()))?;
        // The checkpoint is advanced only after JSON decoding and protocol
        // validation have both succeeded. The ID remains opaque protocol data.
        self.cursor = Some(checkpoint);
        self.pending
            .push_back(EventStreamUpdate::Item(EventStreamItem::Event(event)));
        Ok(())
    }

    async fn read_snapshot_page(&mut self) -> Result<(), SdkError> {
        let cancellation = self.options.cancellation.clone();
        let cursor = self.reconciliation_cursor.clone();
        let request_options = self.request_options();
        let request = self.client.list_public_events_with_options(
            self.project_id,
            cursor.as_ref(),
            None,
            request_options,
        );
        let batch = if let Some(token) = cancellation {
            tokio::select! {
                result = request => result?,
                _ = token.cancelled() => return Err(SdkError::Cancelled),
            }
        } else {
            request.await?
        };
        // Client validates this response too; retain the validation at this
        // checkpoint boundary so this method cannot advance on an unvalidated
        // page if the transport implementation changes.
        batch
            .validate()
            .map_err(|error| SdkError::EventGap(error.to_string()))?;

        if let Some(requested) = cursor.as_ref() {
            if batch.cursor != *requested {
                return Err(SdkError::EventGap(
                    "event reconciliation page cursor did not match its request cursor".to_owned(),
                ));
            }
        }
        if self
            .reconciliation_seen_cursors
            .iter()
            .any(|seen| seen == &batch.cursor)
        {
            return Err(SdkError::EventGap(
                "event reconciliation repeated a page cursor".to_owned(),
            ));
        }

        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor.clone();
        let continuation = if has_more {
            Some(next_cursor.clone().ok_or_else(|| {
                SdkError::EventGap(
                    "event resynchronization omitted its continuation cursor".to_owned(),
                )
            })?)
        } else {
            None
        };
        if let Some(next_cursor) = next_cursor.as_ref() {
            if next_cursor == &batch.cursor
                || self
                    .reconciliation_seen_cursors
                    .iter()
                    .any(|seen| seen == next_cursor)
            {
                return Err(SdkError::EventGap(
                    "event reconciliation repeated a continuation cursor".to_owned(),
                ));
            }
        }
        let candidate = batch
            .next_cursor
            .clone()
            .unwrap_or_else(|| batch.cursor.clone());
        self.reconciliation_seen_cursors.push(batch.cursor.clone());
        self.queue_lifecycle(EventStreamLifecycle::SnapshotPage);
        self.pending
            .push_back(EventStreamUpdate::Item(EventStreamItem::Snapshot(batch)));

        if has_more {
            self.reconciliation_cursor = continuation;
        } else {
            if let Some(next_cursor) = next_cursor.as_ref() {
                self.reconciliation_seen_cursors.push(next_cursor.clone());
            }
            self.reconciliation_cursor = Some(candidate);
            self.reconciliation_requested = false;
            self.reconciliation_started = false;
            self.reconciliation_ready = true;
        }
        Ok(())
    }

    fn request_options(&self) -> RequestOptions {
        self.options
            .cancellation
            .as_ref()
            .map(|token| RequestOptions::default().cancellation_token(token.value()))
            .unwrap_or_default()
    }

    fn update_from_snapshot(&mut self, batch: &PublicEventBatch) {
        // A page's returned continuation is the authoritative checkpoint,
        // including on the final page. Never infer cursor ordering locally.
        self.cursor = Some(
            batch
                .next_cursor
                .clone()
                .unwrap_or_else(|| batch.cursor.clone()),
        );
    }

    fn schedule_retry(&mut self, _error: SdkError) {
        self.reconnects = self.reconnects.saturating_add(1);
        let exhausted = self
            .options
            .max_reconnects
            .is_some_and(|maximum| self.reconnects > maximum);

        let multiplier = 2u32.saturating_pow(self.reconnects.saturating_sub(1).min(10));
        let computed_backoff = self
            .options
            .initial_backoff
            .saturating_mul(multiplier)
            .min(self.options.max_backoff);
        let backoff = if exhausted {
            Duration::ZERO
        } else {
            computed_backoff
        };
        self.retry = Some(RetryState {
            backoff,
            generation: self.retry_signal.generation(),
            paused: exhausted,
        });
        if exhausted {
            self.queue_lifecycle(EventStreamLifecycle::RetryPaused {
                attempt: self.reconnects,
            });
        } else {
            self.queue_lifecycle(EventStreamLifecycle::Reconnecting {
                attempt: self.reconnects,
                backoff,
            });
        }
    }

    fn begin_reconnect_reconciliation(&mut self) {
        if self.connected_once && !self.reconciliation_ready && !self.reconciliation_requested {
            self.reconciliation_cursor = self.cursor.clone();
            self.reconciliation_started = false;
            self.reconciliation_mode = Some(ReconciliationMode::Delta);
            self.reconciliation_seen_cursors.clear();
            self.reconciliation_requested = true;
        }
    }

    fn begin_origin_reconciliation(&mut self) {
        self.reconciliation_cursor = None;
        self.reconciliation_started = false;
        self.reconciliation_mode = Some(ReconciliationMode::Replace);
        self.reconciliation_seen_cursors.clear();
        self.reconciliation_ready = false;
        self.reconciliation_requested = true;
    }

    async fn wait_for_retry(&self, retry: &RetryState) -> Result<(), SdkError> {
        if self.retry_signal.generation() != retry.generation {
            return if self.is_cancelled() {
                Err(SdkError::Cancelled)
            } else {
                Ok(())
            };
        }

        if retry.paused {
            if let Some(token) = &self.options.cancellation {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Err(SdkError::Cancelled),
                    _ = self.retry_signal.wait_for_change(retry.generation) => Ok(()),
                }
            } else {
                self.retry_signal.wait_for_change(retry.generation).await;
                Ok(())
            }
        } else if let Some(token) = &self.options.cancellation {
            let sleep = tokio::time::sleep(retry.backoff);
            tokio::pin!(sleep);
            tokio::select! {
                biased;
                _ = token.cancelled() => Err(SdkError::Cancelled),
                _ = self.retry_signal.wait_for_change(retry.generation) => Ok(()),
                _ = &mut sleep => Ok(()),
            }
        } else {
            let sleep = tokio::time::sleep(retry.backoff);
            tokio::pin!(sleep);
            tokio::select! {
                _ = self.retry_signal.wait_for_change(retry.generation) => Ok(()),
                _ = &mut sleep => Ok(()),
            }
        }
    }

    fn queue_lifecycle(&mut self, lifecycle: EventStreamLifecycle) {
        self.pending
            .push_back(EventStreamUpdate::Lifecycle(lifecycle));
    }

    fn mark_terminal(&mut self, error: SdkError) {
        if self.terminal {
            return;
        }
        self.response = None;
        self.retry = None;
        if is_cancelled_error(&error) {
            self.pending.clear();
        }
        self.terminal = true;
        self.terminal_error = Some(error);
        self.queue_lifecycle(EventStreamLifecycle::TerminalFailure);
    }

    fn is_cancelled(&self) -> bool {
        self.options
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    }
}

struct SseFrame {
    event: Option<String>,
    id: Option<String>,
    data: String,
}

async fn read_frame(
    response: &mut reqwest::Response,
    buffer: &mut Vec<u8>,
) -> Result<Option<SseFrame>, SdkError> {
    loop {
        if let Some(end) = find_frame_end(buffer) {
            if end > MAX_SSE_FRAME_BYTES {
                return Err(SdkError::EventGap(format!(
                    "SSE frame exceeds {MAX_SSE_FRAME_BYTES} bytes"
                )));
            }
            let frame = buffer.drain(..end).collect::<Vec<_>>();
            if let Some(frame) = parse_frame(&frame)? {
                return Ok(Some(frame));
            }
            continue;
        }
        if buffer.len() > MAX_SSE_FRAME_BYTES {
            return Err(SdkError::EventGap(format!(
                "unterminated SSE frame exceeds {MAX_SSE_FRAME_BYTES} bytes"
            )));
        }
        match response.chunk().await? {
            Some(chunk) => {
                buffer.extend_from_slice(&chunk);
                if buffer.len() > MAX_SSE_FRAME_BYTES && find_frame_end(buffer).is_none() {
                    return Err(SdkError::EventGap(format!(
                        "unterminated SSE frame exceeds {MAX_SSE_FRAME_BYTES} bytes"
                    )));
                }
            }
            None => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                let frame = std::mem::take(buffer);
                return parse_frame(&frame);
            }
        }
    }
}

fn find_frame_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2)
        .or_else(|| {
            buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
        })
}

fn parse_frame(bytes: &[u8]) -> Result<Option<SseFrame>, SdkError> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| SdkError::EventGap("SSE frame was not valid UTF-8".to_owned()))?;
    let mut event = None;
    let mut id = None;
    let mut data = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event = Some(sse_value(value));
        } else if let Some(value) = line.strip_prefix("id:") {
            // Remove only the optional SSE separator space. In particular,
            // never trim or otherwise normalize an opaque checkpoint.
            id = Some(sse_value(value));
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(sse_value(value));
        }
    }
    if event.is_none() && id.is_none() && data.is_empty() {
        Ok(None)
    } else {
        Ok(Some(SseFrame {
            event,
            id,
            data: data.join("\n"),
        }))
    }
}

fn sse_value(value: &str) -> String {
    value.strip_prefix(' ').unwrap_or(value).to_owned()
}

fn is_cancelled_error(error: &SdkError) -> bool {
    matches!(error, SdkError::Cancelled)
}

fn is_retryable_error(error: &SdkError) -> bool {
    match error {
        SdkError::Transport(error) => {
            !error.is_builder() && (error.is_connect() || error.is_timeout() || error.is_body())
        }
        SdkError::HttpStatus { status } => is_retryable_status(*status),
        SdkError::Api(failure) => is_retryable_status(failure.status),
        _ => false,
    }
}

fn is_cursor_reset_error(error: &SdkError) -> bool {
    match error {
        SdkError::HttpStatus { status } => *status == 409 || *status == 410,
        SdkError::Api(failure) => failure.status == 409 || failure.status == 410,
        _ => false,
    }
}

fn is_valid_sse_response(response: &reqwest::Response) -> bool {
    response.status() == reqwest::StatusCode::OK
        && response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
}

fn is_retryable_status(status: u16) -> bool {
    status == 408 || status == 429 || (500..=599).contains(&status)
}
