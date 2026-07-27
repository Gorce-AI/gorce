use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use gorce_protocol::{MessageId, OperatorId, ProjectId};
use serde_json::Value;
use tokio::sync::{mpsc, Notify};
use uuid::Uuid;

use crate::error::{AgentError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventCursor(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope<T> {
    pub cursor: EventCursor,
    pub event: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLimits {
    pub max_events: usize,
    pub max_event_bytes: usize,
    pub max_total_bytes: usize,
}

impl EventLimits {
    pub fn bounded(
        max_events: usize,
        max_event_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self> {
        if max_events == 0
            || max_event_bytes == 0
            || max_total_bytes < max_event_bytes
            || max_events == usize::MAX
            || max_event_bytes == usize::MAX
            || max_total_bytes == usize::MAX
        {
            return Err(AgentError::InvalidInput(
                "event limits must be positive and internally consistent".to_owned(),
            ));
        }
        Ok(Self {
            max_events,
            max_event_bytes,
            max_total_bytes,
        })
    }
}

#[derive(Debug)]
struct EventState<T> {
    next: u64,
    history: VecDeque<(EventEnvelope<T>, usize)>,
    limits: EventLimits,
    total_bytes: usize,
}

#[derive(Debug)]
pub struct EventBus<T> {
    state: Arc<Mutex<EventState<T>>>,
    notify: Arc<Notify>,
}

impl<T> Clone for EventBus<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<T> EventBus<T> {
    pub fn new(capacity: usize) -> Result<Self> {
        Self::with_limits(EventLimits::bounded(
            capacity,
            1_048_576,
            capacity.saturating_mul(1_048_576),
        )?)
    }

    pub fn with_limits(limits: EventLimits) -> Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(EventState {
                next: 1,
                history: VecDeque::with_capacity(limits.max_events),
                limits,
                total_bytes: 0,
            })),
            notify: Arc::new(Notify::new()),
        })
    }

    pub fn try_publish(&self, event: T, event_bytes: usize) -> Result<EventEnvelope<T>>
    where
        T: Clone,
    {
        let mut state = self.state.lock().expect("event bus lock poisoned");
        if event_bytes > state.limits.max_event_bytes {
            return Err(AgentError::MessageTooLarge);
        }
        let envelope = EventEnvelope {
            cursor: EventCursor(state.next),
            event,
        };
        state.next = state.next.saturating_add(1);
        state.total_bytes = state.total_bytes.saturating_add(event_bytes);
        state.history.push_back((envelope.clone(), event_bytes));
        while state.history.len() > state.limits.max_events
            || state.total_bytes > state.limits.max_total_bytes
        {
            if let Some((_, bytes)) = state.history.pop_front() {
                state.total_bytes = state.total_bytes.saturating_sub(bytes);
            }
        }
        drop(state);
        self.notify.notify_waiters();
        Ok(envelope)
    }

    pub fn publish(&self, event: T) -> EventEnvelope<T>
    where
        T: Clone,
    {
        self.try_publish(event, 1)
            .expect("event exceeded configured limits")
    }

    pub fn subscribe(&self) -> EventSubscription<T> {
        self.subscribe_from(EventCursor(0))
    }

    pub fn subscribe_from(&self, cursor: EventCursor) -> EventSubscription<T> {
        EventSubscription {
            bus: self.clone(),
            next: cursor.0.saturating_add(1),
        }
    }

    pub fn events_since(&self, cursor: EventCursor) -> Result<Vec<EventEnvelope<T>>>
    where
        T: Clone,
    {
        let state = self.state.lock().expect("event bus lock poisoned");
        let oldest = match state.history.front() {
            Some((event, _)) => event.cursor.0,
            None => state.next,
        };
        let requested = cursor.0.saturating_add(1);
        if requested < oldest && !state.history.is_empty() {
            return Err(AgentError::CursorExpired { requested, oldest });
        }
        Ok(state
            .history
            .iter()
            .filter(|(event, _)| event.cursor.0 > cursor.0)
            .map(|(event, _)| event.clone())
            .collect())
    }

    pub fn latest(&self) -> EventCursor {
        let state = self.state.lock().expect("event bus lock poisoned");
        EventCursor(state.next.saturating_sub(1))
    }
}

#[derive(Debug, Clone)]
pub struct EventSubscription<T> {
    bus: EventBus<T>,
    next: u64,
}

impl<T> EventSubscription<T>
where
    T: Clone,
{
    pub fn poll(&mut self) -> Result<Option<EventEnvelope<T>>> {
        let state = self.bus.state.lock().expect("event bus lock poisoned");
        let oldest = match state.history.front() {
            Some((event, _)) => event.cursor.0,
            None => state.next,
        };
        if self.next < oldest && !state.history.is_empty() {
            return Err(AgentError::CursorExpired {
                requested: self.next,
                oldest,
            });
        }
        let event = state
            .history
            .iter()
            .find(|(event, _)| event.cursor.0 >= self.next)
            .map(|(event, _)| event.clone());
        if let Some(event) = &event {
            self.next = event.cursor.0.saturating_add(1);
        }
        Ok(event)
    }

    pub async fn next(&mut self) -> Result<Option<EventEnvelope<T>>> {
        loop {
            let notified = self.bus.notify.clone().notified_owned();
            if let Some(event) = self.poll()? {
                return Ok(Some(event));
            }
            notified.await;
        }
    }

    pub fn cursor(&self) -> EventCursor {
        EventCursor(self.next.saturating_sub(1))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MailboxEnvelope {
    pub project_id: ProjectId,
    pub team_id: Option<Uuid>,
    pub sender: OperatorId,
    pub recipient: OperatorId,
    pub message_id: MessageId,
    pub message_type: String,
    pub version: u32,
    pub correlation_id: Option<Uuid>,
    pub idempotency_key: String,
    pub payload: Value,
}

impl MailboxEnvelope {
    pub fn validate(&self, max_bytes: usize) -> Result<()> {
        if self.project_id.is_nil()
            || self.sender.is_nil()
            || self.recipient.is_nil()
            || self.message_id.is_nil()
            || self.message_type.trim().is_empty()
            || self.version == 0
            || self.idempotency_key.trim().is_empty()
        {
            return Err(AgentError::InvalidInput(
                "mailbox envelopes require complete identity and version fields".to_owned(),
            ));
        }
        let payload_bytes = serde_json::to_vec(&self.payload)
            .map_err(|error| AgentError::InvalidInput(error.to_string()))?
            .len();
        let envelope_bytes = payload_bytes
            .saturating_add(self.message_type.len())
            .saturating_add(self.idempotency_key.len())
            .saturating_add(256);
        if envelope_bytes > max_bytes {
            return Err(AgentError::MessageTooLarge);
        }
        Ok(())
    }
}

pub trait MailboxAuthorization: Send + Sync {
    fn authorize(
        &self,
        sender: OperatorId,
        recipient: OperatorId,
        project_id: ProjectId,
    ) -> Result<()>;
}

pub trait DurableMailboxPort: Send + Sync {
    fn enqueue(&self, envelope: MailboxEnvelope) -> BoxFuture<Result<()>>;
    fn receive(&self, recipient: OperatorId) -> BoxFuture<Result<Option<MailboxEnvelope>>>;
    fn acknowledge(&self, recipient: OperatorId, message_id: MessageId) -> BoxFuture<Result<()>>;
}

pub struct MailboxBroker {
    port: Arc<dyn DurableMailboxPort>,
    authorization: Arc<dyn MailboxAuthorization>,
    max_message_bytes: usize,
}

impl MailboxBroker {
    pub fn new(
        port: Arc<dyn DurableMailboxPort>,
        authorization: Arc<dyn MailboxAuthorization>,
        max_message_bytes: usize,
    ) -> Result<Self> {
        if max_message_bytes == 0 || max_message_bytes == usize::MAX {
            return Err(AgentError::InvalidInput(
                "mailbox byte limit must be positive".to_owned(),
            ));
        }
        Ok(Self {
            port,
            authorization,
            max_message_bytes,
        })
    }

    pub async fn send(&self, envelope: MailboxEnvelope) -> Result<()> {
        envelope.validate(self.max_message_bytes)?;
        self.authorization
            .authorize(envelope.sender, envelope.recipient, envelope.project_id)?;
        self.port.enqueue(envelope).await
    }

    pub async fn receive(&self, recipient: OperatorId) -> Result<Option<MailboxEnvelope>> {
        if recipient.is_nil() {
            return Err(AgentError::InvalidInput(
                "recipient must not be nil".to_owned(),
            ));
        }
        let envelope = self.port.receive(recipient).await?;
        if let Some(envelope) = &envelope {
            envelope.validate(self.max_message_bytes)?;
            if envelope.recipient != recipient {
                return Err(AgentError::Unauthorized);
            }
        }
        Ok(envelope)
    }

    pub async fn acknowledge(&self, recipient: OperatorId, message_id: MessageId) -> Result<()> {
        if recipient.is_nil() || message_id.is_nil() {
            return Err(AgentError::InvalidInput(
                "acknowledgement identity must not be nil".to_owned(),
            ));
        }
        self.port.acknowledge(recipient, message_id).await
    }
}

use crate::agent::BoxFuture;

#[derive(Debug)]
pub struct Mailbox<T> {
    sender: mpsc::Sender<T>,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<T>>>,
}

#[derive(Debug, Clone)]
pub struct MailboxSender<T> {
    sender: mpsc::Sender<T>,
}

#[derive(Debug, Clone)]
pub struct MailboxReceiver<T> {
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<T>>>,
}

pub type TypedMailbox<T> = Mailbox<T>;

impl<T> Clone for Mailbox<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
        }
    }
}

impl<T> Mailbox<T> {
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(AgentError::InvalidInput(
                "mailbox capacity must be positive".to_owned(),
            ));
        }
        let (sender, receiver) = mpsc::channel(capacity);
        Ok(Self {
            sender,
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        })
    }

    pub fn split(&self) -> (MailboxSender<T>, MailboxReceiver<T>) {
        (self.sender(), self.receiver())
    }

    pub fn send(&self, message: T) -> Result<()> {
        self.sender.try_send(message).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => AgentError::MailboxFull,
            mpsc::error::TrySendError::Closed(_) => {
                AgentError::Conflict("mailbox is closed".to_owned())
            }
        })
    }

    pub async fn send_async(&self, message: T) -> Result<()> {
        self.sender
            .send(message)
            .await
            .map_err(|_| AgentError::Conflict("mailbox is closed".to_owned()))
    }

    pub fn try_recv(&self) -> Option<T> {
        self.receiver.try_lock().ok()?.try_recv().ok()
    }

    pub fn sender(&self) -> MailboxSender<T> {
        MailboxSender {
            sender: self.sender.clone(),
        }
    }

    pub fn receiver(&self) -> MailboxReceiver<T> {
        MailboxReceiver {
            receiver: self.receiver.clone(),
        }
    }
}

impl<T> MailboxSender<T> {
    pub fn send(&self, message: T) -> Result<()> {
        self.sender.try_send(message).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => AgentError::MailboxFull,
            mpsc::error::TrySendError::Closed(_) => {
                AgentError::Conflict("mailbox is closed".to_owned())
            }
        })
    }

    pub async fn send_async(&self, message: T) -> Result<()> {
        self.sender
            .send(message)
            .await
            .map_err(|_| AgentError::Conflict("mailbox is closed".to_owned()))
    }
}

impl<T> MailboxReceiver<T> {
    pub fn try_recv(&self) -> Option<T> {
        self.receiver.try_lock().ok()?.try_recv().ok()
    }

    pub async fn recv(&self) -> Option<T> {
        self.receiver.lock().await.recv().await
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(AgentError::Cancelled)
        } else {
            Ok(())
        }
    }

    pub async fn cancelled(&self) {
        let notified = self.notify.notified();
        if !self.is_cancelled() {
            notified.await;
        }
    }
}
