use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::sync::Notify;

/// A durable, edge-triggered request to resume a paused event stream.
///
/// The generation is incremented before notification. Consumers compare the
/// generation as well as waiting on the notification, so a request made just
/// before a wait cannot be lost and a request from an earlier retry cycle
/// cannot accidentally resume a later one.
#[derive(Clone)]
pub struct RetrySignal {
    generation: Arc<AtomicU64>,
    notify: Arc<Notify>,
}

impl std::fmt::Debug for RetrySignal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetrySignal")
            .field("generation", &self.generation())
            .finish()
    }
}

impl RetrySignal {
    pub fn new() -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Request that a retryable stream skip its current backoff or resume
    /// after it has paused at its retry limit.
    pub fn request(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.notify.notify_waiters();
    }

    /// Alias for [`Self::request`].
    pub fn request_retry(&self) {
        self.request();
    }

    /// Alias for [`Self::request`].
    pub fn signal(&self) {
        self.request();
    }

    /// Alias for [`Self::request`].
    pub fn retry(&self) {
        self.request();
    }

    /// Return the current monotonic request generation.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) async fn wait_for_change(&self, observed: u64) {
        loop {
            if self.generation() != observed {
                return;
            }
            let notified = self.notify.notified();
            if self.generation() != observed {
                continue;
            }
            notified.await;
        }
    }
}

impl Default for RetrySignal {
    fn default() -> Self {
        Self::new()
    }
}
