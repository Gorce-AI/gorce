use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone)]
pub struct CancellationToken {
    value: String,
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CancellationToken(REDACTED)")
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            value: format!("gorce-cancel-{}", Uuid::new_v4()),
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn from_value(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Wait until this token is cancelled.
    ///
    /// This is intentionally separate from the transport header value. It lets
    /// SDK operations interrupt local retry/backoff waits without exposing any
    /// transport or UI concerns to callers.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}
