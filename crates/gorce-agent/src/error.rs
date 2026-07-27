use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    InvalidInput(String),
    NotFound(String),
    Conflict(String),
    CapabilityDenied(String),
    BudgetExceeded(String),
    DepthExceeded,
    ConcurrencyExceeded,
    Cancelled,
    NeedsReconciliation(String),
    LeaseExpired,
    Fenced,
    CircuitOpen,
    MailboxFull,
    MessageTooLarge,
    Unauthorized,
    NotReady(String),
    ApprovalRequired,
    Unsupported(String),
    CursorExpired { requested: u64, oldest: u64 },
    Persistence(String),
    Executor(String),
    Verifier(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "invalid input: {message}"),
            Self::NotFound(message) => write!(formatter, "not found: {message}"),
            Self::Conflict(message) => write!(formatter, "conflict: {message}"),
            Self::CapabilityDenied(message) => write!(formatter, "capability denied: {message}"),
            Self::BudgetExceeded(message) => write!(formatter, "budget exceeded: {message}"),
            Self::DepthExceeded => formatter.write_str("agent depth limit exceeded"),
            Self::ConcurrencyExceeded => formatter.write_str("agent concurrency limit exceeded"),
            Self::Cancelled => formatter.write_str("operation cancelled"),
            Self::NeedsReconciliation(message) => {
                write!(formatter, "execution needs reconciliation: {message}")
            }
            Self::LeaseExpired => formatter.write_str("lease expired"),
            Self::Fenced => formatter.write_str("lease fencing token is stale"),
            Self::CircuitOpen => formatter.write_str("circuit breaker is open"),
            Self::MailboxFull => formatter.write_str("mailbox is full"),
            Self::MessageTooLarge => formatter.write_str("message exceeds the mailbox limit"),
            Self::Unauthorized => formatter.write_str("sender is not authorized"),
            Self::NotReady(message) => write!(formatter, "not ready: {message}"),
            Self::ApprovalRequired => formatter.write_str("human approval is required"),
            Self::Unsupported(message) => write!(formatter, "unsupported: {message}"),
            Self::CursorExpired { requested, oldest } => write!(
                formatter,
                "event cursor {requested} is no longer retained; oldest is {oldest}"
            ),
            Self::Persistence(message) => write!(formatter, "persistence error: {message}"),
            Self::Executor(message) => write!(formatter, "executor error: {message}"),
            Self::Verifier(message) => write!(formatter, "verifier error: {message}"),
        }
    }
}

impl std::error::Error for AgentError {}
