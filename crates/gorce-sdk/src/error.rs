use std::fmt::{Display, Formatter};

use gorce_protocol::CommandError;

use crate::models::ApiFailure;

pub enum SdkError {
    InvalidConfiguration(String),
    Discovery(String),
    Token(String),
    Io(std::io::Error),
    Transport(reqwest::Error),
    Api(ApiFailure),
    Command {
        status: u16,
        error: CommandError,
    },
    HttpStatus {
        status: u16,
    },
    Decode {
        context: &'static str,
        source: serde_json::Error,
    },
    Cancelled,
    EventGap(String),
    Unsupported(String),
}

impl std::fmt::Debug for SdkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(_) => formatter.write_str("SdkError::InvalidConfiguration"),
            Self::Discovery(_) => formatter.write_str("SdkError::Discovery"),
            Self::Token(_) => formatter.write_str("SdkError::Token"),
            Self::Io(_) => formatter.write_str("SdkError::Io"),
            Self::Transport(_) => formatter.write_str("SdkError::Transport"),
            Self::Api(failure) => formatter
                .debug_struct("SdkError::Api")
                .field("status", &failure.status)
                .finish(),
            Self::Command { status, .. } => formatter
                .debug_struct("SdkError::Command")
                .field("status", status)
                .finish(),
            Self::HttpStatus { status } => formatter
                .debug_struct("SdkError::HttpStatus")
                .field("status", status)
                .finish(),
            Self::Decode { context, .. } => formatter
                .debug_struct("SdkError::Decode")
                .field("context", context)
                .finish(),
            Self::Cancelled => formatter.write_str("SdkError::Cancelled"),
            Self::EventGap(_) => formatter.write_str("SdkError::EventGap"),
            Self::Unsupported(_) => formatter.write_str("SdkError::Unsupported"),
        }
    }
}

impl Display for SdkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(_) => formatter.write_str("invalid configuration"),
            Self::Discovery(_) => formatter.write_str("daemon discovery failed"),
            Self::Token(_) => formatter.write_str("token loading failed"),
            Self::Io(_) => formatter.write_str("I/O error"),
            Self::Transport(_) => formatter.write_str("HTTP transport failed"),
            Self::Api(failure) => {
                write!(formatter, "daemon returned HTTP status {}", failure.status)
            }
            Self::Command { status, error } => write!(
                formatter,
                "daemon rejected command with HTTP status {status}: {}",
                error.message
            ),
            Self::HttpStatus { status } => {
                write!(formatter, "daemon returned HTTP status {status}")
            }
            Self::Decode { context, .. } => write!(formatter, "invalid {context} response"),
            Self::Cancelled => formatter.write_str("operation cancelled"),
            Self::EventGap(_) => formatter.write_str("event stream requires resynchronization"),
            Self::Unsupported(_) => formatter.write_str("unsupported operation"),
        }
    }
}

impl std::error::Error for SdkError {}

impl From<std::io::Error> for SdkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<reqwest::Error> for SdkError {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error)
    }
}

pub(crate) fn decode_error(context: &'static str, source: serde_json::Error) -> SdkError {
    SdkError::Decode { context, source }
}
