use thiserror::Error;

/// Errors that cross the core Client/Server boundary.
///
/// Mirrors `core/errors` in apernet/hysteria. `StreamLimitReached` is
/// intentionally **not** wrapped as [`Error::Closed`].
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid config: {field}: {reason}")]
    Config { field: &'static str, reason: String },

    #[error("connect error: {0}")]
    Connect(String),

    #[error("authentication error, HTTP status code: {status}")]
    Auth { status: u16 },

    #[error("dial error: {0}")]
    Dial(String),

    #[error("connection closed{}", .0.as_ref().map(|e| format!(": {e}")).unwrap_or_default())]
    Closed(Option<String>),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("stream limit reached")]
    StreamLimitReached,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("quic error: {0}")]
    Quic(String),
}

impl Error {
    pub fn config(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Config {
            field,
            reason: reason.into(),
        }
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
}
