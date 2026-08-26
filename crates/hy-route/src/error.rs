use thiserror::Error;

/// Compile / I/O / direct-dial errors for client routing.
#[derive(Debug, Error)]
pub enum Error {
    #[error("line {line}: {msg}")]
    Compile { line: usize, msg: String },
    #[error("read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("direct: {0}")]
    Direct(String),
}

impl Error {
    pub(crate) fn compile(line: usize, msg: impl Into<String>) -> Self {
        Self::Compile {
            line,
            msg: msg.into(),
        }
    }

    pub(crate) fn direct(msg: impl Into<String>) -> Self {
        Self::Direct(msg.into())
    }
}
