use thiserror::Error;

/// Compile / I/O errors for a local Shadowrocket-style rules file.
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
}

impl Error {
    pub(crate) fn compile(line: usize, msg: impl Into<String>) -> Self {
        Self::Compile {
            line,
            msg: msg.into(),
        }
    }
}
