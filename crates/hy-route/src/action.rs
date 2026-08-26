/// Routing decision for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Unique hy tunnel (`-c` main server).
    Proxy,
    /// Local direct dial (not implemented this step).
    Direct,
    /// Reject: do not open a tunnel.
    Reject,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Proxy => "PROXY",
            Action::Direct => "DIRECT",
            Action::Reject => "REJECT",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
