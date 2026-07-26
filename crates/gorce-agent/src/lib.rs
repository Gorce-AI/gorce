#![forbid(unsafe_code)]

pub const AGENT_VERSION: &str = "0.1";

pub fn agent_version() -> &'static str {
    let _ = gorce_core::core_version();
    let _ = gorce_protocol::protocol_version();
    let _ = gorce_store::storage_format_version();
    AGENT_VERSION
}

#[cfg(test)]
mod tests {
    use super::{agent_version, AGENT_VERSION};

    #[test]
    fn exposes_the_agent_version() {
        assert_eq!(agent_version(), AGENT_VERSION);
    }
}
