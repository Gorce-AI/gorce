#![forbid(unsafe_code)]

pub const DAEMON_VERSION: &str = "0.1";

pub fn daemon_version() -> &'static str {
    let _ = gorce_agent::agent_version();
    DAEMON_VERSION
}

#[cfg(test)]
mod tests {
    use super::{daemon_version, DAEMON_VERSION};

    #[test]
    fn exposes_the_daemon_version() {
        assert_eq!(daemon_version(), DAEMON_VERSION);
    }
}
