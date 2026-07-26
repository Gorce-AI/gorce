#![forbid(unsafe_code)]

pub const CORE_VERSION: &str = "0.1";

pub fn core_version() -> &'static str {
    let _ = gorce_protocol::protocol_version();
    CORE_VERSION
}

#[cfg(test)]
mod tests {
    use super::{core_version, CORE_VERSION};

    #[test]
    fn exposes_the_core_version() {
        assert_eq!(core_version(), CORE_VERSION);
    }
}
