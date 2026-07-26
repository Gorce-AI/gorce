#![forbid(unsafe_code)]

pub const PROTOCOL_VERSION: &str = "0.1";

pub fn protocol_version() -> &'static str {
    PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::{protocol_version, PROTOCOL_VERSION};

    #[test]
    fn exposes_the_protocol_version() {
        assert_eq!(protocol_version(), PROTOCOL_VERSION);
    }
}
