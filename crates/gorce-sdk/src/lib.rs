#![forbid(unsafe_code)]

pub const SDK_VERSION: &str = "0.1";

pub fn sdk_version() -> &'static str {
    let _ = gorce_protocol::protocol_version();
    SDK_VERSION
}

#[cfg(test)]
mod tests {
    use super::{sdk_version, SDK_VERSION};

    #[test]
    fn exposes_the_sdk_version() {
        assert_eq!(sdk_version(), SDK_VERSION);
    }
}
