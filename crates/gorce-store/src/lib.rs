#![forbid(unsafe_code)]

pub const STORAGE_FORMAT_VERSION: &str = "0.1";

pub fn storage_format_version() -> &'static str {
    let _ = gorce_core::core_version();
    STORAGE_FORMAT_VERSION
}

#[cfg(test)]
mod tests {
    use super::{storage_format_version, STORAGE_FORMAT_VERSION};

    #[test]
    fn exposes_the_storage_format_version() {
        assert_eq!(storage_format_version(), STORAGE_FORMAT_VERSION);
    }
}
