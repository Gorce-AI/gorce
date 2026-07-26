#![forbid(unsafe_code)]

pub const TUI_VERSION: &str = "0.1";

pub fn tui_version() -> &'static str {
    let _ = gorce_sdk::sdk_version();
    TUI_VERSION
}

#[cfg(test)]
mod tests {
    use super::{tui_version, TUI_VERSION};

    #[test]
    fn exposes_the_tui_version() {
        assert_eq!(tui_version(), TUI_VERSION);
    }
}
