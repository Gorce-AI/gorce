#![forbid(unsafe_code)]

fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn application_dependencies_compile() {
        assert_eq!(gorce_daemon::daemon_version(), "0.1");
        assert_eq!(gorce_sdk::sdk_version(), "0.1");
        assert_eq!(gorce_tui::tui_version(), "0.1");
    }
}
