# Changelog

All notable changes to Gorce will be documented here.

The format follows the principles of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow Semantic Versioning where applicable.

## [Unreleased]

### Added

- Initial Rust monorepo scaffold for Gorce v0.1.
- API placeholders, architecture documentation, and repository governance files.

### Changed

- Raised the workspace MSRV to Rust 1.88 and updated the TUI to ratatui 0.30.2
  with crossterm 0.29.0, removing the vulnerable TUI dependency closure.
- Release validation now requires locked workspace gates, the pinned Rust
  1.97.1 three-platform CI gate, and clean `cargo audit --deny warnings`; no
  release may be made from an intermediate red-audit commit.
