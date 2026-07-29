use std::path::{Path, PathBuf};
use std::process::Command;

use crate::auth::TokenLoader;
use crate::discovery::DaemonDiscovery;
use crate::error::SdkError;
use crate::models::{DiagnosticCheck, DiagnosticReport, DiagnosticStatus};
use crate::Client;

#[derive(Debug, Clone)]
pub struct DiagnosticOptions {
    pub current_dir: PathBuf,
    pub project_id: Option<gorce_protocol::ProjectId>,
}

impl Default for DiagnosticOptions {
    fn default() -> Self {
        Self {
            current_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            project_id: None,
        }
    }
}

pub async fn run_diagnostics(options: DiagnosticOptions) -> DiagnosticReport {
    let mut checks = Vec::new();
    let discovered = match DaemonDiscovery::new().discover() {
        Ok(value) => {
            checks.push(DiagnosticCheck {
                name: "daemon descriptor".to_owned(),
                status: DiagnosticStatus::Pass,
                message: "descriptor discovered".to_owned(),
            });
            Some(value)
        }
        Err(error) => {
            checks.push(DiagnosticCheck {
                name: "daemon descriptor".to_owned(),
                status: DiagnosticStatus::Fail,
                message: safe_error(&error),
            });
            None
        }
    };

    if let Some(daemon) = discovered {
        checks.push(DiagnosticCheck {
            name: "token".to_owned(),
            status: DiagnosticStatus::Pass,
            message: "token loaded".to_owned(),
        });
        match Client::from_discovered(daemon) {
            Ok(client) => match client.health().await {
                Ok(health) => checks.push(DiagnosticCheck {
                    name: "daemon".to_owned(),
                    status: DiagnosticStatus::Pass,
                    message: format!("healthy ({})", health.version),
                }),
                Err(error) => checks.push(DiagnosticCheck {
                    name: "daemon".to_owned(),
                    status: DiagnosticStatus::Fail,
                    message: safe_error(&error),
                }),
            },
            Err(error) => checks.push(DiagnosticCheck {
                name: "daemon".to_owned(),
                status: DiagnosticStatus::Fail,
                message: safe_error(&error),
            }),
        }
    } else if let Err(error) = TokenLoader::new().load(None) {
        checks.push(DiagnosticCheck {
            name: "token".to_owned(),
            status: DiagnosticStatus::Fail,
            message: safe_error(&error),
        });
    }

    checks.push(project_check(&options.current_dir, options.project_id));
    checks.push(git_check(&options.current_dir));
    checks.push(terminal_check());
    DiagnosticReport { checks }
}

fn project_check(path: &Path, project_id: Option<gorce_protocol::ProjectId>) -> DiagnosticCheck {
    let has_git = path.join(".git").exists() || git_root(path).is_some();
    let status = if has_git {
        DiagnosticStatus::Pass
    } else {
        DiagnosticStatus::Warn
    };
    let message = match project_id {
        Some(_) if has_git => "project context supplied and repository found",
        Some(_) => "project context supplied; repository metadata was not found",
        None if has_git => "repository found; no project id supplied",
        None => "no project id or repository metadata found",
    };
    DiagnosticCheck {
        name: "project".to_owned(),
        status,
        message: message.to_owned(),
    }
}

fn git_check(path: &Path) -> DiagnosticCheck {
    if git_root(path).is_some() {
        DiagnosticCheck {
            name: "git".to_owned(),
            status: DiagnosticStatus::Pass,
            message: "Git repository detected".to_owned(),
        }
    } else {
        DiagnosticCheck {
            name: "git".to_owned(),
            status: DiagnosticStatus::Warn,
            message: "Git repository was not detected".to_owned(),
        }
    }
}

fn git_root(path: &Path) -> Option<PathBuf> {
    Command::new("git")
        .args(["-C", path.to_str()?, "rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|root| PathBuf::from(root.trim()))
}

fn terminal_check() -> DiagnosticCheck {
    use std::io::IsTerminal;
    let has_term = std::env::var_os("TERM").is_some();
    let interactive = std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
    if has_term && interactive {
        DiagnosticCheck {
            name: "terminal".to_owned(),
            status: DiagnosticStatus::Pass,
            message: "interactive terminal capabilities detected".to_owned(),
        }
    } else if has_term {
        DiagnosticCheck {
            name: "terminal".to_owned(),
            status: DiagnosticStatus::Warn,
            message: "terminal environment detected; output is not interactive".to_owned(),
        }
    } else {
        DiagnosticCheck {
            name: "terminal".to_owned(),
            status: DiagnosticStatus::Warn,
            message: "TERM is not set; use JSON or NDJSON output".to_owned(),
        }
    }
}

fn safe_error(error: &SdkError) -> String {
    error.to_string()
}
