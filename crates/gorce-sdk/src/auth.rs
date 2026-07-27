use std::fmt::{Debug, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use crate::discovery::{
    canonical_runtime_dir, expected_token_path, secure_private_file, validate_loopback_endpoint,
    TOKEN_FILE_NAME,
};
use crate::error::SdkError;
use crate::models::DaemonDescriptor;

const TOKEN_ENV: &str = "GORCE_TOKEN";
const TOKEN_FILE_ENV: &str = "GORCE_TOKEN_FILE";

#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn new(value: impl Into<String>) -> Result<Self, SdkError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SdkError::Token("token is empty".to_owned()));
        }
        Ok(Self(value.trim().to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for Token {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Token(REDACTED)")
    }
}

#[derive(Clone)]
pub struct TokenLoader {
    pub path: Option<PathBuf>,
    pub use_environment: bool,
}

impl Debug for TokenLoader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenLoader")
            .field("has_explicit_path", &self.path.is_some())
            .field("use_environment", &self.use_environment)
            .finish()
    }
}

impl Default for TokenLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenLoader {
    pub fn new() -> Self {
        Self {
            path: None,
            use_environment: true,
        }
    }

    pub fn load(&self, descriptor: Option<&DaemonDescriptor>) -> Result<Token, SdkError> {
        if self.use_environment {
            if let Ok(value) = std::env::var(TOKEN_ENV) {
                return Token::new(value);
            }
        }

        let path = if let Some(descriptor) = descriptor {
            validate_loopback_endpoint(&descriptor.endpoint)?;
            let runtime = canonical_runtime_dir().ok_or_else(|| {
                SdkError::Token("the private per-user runtime directory is unavailable".to_owned())
            })?;
            let expected = expected_token_path(&runtime);
            if descriptor.token_file.as_deref() != Some(expected.as_path()) {
                return Err(SdkError::Token(
                    "the descriptor token is not the canonical sibling token".to_owned(),
                ));
            }
            Some(expected)
        } else {
            self.path
                .clone()
                .or_else(|| std::env::var_os(TOKEN_FILE_ENV).map(PathBuf::from))
                .or_else(default_token_path)
        };
        let path =
            path.ok_or_else(|| SdkError::Token("no token source was configured".to_owned()))?;
        read_token_file(&path)
    }
}

pub fn default_token_path() -> Option<PathBuf> {
    canonical_runtime_dir().map(|path| expected_token_path(&path))
}

pub fn config_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("GORCE_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("gorce"));
    }
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("gorce"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/gorce"))
}

pub(crate) fn read_token_file(path: &Path) -> Result<Token, SdkError> {
    let safe_path = secure_private_file(path, TOKEN_FILE_NAME)?;
    let runtime = canonical_runtime_dir().ok_or_else(|| {
        SdkError::Token("the private per-user runtime directory is unavailable".to_owned())
    })?;
    if safe_path.parent() != Some(runtime.as_path()) {
        return Err(SdkError::Token(
            "the token is outside the canonical runtime directory".to_owned(),
        ));
    }
    let value = fs::read_to_string(safe_path)
        .map_err(|_| SdkError::Token("the canonical daemon token cannot be read".to_owned()))?;
    Token::new(value)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::read_token_file;

    #[test]
    fn rejects_symlink_and_world_readable_tokens() {
        let root = std::env::temp_dir().join(format!("gorce-sdk-token-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o700);
        let token = root.join("daemon.token");
        fs::write(&token, "secret\n").unwrap();
        set_mode(&token, 0o644);
        assert!(read_token_file(&token).is_err());
        set_mode(&token, 0o600);
        #[cfg(unix)]
        {
            let target = root.join("token-target");
            fs::rename(&token, &target).unwrap();
            std::os::unix::fs::symlink(&target, &token).unwrap();
            assert!(read_token_file(&token).is_err());
        }
        let _ = fs::remove_dir_all(root);
    }

    fn set_mode(path: &PathBuf, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }
}
