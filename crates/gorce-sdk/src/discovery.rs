use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use reqwest::Url;

use crate::auth::read_token_file;
use crate::error::SdkError;
use crate::models::DaemonDescriptor;

pub const DESCRIPTOR_FILE_NAME: &str = "daemon.json";
pub const TOKEN_FILE_NAME: &str = "daemon.token";

#[derive(Clone, Default)]
pub struct DaemonDiscovery {
    pub descriptor_path: Option<PathBuf>,
}

impl fmt::Debug for DaemonDiscovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonDiscovery")
            .field("has_explicit_path", &self.descriptor_path.is_some())
            .finish()
    }
}

impl DaemonDiscovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            descriptor_path: Some(path.into()),
        }
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        if let Some(path) = &self.descriptor_path {
            return vec![path.clone()];
        }
        canonical_runtime_dir()
            .map(|path| vec![path.join(DESCRIPTOR_FILE_NAME)])
            .unwrap_or_default()
    }

    pub fn discover(&self) -> Result<DiscoveredDaemon, SdkError> {
        let runtime = canonical_runtime_dir().ok_or_else(|| {
            SdkError::Discovery("the private per-user runtime directory is unavailable".to_owned())
        })?;
        for path in self.paths() {
            if !path.exists() {
                continue;
            }
            let descriptor = read_descriptor_in_runtime(&path, &runtime)?;
            let token_path = expected_token_path(&runtime);
            let token = read_token_file(&token_path)?;
            return Ok(DiscoveredDaemon {
                descriptor,
                descriptor_path: path,
                token,
            });
        }
        Err(SdkError::Discovery(
            "no trusted daemon descriptor was found".to_owned(),
        ))
    }
}

pub struct DiscoveredDaemon {
    pub descriptor: DaemonDescriptor,
    pub descriptor_path: PathBuf,
    pub token: crate::Token,
}

impl Clone for DiscoveredDaemon {
    fn clone(&self) -> Self {
        Self {
            descriptor: self.descriptor.clone(),
            descriptor_path: self.descriptor_path.clone(),
            token: self.token.clone(),
        }
    }
}

impl fmt::Debug for DiscoveredDaemon {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveredDaemon")
            .field("descriptor", &self.descriptor)
            .field("has_descriptor_path", &true)
            .field("token", &self.token)
            .finish()
    }
}

pub fn read_descriptor(path: &Path) -> Result<DaemonDescriptor, SdkError> {
    let parent = path
        .parent()
        .ok_or_else(|| SdkError::Discovery("descriptor has no parent directory".to_owned()))?;
    let runtime = private_directory(parent)?;
    read_descriptor_in_runtime(path, &runtime)
}

pub fn write_descriptor(path: &Path, descriptor: &DaemonDescriptor) -> Result<(), SdkError> {
    let parent = path
        .parent()
        .ok_or_else(|| SdkError::Discovery("descriptor has no parent directory".to_owned()))?;
    let runtime = private_directory(parent)?;
    if path.file_name().and_then(|name| name.to_str()) != Some(DESCRIPTOR_FILE_NAME) {
        return Err(SdkError::Discovery(
            "descriptor must use the canonical file name".to_owned(),
        ));
    }
    validate_descriptor(descriptor, &runtime)?;
    let content = serde_json::to_vec_pretty(descriptor)
        .map_err(|error| SdkError::Discovery(format!("cannot encode descriptor: {error}")))?;
    let temporary = runtime.join(".daemon.json.tmp");
    fs::write(&temporary, content)?;
    set_private_file(&temporary)?;
    fs::rename(temporary, runtime.join(DESCRIPTOR_FILE_NAME))?;
    Ok(())
}

pub(crate) fn canonical_runtime_dir() -> Option<PathBuf> {
    let path = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|value| PathBuf::from(value).join("gorce"))
        .or_else(crate::auth::config_dir)?;
    private_directory(&path).ok()
}

pub(crate) fn expected_token_path(runtime: &Path) -> PathBuf {
    runtime.join(TOKEN_FILE_NAME)
}

pub(crate) fn private_directory(path: &Path) -> Result<PathBuf, SdkError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        SdkError::Discovery("the descriptor parent directory is unavailable".to_owned())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SdkError::Discovery(
            "the descriptor parent directory is not a private directory".to_owned(),
        ));
    }
    ensure_private_mode(&metadata, "descriptor parent directory")?;
    let canonical = fs::canonicalize(path).map_err(|_| {
        SdkError::Discovery("the descriptor parent directory is unavailable".to_owned())
    })?;
    let canonical_metadata = fs::symlink_metadata(&canonical).map_err(|_| {
        SdkError::Discovery("the descriptor parent directory is unavailable".to_owned())
    })?;
    ensure_private_mode(&canonical_metadata, "descriptor parent directory")?;
    Ok(canonical)
}

pub(crate) fn secure_private_file(path: &Path, expected_name: &str) -> Result<PathBuf, SdkError> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        return Err(SdkError::Token(
            "the token path is not the canonical daemon token".to_owned(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| SdkError::Token("the token path is invalid".to_owned()))?;
    let canonical_parent = private_directory(parent)
        .map_err(|_| SdkError::Token("the token parent directory is not private".to_owned()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| SdkError::Token("the canonical daemon token is unavailable".to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SdkError::Token(
            "the canonical daemon token is not a regular file".to_owned(),
        ));
    }
    ensure_private_mode(&metadata, "token file")
        .map_err(|_| SdkError::Token("the canonical daemon token is not private".to_owned()))?;
    Ok(canonical_parent.join(expected_name))
}

fn read_descriptor_in_runtime(path: &Path, runtime: &Path) -> Result<DaemonDescriptor, SdkError> {
    let parent = path
        .parent()
        .ok_or_else(|| SdkError::Discovery("descriptor has no parent directory".to_owned()))?;
    let canonical_parent = private_directory(parent)?;
    if canonical_parent != runtime
        || path.file_name().and_then(|name| name.to_str()) != Some(DESCRIPTOR_FILE_NAME)
    {
        return Err(SdkError::Discovery(
            "the descriptor is outside the canonical runtime directory".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| SdkError::Discovery("the daemon descriptor is unavailable".to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SdkError::Discovery(
            "the daemon descriptor is not a regular file".to_owned(),
        ));
    }
    ensure_private_mode(&metadata, "descriptor file")?;
    let content = fs::read(path)
        .map_err(|_| SdkError::Discovery("the daemon descriptor cannot be read".to_owned()))?;
    let descriptor: DaemonDescriptor = serde_json::from_slice(&content)
        .map_err(|_| SdkError::Discovery("the daemon descriptor is invalid".to_owned()))?;
    validate_descriptor(&descriptor, runtime)?;
    Ok(descriptor)
}

fn validate_descriptor(descriptor: &DaemonDescriptor, runtime: &Path) -> Result<(), SdkError> {
    if descriptor.protocol_version != gorce_protocol::PROTOCOL_VERSION {
        return Err(SdkError::Discovery(
            "unsupported daemon protocol version".to_owned(),
        ));
    }
    validate_loopback_endpoint(&descriptor.endpoint)?;
    let expected = expected_token_path(runtime);
    if descriptor.token_file.as_deref() != Some(expected.as_path()) {
        return Err(SdkError::Discovery(
            "the descriptor token must be the canonical sibling token".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_loopback_endpoint(endpoint: &str) -> Result<(), SdkError> {
    let normalized = if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("http://{endpoint}")
    };
    let url = Url::parse(&normalized)
        .map_err(|_| SdkError::Discovery("the daemon endpoint is invalid".to_owned()))?;
    if url.scheme() != "http" || url.username() != "" || url.password().is_some() {
        return Err(SdkError::Discovery(
            "the daemon endpoint must be loopback HTTP".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| SdkError::Discovery("the daemon endpoint has no host".to_owned()))?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false);
    if !is_loopback
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "" && url.path() != "/" && url.path() != "/v0"
    {
        return Err(SdkError::Discovery(
            "the daemon endpoint must be loopback HTTP".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_private_mode(metadata: &fs::Metadata, label: &str) -> Result<(), SdkError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SdkError::Discovery(format!("{label} is not private")));
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, label);
    Ok(())
}

fn set_private_file(path: &Path) -> Result<(), SdkError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{read_descriptor, DaemonDescriptor, DESCRIPTOR_FILE_NAME, TOKEN_FILE_NAME};

    fn fixture() -> (PathBuf, DaemonDescriptor) {
        let root =
            std::env::temp_dir().join(format!("gorce-sdk-discovery-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o700);
        let mut descriptor =
            DaemonDescriptor::new("127.0.0.1:4317", gorce_protocol::PROTOCOL_VERSION);
        descriptor.token_file = Some(root.join(TOKEN_FILE_NAME));
        (root, descriptor)
    }

    fn write_descriptor(root: &Path, descriptor: &DaemonDescriptor) -> PathBuf {
        let path = root.join(DESCRIPTOR_FILE_NAME);
        fs::write(&path, serde_json::to_vec(descriptor).unwrap()).unwrap();
        set_mode(&path, 0o600);
        path
    }

    fn set_mode(path: &PathBuf, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = (path, mode);
    }

    #[test]
    fn rejects_remote_endpoints_before_token_use() {
        let (root, mut descriptor) = fixture();
        descriptor.endpoint = "http://192.0.2.1:4317".to_owned();
        let path = write_descriptor(&root, &descriptor);
        assert!(read_descriptor(&path).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_symlink_and_world_readable_descriptors() {
        let (root, descriptor) = fixture();
        let target = write_descriptor(&root, &descriptor);
        let link_target = root.join("descriptor-target");
        fs::rename(&target, &link_target).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&link_target, &target).unwrap();
        #[cfg(unix)]
        {
            assert!(read_descriptor(&target).is_err());
            fs::remove_file(&target).unwrap();
            fs::copy(&link_target, &target).unwrap();
            set_mode(&target, 0o644);
            assert!(read_descriptor(&target).is_err());
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_a_token_path_that_points_at_ssh_material() {
        let (root, mut descriptor) = fixture();
        descriptor.token_file = Some(PathBuf::from("/home/user/.ssh/id_rsa"));
        let path = write_descriptor(&root, &descriptor);
        assert!(read_descriptor(&path).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
