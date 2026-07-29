use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{Mutex, Notify};

use crate::client::{Client, ClientConfig};
use crate::discovery::DaemonDiscovery;
use crate::error::SdkError;

pub type LaunchFuture = Pin<Box<dyn Future<Output = Result<(), SdkError>> + Send + 'static>>;

pub trait DaemonLauncher: Send + Sync {
    fn launch(&self) -> LaunchFuture;

    fn abort(&self) {}
}

#[derive(Clone)]
pub struct ProcessLauncher {
    pub program: PathBuf,
    pub arguments: Vec<String>,
    child: Arc<StdMutex<Option<std::process::Child>>>,
}

impl std::fmt::Debug for ProcessLauncher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessLauncher")
            .field("argument_count", &self.arguments.len())
            .finish()
    }
}

impl ProcessLauncher {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            child: Arc::new(StdMutex::new(None)),
        }
    }

    pub fn arg(mut self, argument: impl Into<String>) -> Self {
        self.arguments.push(argument.into());
        self
    }
}

impl DaemonLauncher for ProcessLauncher {
    fn launch(&self) -> LaunchFuture {
        let program = self.program.clone();
        let arguments = self.arguments.clone();
        let child_slot = self.child.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let child = Command::new(program)
                    .args(arguments)
                    .spawn()
                    .map_err(SdkError::Io)?;
                *child_slot.lock().expect("launcher child lock poisoned") = Some(child);
                Ok(())
            })
            .await
            .map_err(|_| SdkError::Unsupported("daemon launcher task failed".to_owned()))?
        })
    }

    fn abort(&self) {
        if let Some(mut child) = self
            .child
            .lock()
            .expect("launcher child lock poisoned")
            .take()
        {
            let _ = child.kill();
        }
    }
}

impl<F, Fut> DaemonLauncher for F
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), SdkError>> + Send + 'static,
{
    fn launch(&self) -> LaunchFuture {
        Box::pin((self)())
    }
}

struct LazyState {
    client: Option<Client>,
    startup_started: bool,
    startup_error: Option<String>,
}

#[derive(Clone)]
pub struct LazyDaemon {
    discovery: DaemonDiscovery,
    launcher: Option<Arc<dyn DaemonLauncher>>,
    state: Arc<Mutex<LazyState>>,
    startup_notify: Arc<Notify>,
}

impl std::fmt::Debug for LazyDaemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LazyDaemon")
            .field("discovery", &self.discovery)
            .field("has_launcher", &self.launcher.is_some())
            .finish()
    }
}

impl LazyDaemon {
    pub fn new(discovery: DaemonDiscovery) -> Self {
        Self {
            discovery,
            launcher: None,
            state: Arc::new(Mutex::new(LazyState {
                client: None,
                startup_started: false,
                startup_error: None,
            })),
            startup_notify: Arc::new(Notify::new()),
        }
    }

    pub fn with_launcher<L>(mut self, launcher: L) -> Self
    where
        L: DaemonLauncher + 'static,
    {
        self.launcher = Some(Arc::new(launcher));
        self
    }

    pub async fn attach_or_launch(&self) -> Result<Client, SdkError> {
        self.client().await
    }

    pub async fn attach(&self) -> Result<Client, SdkError> {
        let daemon = discover_async(self.discovery.clone()).await?;
        let client = Client::from_discovered(daemon)?;
        let mut state = self.state.lock().await;
        state.client = Some(client.clone());
        Ok(client)
    }

    pub async fn client(&self) -> Result<Client, SdkError> {
        loop {
            let notified = self.startup_notify.notified();
            let should_start = {
                let state = self.state.lock().await;
                if let Some(client) = &state.client {
                    return Ok(client.clone());
                }
                if let Some(error) = &state.startup_error {
                    return Err(SdkError::Discovery(error.clone()));
                }
                !state.startup_started
            };

            if should_start {
                {
                    let mut state = self.state.lock().await;
                    if state.startup_started {
                        continue;
                    }
                    state.startup_started = true;
                }
                let result = self.startup().await;
                let mut state = self.state.lock().await;
                match result {
                    Ok(client) => {
                        state.client = Some(client.clone());
                        self.startup_notify.notify_waiters();
                        return Ok(client);
                    }
                    Err(error) => {
                        state.startup_error = Some(error.to_string());
                        self.startup_notify.notify_waiters();
                        return Err(error);
                    }
                }
            }
            notified.await;
        }
    }

    async fn startup(&self) -> Result<Client, SdkError> {
        match discover_async(self.discovery.clone()).await {
            Ok(daemon) => Client::from_discovered(daemon),
            Err(discovery_error) => {
                let launcher = self.launcher.as_ref().ok_or(discovery_error)?;
                if let Err(error) = launcher.launch().await {
                    launcher.abort();
                    return Err(error);
                }
                match wait_for_descriptor(&self.discovery).await {
                    Ok(daemon) => match Client::from_discovered(daemon) {
                        Ok(client) => Ok(client),
                        Err(error) => {
                            launcher.abort();
                            Err(error)
                        }
                    },
                    Err(error) => {
                        launcher.abort();
                        Err(error)
                    }
                }
            }
        }
    }

    pub async fn clear(&self) {
        let mut state = self.state.lock().await;
        state.client = None;
        state.startup_started = false;
        state.startup_error = None;
    }
}

impl Default for LazyDaemon {
    fn default() -> Self {
        Self::new(DaemonDiscovery::new())
    }
}

async fn discover_async(discovery: DaemonDiscovery) -> Result<crate::DiscoveredDaemon, SdkError> {
    tokio::task::spawn_blocking(move || discovery.discover())
        .await
        .map_err(|_| SdkError::Unsupported("daemon discovery task failed".to_owned()))?
}

async fn wait_for_descriptor(
    discovery: &DaemonDiscovery,
) -> Result<crate::DiscoveredDaemon, SdkError> {
    let mut last_error = None;
    for _ in 0..50 {
        match discover_async(discovery.clone()).await {
            Ok(value) => return Ok(value),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Err(last_error.unwrap_or_else(|| {
        SdkError::Discovery("daemon did not publish a trusted descriptor".to_owned())
    }))
}

pub fn configured_client(config: ClientConfig) -> Result<Client, SdkError> {
    Client::new(config)
}
