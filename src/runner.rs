// runner.rs
use std::collections::HashMap;
use std::future::Future;
use tokio::{sync::broadcast, task::JoinHandle, time::Duration};
use tracing::{error, info};

// tracks which services are running to avoid duplicates
pub struct ServiceTracker {
    // TODO: track full adapter state/connections
    services: HashMap<&'static str, bool>,
}

impl ServiceTracker {
    fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    fn is_running(&self, service: &'static str) -> bool {
        self.services.get(service).copied().unwrap_or(false)
    }

    fn mark_running(&mut self, service: &'static str) {
        self.services.insert(service, true);
    }
}

pub struct Runner {
    tasks: Vec<JoinHandle<()>>,
    shutdown: broadcast::Sender<()>,
    services: ServiceTracker,
}

impl Runner {
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            tasks: Vec::new(),
            shutdown: shutdown_tx,
            services: ServiceTracker::new(),
        }
    }

    // spawn a task only if it's not already running
    pub async fn spawn<F, Fut>(&mut self, f: F, service_name: Option<&'static str>)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send,
    {
        // check if this is a unique service that's already running
        if let Some(name) = service_name {
            if self.services.is_running(name) {
                info!("service {} already running, skipping", name);
                return;
            }
            self.services.mark_running(name);
        }

        let mut shutdown_rx = self.shutdown.subscribe();
        self.tasks.push(tokio::spawn(async move {
            tokio::select! {
                res = f() => {
                    if let Err(e) = res {
                        error!("task error: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("task received shutdown signal");
                }
            }
        }));
    }

    pub async fn run(self) {
        info!("running {} tasks", self.tasks.len());

        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("received interrupt signal");
                let _ = self.shutdown.send(());

                // give tasks time to clean up
                tokio::time::sleep(Duration::from_secs(1)).await;

                // force abort any remaining tasks
                for task in self.tasks.iter() {
                    task.abort();
                }

                info!("forced shutdown complete");
                std::process::exit(0);
            }
            Err(e) => {
                error!("failed to listen for interrupt: {}", e);
                std::process::exit(1);
            }
        }
    }
}

impl Default for Runner {
    fn default() -> Self {
        Self::new()
    }
}
