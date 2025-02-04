use tokio::task::JoinHandle;
use tracing::info;
/// NOTE: I hate how short this file is

#[derive(Default)]
pub struct Runner {
    handlers: Vec<JoinHandle<()>>,
}

impl Runner {
    /// Push a job to the queue
    pub async fn push(&mut self, handler: JoinHandle<()>) {
        self.handlers.push(handler);
    }

    /// Run jobs, Ctr-C for gracefully shutdown
    pub async fn run(self) {
        info!("Spawning {} jobs", self.handlers.len());
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                std::process::exit(0);
            }
            _ = futures::future::join_all(self.handlers) => {
                info!("All services completed");
            }
        }
    }
}
