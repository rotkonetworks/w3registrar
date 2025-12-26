use async_trait::async_trait;
use subxt::utils::AccountId32;

use crate::api::{AccountType, AccountVerification, Network};
use crate::postgres::TimelineEvent;

/// Abstraction for verification state storage (Redis)
#[async_trait]
pub trait VerificationStore: Send + Sync {
    async fn get_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<Option<AccountVerification>>;

    async fn update_challenge_status(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        account_type: &AccountType,
    ) -> anyhow::Result<()>;
}

/// Abstraction for timeline persistence (Postgres)
#[async_trait]
pub trait TimelineStore: Send + Sync {
    async fn update_timeline(
        &self,
        event: TimelineEvent,
        account_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()>;

    async fn finalize_timeline(
        &self,
        account_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()>;
}

/// Abstraction for on-chain registration
#[async_trait]
pub trait ChainRegistrar: Send + Sync {
    async fn register_identity(
        &self,
        account_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()>;
}


#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock verification store for testing
    pub struct MockVerificationStore {
        states: Arc<Mutex<HashMap<String, AccountVerification>>>,
        updated_challenges: Arc<Mutex<Vec<(Network, AccountId32, AccountType)>>>,
    }

    impl MockVerificationStore {
        pub fn new() -> Self {
            Self {
                states: Arc::new(Mutex::new(HashMap::new())),
                updated_challenges: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_state(self, network: &Network, account_id: &AccountId32, state: AccountVerification) -> Self {
            let key = format!("{}|{}", network, account_id);
            self.states.lock().unwrap().insert(key, state);
            self
        }

        pub fn get_updated_challenges(&self) -> Vec<(Network, AccountId32, AccountType)> {
            self.updated_challenges.lock().unwrap().clone()
        }
    }

    impl Default for MockVerificationStore {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl VerificationStore for MockVerificationStore {
        async fn get_verification_state(
            &mut self,
            network: &Network,
            account_id: &AccountId32,
        ) -> anyhow::Result<Option<AccountVerification>> {
            let key = format!("{}|{}", network, account_id);
            Ok(self.states.lock().unwrap().get(&key).cloned())
        }

        async fn update_challenge_status(
            &mut self,
            network: &Network,
            account_id: &AccountId32,
            account_type: &AccountType,
        ) -> anyhow::Result<()> {
            self.updated_challenges.lock().unwrap().push((
                network.clone(),
                account_id.clone(),
                account_type.clone(),
            ));
            Ok(())
        }
    }

    /// Mock timeline store for testing
    pub struct MockTimelineStore {
        updates: Arc<Mutex<Vec<(TimelineEvent, AccountId32, Network)>>>,
        finalized: Arc<Mutex<Vec<(AccountId32, Network)>>>,
    }

    impl MockTimelineStore {
        pub fn new() -> Self {
            Self {
                updates: Arc::new(Mutex::new(Vec::new())),
                finalized: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn get_updates(&self) -> Vec<(TimelineEvent, AccountId32, Network)> {
            self.updates.lock().unwrap().clone()
        }

        pub fn get_finalized(&self) -> Vec<(AccountId32, Network)> {
            self.finalized.lock().unwrap().clone()
        }
    }

    impl Default for MockTimelineStore {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl TimelineStore for MockTimelineStore {
        async fn update_timeline(
            &self,
            event: TimelineEvent,
            account_id: &AccountId32,
            network: &Network,
        ) -> anyhow::Result<()> {
            self.updates.lock().unwrap().push((event, account_id.clone(), network.clone()));
            Ok(())
        }

        async fn finalize_timeline(
            &self,
            account_id: &AccountId32,
            network: &Network,
        ) -> anyhow::Result<()> {
            self.finalized.lock().unwrap().push((account_id.clone(), network.clone()));
            Ok(())
        }
    }

    /// Mock chain registrar for testing
    pub struct MockChainRegistrar {
        registered: Arc<Mutex<Vec<(AccountId32, Network)>>>,
        should_fail: bool,
    }

    impl MockChainRegistrar {
        pub fn new() -> Self {
            Self {
                registered: Arc::new(Mutex::new(Vec::new())),
                should_fail: false,
            }
        }

        pub fn failing() -> Self {
            Self {
                registered: Arc::new(Mutex::new(Vec::new())),
                should_fail: true,
            }
        }

        pub fn get_registered(&self) -> Vec<(AccountId32, Network)> {
            self.registered.lock().unwrap().clone()
        }
    }

    impl Default for MockChainRegistrar {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl ChainRegistrar for MockChainRegistrar {
        async fn register_identity(
            &self,
            account_id: &AccountId32,
            network: &Network,
        ) -> anyhow::Result<()> {
            if self.should_fail {
                return Err(anyhow::anyhow!("mock chain registration failed"));
            }
            self.registered.lock().unwrap().push((account_id.clone(), network.clone()));
            Ok(())
        }
    }
}
