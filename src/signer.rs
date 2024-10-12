use crate::node;
use std::sync::Arc;
use anyhow::Result;
use subxt::{tx::PairSigner, OnlineClient, PolkadotConfig};

pub struct Signer {
    node_client: Arc<node::Client>,
    pair_signer: PairSigner<PolkadotConfig, subxt::ext::sp_core::sr25519::Pair>,
    proxy_account: node::api::runtime_types::sp_core::crypto::AccountId32,
    registrar_account: node::api::runtime_types::sp_core::crypto::AccountId32,
}

impl Signer {
    pub async fn new(
        node_client: Arc<node::Client>,
        keystore_path: &str,
        proxy_account: node::api::runtime_types::sp_core::crypto::AccountId32,
        registrar_account: node::api::runtime_types::sp_core::crypto::AccountId32,
    ) -> Result<Self> {
        let pair = subxt::ext::sp_core::sr25519::Pair::from_string(&std::fs::read_to_string(keystore_path)?, None)?;
        let pair_signer = PairSigner::new(pair);

        Ok(Self {
            node_client,
            pair_signer,
            proxy_account,
            registrar_account,
        })
    }

    pub async fn provide_judgement(
        &self,
        target: node::api::runtime_types::sp_core::crypto::AccountId32,
        judgement: node::api::runtime_types::pallet_identity::types::Judgement<u128>,
        registrar_index: u32,
    ) -> Result<()> {
        let client = OnlineClient::<PolkadotConfig>::from_url(&self.node_client.url()).await?;

        let inner_call = node::api::tx().identity().provide_judgement(
            registrar_index,
            node::api::runtime_types::sp_runtime::multiaddress::MultiAddress::Id(target.clone()),
            judgement.clone(),
        );

        let proxy_call = node::api::tx().proxy().proxy(
            node::api::runtime_types::sp_runtime::multiaddress::MultiAddress::Id(self.registrar_account.clone()),
            // proxy rights only for providing judgement
            Some(node::api::runtime_types::people_rococo_runtime::ProxyType::IdentityJudgement),
            inner_call,
        );

        let tx_progress = client.tx().sign_and_submit_then_watch_default(&proxy_call, &self.pair_signer).await?;

        let tx_result = tx_progress.wait_for_finalized_success().await?;
        
        tracing::info!(
            "Judgement provided successfully for {:?}: {:?}. Block hash: {:?}",
            target,
            judgement,
            tx_result.block_hash()
        );

        Ok(())
    }
}
