// signer.rs
use crate::node;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use subxt::{OnlineClient, PolkadotConfig};
use subxt::tx::signer::PairSigner;
use subxt_signer::sr25519::Keypair;
use subxt::utils::AccountId32 as AccountId;
use subxt::utils::MultiAddress;

pub struct Signer {
    node_client: Arc<node::Client>,
    pair_signer: PairSigner<PolkadotConfig, Keypair>,
    proxy_account: AccountId,
    registrar_account: AccountId,
}

impl Signer {
    pub async fn new(
        node_client: Arc<node::Client>,
        keystore_path: &str,
        proxy_account: AccountId,
        registrar_account: AccountId,
    ) -> Result<Self> {
        let seed_phrase = std::fs::read_to_string(keystore_path)?.trim().to_string();
        let keypair = Keypair::from_phrase(&seed_phrase, None)
            .map_err(|e| anyhow!("Failed to create key pair: {:?}", e))?;
        let pair_signer = PairSigner::new(keypair);

        Ok(Self {
            node_client,
            pair_signer,
            proxy_account,
            registrar_account,
        })
    }

    pub async fn provide_judgement(
        &self,
        target: AccountId,
        judgement: node::Judgement,
        registrar_index: u32,
        identity_hash: node::Hash,
    ) -> Result<()> {
        let client = OnlineClient::<PolkadotConfig>::from_url(self.node_client.url()).await?;

        // Create the inner call (identity.provide_judgement)
        let inner_call = node::tx().identity().provide_judgement(
            registrar_index,
            MultiAddress::Id(target.clone()),
            judgement.clone(),
            identity_hash,
        );

        // Create the outer call (proxy.proxy)
        let proxy_call = node::tx().proxy().proxy(
            MultiAddress::Id(self.registrar_account.clone()),
            None, // TODO: ProxyType::IdentityJudgement
            inner_call,
        );

        let tx_progress = client
            .tx()
            .sign_and_submit_then_watch_default(&proxy_call, &self.pair_signer)
            .await?;

        let tx_result = tx_progress.wait_for_finalized_success().await?;

        tracing::info!(
            "Judgement provided successfully for {:?}: {:?}. Block hash: {:?}, Identity hash: {:?}",
            target,
            judgement,
            tx_result.block_hash(),
            identity_hash
        );

        Ok(())
    }
}
