use crate::node;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use substrate_api_client::{Api, UncheckedExtrinsic, CompositeClient};
use sp_core::crypto::AccountId32 as AccountId;

pub struct Signer {
    node_client: Arc<node::Client>,
    substrate_api: Api<CompositeClient>,
    proxy_account: AccountId,
    registrar_account: AccountId,
}

impl Signer {
    pub fn new(node_client: Arc<node::Client>, substrate_api: Api<CompositeClient>, proxy_account: AccountId, registrar_account: AccountId) -> Self {
        Self {
            node_client,
            substrate_api,
            proxy_account,
            registrar_account,
        }
    }

    pub async fn provide_judgement(&self, target: AccountId, judgement: node::Judgement, registrar_index: u32) -> Result<()> {
        // Create the inner call (identity.provide_judgement)
        let inner_call = self.substrate_api.call().identity().provide_judgement(
            registrar_index,
            target,
            judgement,
        );

        // Create the outer call (proxy.proxy)
        let proxy_call = self.substrate_api.call().proxy().proxy(
            self.registrar_account.clone(),
            None, // TODO: we probably want to limit Judgements only.
            inner_call,
        );

        let xt: UncheckedExtrinsic = self.substrate_api
            .extrinsic_with_nonce(proxy_call)
            .build_signed_extrinsic(self.proxy_account.clone());

        let tx_hash = self.substrate_api.submit_extrinsic(xt).await?;

        tracing::info!("Judgement provided successfully for {:?}: {:?}. Transaction hash: {:?}", target, judgement, tx_hash);
        
        Ok(())
    }
}
