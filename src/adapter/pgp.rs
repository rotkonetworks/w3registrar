use anyhow::anyhow;
use anyhow::Result;
use openpgp::parse::stream::*;
use openpgp::{parse::Parse, policy::StandardPolicy, Cert};
use sequoia_openpgp::{self as openpgp, KeyHandle};
use subxt::utils::AccountId32;
use tracing::error;
use tracing::info;

use crate::api::Network;
use crate::api::{Account, RedisConnection};
use super::Adapter;

pub struct PGPHelper {
    signature: Vec<u8>,
}

impl Adapter for PGPHelper {}

impl PGPHelper {
    pub fn new(signature: &[u8]) -> Self {
        Self {
            signature: signature.to_vec().clone(),
        }
    }

    /// Verifies PGP signed challenge by first checking if the fingerprint matches the one
    /// registered, and if the signed challenge is equal to the requested one
    pub async fn verify(
        signed_challenge: &[u8],
        registered_fingerprint: [u8; 20],
        network: &Network,
        account_id: AccountId32,
    ) -> anyhow::Result<serde_json::Value> {
        let policy = &StandardPolicy::new();
        let helper = PGPHelper::new(&registered_fingerprint);

        // NOTE: mainly checks signature, can be used for other things
        let mut verifier =
            VerifierBuilder::from_bytes(signed_challenge)?.with_policy(policy, None, helper)?;

        // signed message
        let mut output_buffer = vec![];
        std::io::copy(&mut verifier, &mut output_buffer)?;
        let output = &String::from_utf8(output_buffer)?;

        let mut redis_connection = RedisConnection::default().await;
        let account = Account::PGPFingerprint(registered_fingerprint);
        match PGPHelper::handle_content(
            output,
            &mut redis_connection,
            network,
            &account_id,
            &account,
        )
        .await
        {
            Ok(_) => Ok(serde_json::json!({
                "type": "JsonResult",
                "payload": {
                    "type": "ok",
                    "message": "PGP verification is done",
                }
            })),
            Err(e) => {
                info!(error=?e, "Verification error");
                Ok(serde_json::json!({
                    "type": "error",
                    "message": format!("{e}"),
                }))
            }
        }
    }
}

impl VerificationHelper for PGPHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        for id in _ids {
            info!("ID: {:#?}", id.to_hex());
            let registered = self.signature.clone();
            let encoded = id.as_bytes();
            if encoded.ne(&registered) {
                error!(
                    encoded =?encoded, registered =?registered,
                    "Encoded signature does not match the registered signature"
                );
                return Err(anyhow!(
                    "Encoded signature does not match the registered signature"
                ));
            }
        }
        Ok(vec![])
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for structure in structure.iter() {
            match structure {
                MessageLayer::SignatureGroup { results } => {
                    for result in results {
                        // NOTE: what causes the `result` to be Error and should
                        // we be concerned? and I don't like how nested this is
                        match result {
                            Ok(o) => {
                                info!("Good checksum");
                                info!("SIGNATURE: {:?}", o.sig);
                            }
                            Err(e) => {
                                error!(error=?e, "Signature error");
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
