use anyhow::anyhow;
use anyhow::Result;
use openpgp::parse::stream::*;
use openpgp::{parse::Parse, policy::StandardPolicy, Cert};
use sequoia_openpgp::{self as openpgp, KeyHandle};
use subxt::utils::AccountId32;
use tracing::error;
use tracing::info;

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
    /// registed, and if the signed challenge is equal to the requested one
    pub async fn verify(
        signed_challenge: &[u8],
        registred_fingerprint: [u8; 20],
        network: &str,
        account_id: AccountId32,
    ) -> anyhow::Result<serde_json::Value> {
        let policy = &StandardPolicy::new();
        let helper = PGPHelper::new(&registred_fingerprint);

        // NOTE: mainly checks signature, can be used for other things
        let mut verifier =
            VerifierBuilder::from_bytes(signed_challenge)?.with_policy(policy, None, helper)?;

        // signed message
        let mut output_buffer = vec![];
        std::io::copy(&mut verifier, &mut output_buffer)?;
        let output = &String::from_utf8(output_buffer)?;

        let mut redis_connection = RedisConnection::default();
        let account = Account::PGPFingerprint(registred_fingerprint);
        if PGPHelper::handle_content(
            &output,
            &mut redis_connection,
            network,
            &account_id,
            &account,
        )
        .await?
        {
            return Ok(serde_json::json!({
                "type": "JsonResult",
                "payload": {
                    "type": "ok",
                    "message": "PGP verification is done",
                }
            }));
        } else {
            info!(got=?output, "Wrong challenge");
            return Ok(serde_json::json!({
                "type": "error",
                "message": format!("Wrong challenge")
            }));
        }
    }
}

impl VerificationHelper for PGPHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        for id in _ids {
            info!("ID: {:#?}", id.to_hex());
            let registred = self.signature.clone();
            let encoded = id.as_bytes();
            if encoded.ne(&registred) {
                error!(
                    encoded =?encoded, registred =?registred,
                    "Encoded signature does not match the registred signature"
                );
                return Err(anyhow!(
                    "Encoded signature does not match the registred signature"
                ));
            }
        }
        Ok(vec![])
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for thing in structure.iter() {
            match thing {
                MessageLayer::SignatureGroup { results } => {
                    for result in results {
                        match result {
                            Ok(o) => {
                                info!("Good checksum");
                                info!("SIGNATURE: {:?}", o.sig);
                            }
                            Err(_) => {} // return Err(anyhow::anyhow!("{:?}", e))
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
