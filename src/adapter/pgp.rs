use anyhow::anyhow;
use anyhow::Result;
use openpgp::parse::stream::*;
use openpgp::{parse::Parse, policy::StandardPolicy, Cert};
use reqwest;
use sequoia_openpgp::{self as openpgp, KeyHandle};
use subxt::utils::AccountId32;
use tracing::error;
use tracing::info;

use super::Adapter;
use crate::api::Account;
use crate::api::Network;
use crate::redis::RedisConnection;

const KEYSERVER_URL: &str = "https://keyserver.ubuntu.com";

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

    /// Fetch PGP public key from Ubuntu keyserver by fingerprint
    pub async fn fetch_key_from_keyserver(fingerprint: &[u8; 20]) -> Result<Cert> {
        let fingerprint_hex = hex::encode(fingerprint);
        info!("Fetching PGP key for fingerprint: {}", fingerprint_hex);

        let url = format!(
            "{}/pks/lookup?op=get&options=mr&search=0x{}",
            KEYSERVER_URL, fingerprint_hex
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch key from keyserver: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Keyserver returned error: {}",
                response.status()
            ));
        }

        let key_data = response
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read keyserver response: {}", e))?;

        if key_data.is_empty() || !key_data.contains("BEGIN PGP PUBLIC KEY BLOCK") {
            return Err(anyhow!("No PGP key found for fingerprint: {}", fingerprint_hex));
        }

        Cert::from_bytes(key_data.as_bytes())
            .map_err(|e| anyhow!("Failed to parse PGP certificate: {}", e))
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

        let mut redis_connection = RedisConnection::default().await?;
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
        let mut certs = Vec::new();

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

            // Try to fetch the certificate from keyserver
            if let Ok(fingerprint_array) = <[u8; 20]>::try_from(registered.as_slice()) {
                match tokio::runtime::Handle::current().block_on(async {
                    PGPHelper::fetch_key_from_keyserver(&fingerprint_array).await
                }) {
                    Ok(cert) => {
                        info!("Successfully fetched certificate from keyserver");
                        certs.push(cert);
                    }
                    Err(e) => {
                        error!(error=?e, "Failed to fetch certificate from keyserver");
                        return Err(anyhow!("Failed to fetch certificate: {}", e));
                    }
                }
            }
        }

        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for structure in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = structure {
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
        }
        Ok(())
    }
}
