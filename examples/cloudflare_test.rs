//! End-to-end test for Cloudflare DNS verification
//!
//! Usage:
//!   CF_API_TOKEN=your-token cargo run --example cloudflare_test
//!
//! This test will:
//! 1. Create a TXT record on a test subdomain
//! 2. Verify it can be read via DNS
//! 3. Clean up the record

use anyhow::{anyhow, Result};
use cloudflare::endpoints::dns::dns::{
    CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, DnsRecord,
    ListDnsRecords, ListDnsRecordsParams,
};
use cloudflare::endpoints::zones::zone::{ListZones, ListZonesParams};
use cloudflare::framework::auth::Credentials;
use cloudflare::framework::client::async_api::Client;
use cloudflare::framework::client::ClientConfig;
use cloudflare::framework::Environment;
use std::collections::HashMap;
use std::env;

/// Manages Cloudflare DNS operations for testing
pub struct CloudflareManager {
    client: Client,
    zone_cache: HashMap<String, String>,
}

impl CloudflareManager {
    pub fn new(api_token: &str) -> Result<Self> {
        let credentials = Credentials::UserAuthToken {
            token: api_token.to_string(),
        };

        let client = Client::new(credentials, ClientConfig::default(), Environment::Production)
            .map_err(|e| anyhow!("Failed to create Cloudflare client: {}", e))?;

        Ok(Self {
            client,
            zone_cache: HashMap::new(),
        })
    }

    pub async fn get_zone_id(&mut self, domain: &str) -> Result<String> {
        let root_domain = extract_root_domain(domain);

        if let Some(zone_id) = self.zone_cache.get(&root_domain) {
            return Ok(zone_id.clone());
        }

        let params = ListZonesParams {
            name: Some(root_domain.clone()),
            ..Default::default()
        };

        let response = self
            .client
            .request(&ListZones { params })
            .await
            .map_err(|e| anyhow!("Failed to list zones: {:?}", e))?;

        let zone = response
            .result
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Zone not found for domain: {}", domain))?;

        self.zone_cache.insert(root_domain, zone.id.clone());
        Ok(zone.id)
    }

    pub async fn create_verification_record(
        &mut self,
        domain: &str,
        challenge_token: &str,
    ) -> Result<String> {
        let zone_id = self.get_zone_id(domain).await?;

        let params = CreateDnsRecordParams {
            name: domain,
            content: DnsContent::TXT {
                content: challenge_token.to_string(),
            },
            ttl: Some(60),
            priority: None,
            proxied: Some(false),
        };

        let response = self
            .client
            .request(&CreateDnsRecord {
                zone_identifier: &zone_id,
                params,
            })
            .await
            .map_err(|e| anyhow!("Failed to create TXT record: {:?}", e))?;

        Ok(response.result.id)
    }

    pub async fn list_txt_records(&mut self, domain: &str) -> Result<Vec<DnsRecord>> {
        let zone_id = self.get_zone_id(domain).await?;

        let params = ListDnsRecordsParams {
            name: Some(domain.to_string()),
            record_type: Some(DnsContent::TXT {
                content: String::new(),
            }),
            ..Default::default()
        };

        let response = self
            .client
            .request(&ListDnsRecords {
                zone_identifier: &zone_id,
                params,
            })
            .await
            .map_err(|e| anyhow!("Failed to list TXT records: {:?}", e))?;

        Ok(response.result)
    }

    pub async fn delete_txt_record(&mut self, domain: &str, record_id: &str) -> Result<()> {
        let zone_id = self.get_zone_id(domain).await?;

        self.client
            .request(&DeleteDnsRecord {
                zone_identifier: &zone_id,
                identifier: record_id,
            })
            .await
            .map_err(|e| anyhow!("Failed to delete TXT record: {:?}", e))?;

        Ok(())
    }
}

fn extract_root_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let api_token =
        env::var("CF_API_TOKEN").expect("CF_API_TOKEN environment variable required");

    let test_domain =
        env::var("CF_TEST_DOMAIN").unwrap_or_else(|_| "w3reg-test.rotko.net".to_string());
    let challenge_token = format!("w3r-test-{}", uuid::Uuid::new_v4());

    println!("=== Cloudflare DNS Verification Test ===");
    println!("Test domain: {}", test_domain);
    println!("Challenge token: {}", challenge_token);
    println!();

    let mut manager = CloudflareManager::new(&api_token)?;

    // Step 1: Create TXT record
    println!("1. Creating TXT record...");
    let record_id = manager
        .create_verification_record(&test_domain, &challenge_token)
        .await?;
    println!("   Created record with ID: {}", record_id);

    // Step 2: Wait for DNS propagation and retry
    println!("2. Waiting for DNS propagation (up to 60 seconds)...");
    let mut verified = false;
    for attempt in 1..=6 {
        println!("   Attempt {}/6...", attempt);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        verified =
            w3registrar::adapter::web::dns::verify_txt(&test_domain, &challenge_token).await;
        if verified {
            println!("   DNS verification: SUCCESS on attempt {}", attempt);
            break;
        } else {
            println!("   DNS verification: not yet propagated");
        }
    }

    println!(
        "3. Final DNS verification result: {}",
        if verified { "SUCCESS" } else { "FAILED" }
    );

    // Step 4: List records
    println!("4. Listing TXT records for domain...");
    let records = manager.list_txt_records(&test_domain).await?;
    for record in &records {
        println!("   - ID: {}, Name: {}", record.id, record.name);
    }

    // Step 5: Cleanup
    println!("5. Cleaning up TXT record...");
    manager.delete_txt_record(&test_domain, &record_id).await?;
    println!("   Record deleted");

    println!();
    if verified {
        println!("=== TEST PASSED ===");
    } else {
        println!("=== TEST FAILED (DNS propagation may need more time) ===");
    }

    Ok(())
}
