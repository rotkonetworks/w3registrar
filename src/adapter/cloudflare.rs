//! Cloudflare DNS management for web verification
//!
//! This module provides functionality to programmatically create and manage
//! TXT records for domain verification via Cloudflare's API.

#![allow(dead_code)]

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
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument};

/// Global Cloudflare client
static CF_CLIENT: OnceCell<Arc<RwLock<CloudflareManager>>> = OnceCell::new();

/// Cloudflare configuration
#[derive(Debug, Clone)]
pub struct CloudflareConfig {
    /// API token with DNS edit permissions
    pub api_token: String,
    /// Optional: specific zone ID (if not provided, will lookup by domain)
    pub zone_id: Option<String>,
}

/// Manages Cloudflare DNS operations
pub struct CloudflareManager {
    client: Client,
    zone_cache: std::collections::HashMap<String, String>,
}

impl CloudflareManager {
    /// Create a new CloudflareManager with the given API token
    pub fn new(api_token: &str) -> Result<Self> {
        let credentials = Credentials::UserAuthToken {
            token: api_token.to_string(),
        };

        let client = Client::new(credentials, ClientConfig::default(), Environment::Production)
            .map_err(|e| anyhow!("Failed to create Cloudflare client: {}", e))?;

        Ok(Self {
            client,
            zone_cache: std::collections::HashMap::new(),
        })
    }

    /// Get zone ID for a domain (with caching)
    #[instrument(skip(self))]
    pub async fn get_zone_id(&mut self, domain: &str) -> Result<String> {
        // Extract root domain (e.g., "test.rotko.net" -> "rotko.net")
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

    /// Create a TXT record for web verification
    #[instrument(skip(self))]
    pub async fn create_txt_record(
        &mut self,
        domain: &str,
        content: &str,
        ttl: Option<u32>,
    ) -> Result<String> {
        let zone_id = self.get_zone_id(domain).await?;

        let params = CreateDnsRecordParams {
            name: domain,
            content: DnsContent::TXT {
                content: content.to_string(),
            },
            ttl,
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

        info!(
            domain = %domain,
            record_id = %response.result.id,
            "TXT record created successfully"
        );

        Ok(response.result.id)
    }

    /// Delete a TXT record by ID
    #[instrument(skip(self))]
    pub async fn delete_txt_record(&mut self, domain: &str, record_id: &str) -> Result<()> {
        let zone_id = self.get_zone_id(domain).await?;

        self.client
            .request(&DeleteDnsRecord {
                zone_identifier: &zone_id,
                identifier: record_id,
            })
            .await
            .map_err(|e| anyhow!("Failed to delete TXT record: {:?}", e))?;

        info!(
            domain = %domain,
            record_id = %record_id,
            "TXT record deleted successfully"
        );

        Ok(())
    }

    /// List TXT records for a domain
    #[instrument(skip(self))]
    pub async fn list_txt_records(&mut self, domain: &str) -> Result<Vec<DnsRecord>> {
        let zone_id = self.get_zone_id(domain).await?;

        let params = ListDnsRecordsParams {
            name: Some(domain.to_string()),
            // Filter by TXT record type
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

        debug!(
            domain = %domain,
            count = response.result.len(),
            "Listed TXT records"
        );

        Ok(response.result)
    }

    /// Find and delete TXT records matching a specific content
    #[instrument(skip(self))]
    pub async fn delete_txt_records_by_content(
        &mut self,
        domain: &str,
        content: &str,
    ) -> Result<usize> {
        let records = self.list_txt_records(domain).await?;
        let mut deleted = 0;

        for record in records {
            if let DnsContent::TXT {
                content: record_content,
            } = &record.content
            {
                if record_content == content {
                    if let Err(e) = self.delete_txt_record(domain, &record.id).await {
                        error!(record_id = %record.id, error = %e, "Failed to delete record");
                    } else {
                        deleted += 1;
                    }
                }
            }
        }

        info!(domain = %domain, deleted = deleted, "Cleanup completed");
        Ok(deleted)
    }

    /// Create a verification TXT record and return the record ID
    /// The record name will be the domain itself (for direct TXT lookup)
    #[instrument(skip(self))]
    pub async fn create_verification_record(
        &mut self,
        domain: &str,
        challenge_token: &str,
    ) -> Result<String> {
        // Use short TTL (60 seconds) for verification records
        self.create_txt_record(domain, challenge_token, Some(60))
            .await
    }
}

/// Extract the root domain from a subdomain
/// e.g., "test.sub.example.com" -> "example.com"
fn extract_root_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

/// Initialize the global Cloudflare manager
pub fn init_cloudflare(api_token: &str) -> Result<()> {
    let manager = CloudflareManager::new(api_token)?;
    CF_CLIENT
        .set(Arc::new(RwLock::new(manager)))
        .map_err(|_| anyhow!("Cloudflare manager already initialized"))?;
    info!("Cloudflare DNS manager initialized");
    Ok(())
}

/// Get the global Cloudflare manager
pub fn get_cloudflare() -> Result<Arc<RwLock<CloudflareManager>>> {
    CF_CLIENT
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("Cloudflare manager not initialized"))
}

/// Convenience function: create a verification TXT record
pub async fn create_verification_record(domain: &str, challenge_token: &str) -> Result<String> {
    let manager = get_cloudflare()?;
    let mut manager = manager.write().await;
    manager
        .create_verification_record(domain, challenge_token)
        .await
}

/// Convenience function: delete a verification record
pub async fn delete_verification_record(domain: &str, record_id: &str) -> Result<()> {
    let manager = get_cloudflare()?;
    let mut manager = manager.write().await;
    manager.delete_txt_record(domain, record_id).await
}

/// Convenience function: cleanup verification records by token
pub async fn cleanup_verification_records(domain: &str, challenge_token: &str) -> Result<usize> {
    let manager = get_cloudflare()?;
    let mut manager = manager.write().await;
    manager
        .delete_txt_records_by_content(domain, challenge_token)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_root_domain() {
        assert_eq!(extract_root_domain("example.com"), "example.com");
        assert_eq!(extract_root_domain("sub.example.com"), "example.com");
        assert_eq!(extract_root_domain("deep.sub.example.com"), "example.com");
        assert_eq!(extract_root_domain("rotko.net"), "rotko.net");
        assert_eq!(extract_root_domain("test.rotko.net"), "rotko.net");
    }
}
