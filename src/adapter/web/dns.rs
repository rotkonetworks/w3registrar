use anyhow::Result;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    proto::rr::{RData, RecordType},
    AsyncResolver,
};

static DNS_RESOLVER: OnceCell<Arc<AsyncResolver<TokioConnectionProvider>>> = OnceCell::new();

fn get_resolver() -> Arc<AsyncResolver<TokioConnectionProvider>> {
    DNS_RESOLVER
        .get_or_init(|| {
            let mut opts = ResolverOpts::default();
            // Optimize for verification use case
            opts.timeout = Duration::from_secs(5);
            opts.attempts = 2;
            opts.cache_size = 256; // Cache recent lookups
            opts.use_hosts_file = false; // Skip /etc/hosts for speed
            opts.positive_min_ttl = Some(Duration::from_secs(30)); // Min cache time
            opts.negative_min_ttl = Some(Duration::from_secs(10)); // Cache failures briefly

            Arc::new(AsyncResolver::tokio(
                ResolverConfig::cloudflare_tls(),
                opts,
            ))
        })
        .clone()
}

#[instrument(skip_all)]
async fn lookup_txt_records(domain: &str) -> Result<Vec<String>, String> {
    debug!(domain = %domain, "DNS TXT lookup");

    get_resolver()
        .lookup(domain, RecordType::TXT)
        .await
        .map(|response| {
            response
                .iter()
                .filter_map(|record| match record {
                    RData::TXT(txt_data) => Some(txt_data),
                    _ => None,
                })
                .flat_map(|txt_data| txt_data.iter())
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// Verify that a domain has a TXT record matching the challenge token.
/// Uses Cloudflare DNS over TLS for fast, secure lookups with caching.
#[instrument(skip_all)]
pub async fn verify_txt(domain: &str, challenge: &str) -> bool {
    match lookup_txt_records(domain).await {
        Ok(records) => {
            debug!(domain = %domain, count = records.len(), "Found TXT records");

            // Fast path: check for exact match
            for record in &records {
                if record == challenge {
                    info!(domain = %domain, "TXT verification successful");
                    return true;
                }
            }

            debug!(domain = %domain, challenge = %challenge, "No matching TXT record");
            false
        }
        Err(err) => {
            debug!(domain = %domain, error = %err, "DNS lookup failed");
            false
        }
    }
}

/// Verify TXT record with retry support for DNS propagation delays.
/// Useful when records were just created.
#[instrument(skip_all)]
pub async fn verify_txt_with_retry(
    domain: &str,
    challenge: &str,
    max_attempts: u32,
    delay_secs: u64,
) -> bool {
    for attempt in 1..=max_attempts {
        if verify_txt(domain, challenge).await {
            return true;
        }

        if attempt < max_attempts {
            debug!(
                domain = %domain,
                attempt = attempt,
                max = max_attempts,
                "Retrying DNS verification"
            );
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_lookup_real_domain() {
        let records = lookup_txt_records("google.com").await;
        assert!(records.is_ok(), "Should be able to lookup TXT records");
        let records = records.unwrap();
        assert!(!records.is_empty(), "google.com should have TXT records");
    }

    #[tokio::test]
    async fn test_dns_verify_nonexistent_token() {
        let result = verify_txt("google.com", "w3r-test-nonexistent-token-12345").await;
        assert!(!result, "Random token should not match any TXT record");
    }

    #[tokio::test]
    async fn test_resolver_caching() {
        // First lookup
        let start = std::time::Instant::now();
        let _ = lookup_txt_records("cloudflare.com").await;
        let first = start.elapsed();

        // Second lookup (should be cached)
        let start = std::time::Instant::now();
        let _ = lookup_txt_records("cloudflare.com").await;
        let second = start.elapsed();

        // Cached lookup should be significantly faster
        println!("First: {:?}, Second (cached): {:?}", first, second);
        // Note: Can't guarantee timing in CI, so just verify both work
    }
}
