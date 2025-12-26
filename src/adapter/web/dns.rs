use anyhow::Result;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tracing::{info, instrument};
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
            Arc::new(AsyncResolver::tokio(
                ResolverConfig::cloudflare_tls(),
                ResolverOpts::default(),
            ))
        })
        .clone()
}

#[instrument(skip_all)]
async fn lookup_txt_records(domain: &str) -> Result<Vec<String>, String> {
    info!(domain = %domain, "Looking for TXT records");
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

#[instrument(skip_all)]
pub async fn verify_txt(domain: &str, challenge: &str) -> bool {
    match lookup_txt_records(domain).await {
        Ok(records) => {
            for record in &records {
                info!(domain = %domain, "Found Record: {record}");
            }
            if records.contains(&challenge.to_string()) {
                info!(domain = %domain, "TXT record verification successful");
                return true;
            }
            info!(domain = %domain, "No matching({}) TXT record found", &challenge.to_string());
            false
        }
        Err(err) => {
            info!(domain = %domain, error = %err, "Record lookup failed");
            false
        }
    }
}