use trust_dns_resolver::{AsyncResolver, config::{ResolverConfig, ResolverOpts}};
use trust_dns_resolver::proto::rr::{RecordType, RData};

pub sync fn watch_dns

pub async fn verify_txt(domain: &str, txt: &str) -> bool {
    let resolver = AsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());
    match resolver.lookup(domain, RecordType::TXT).await {
        Ok(response) => response
            .iter()
            .filter_map(|record| match record {
                RData::TXT(txt_data) => Some(txt_data),
                _ => None,
            })
            .flat_map(|txt_data| txt_data.iter())
            .map(|bytes| String::from_utf8_lossy(bytes))
            .any(|record| record == txt),
        Err(_) => false,
    }
}
