use reqwest::{Client, StatusCode};
use std::time::Duration;
use tracing::{info, instrument, warn};

use crate::adapter::constant_time_eq;

#[instrument(skip_all)]
pub async fn verify_http(domain: &str, challenge: &str) -> bool {
    // Check if this is a GitHub gist URL
    if is_github_gist(domain) {
        return verify_gist(domain, challenge).await;
    }

    // Try HTTPS first, then HTTP
    if verify_https(domain, challenge).await {
        return true;
    }

    info!(domain = %domain, "HTTPS verification failed, trying HTTP");
    verify_http_protocol(domain, challenge, "http").await
}

/// Check if the domain is a GitHub gist URL
fn is_github_gist(domain: &str) -> bool {
    let clean = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    clean.starts_with("gist.github.com/") || clean.starts_with("gist.githubusercontent.com/")
}

/// Verify a GitHub gist contains the challenge token
#[instrument(skip_all)]
async fn verify_gist(gist_url: &str, challenge: &str) -> bool {
    let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to create HTTP client for gist");
            return false;
        }
    };

    // Convert gist.github.com URL to raw URL if needed
    let raw_url = convert_to_raw_gist_url(gist_url);
    info!(url = %raw_url, "Checking GitHub gist");

    match client.get(&raw_url).send().await {
        Ok(response) => {
            if response.status() == StatusCode::OK {
                match response.text().await {
                    Ok(body) => {
                        let body_trimmed = body.trim();
                        if constant_time_eq(body_trimmed, challenge) || body_trimmed.contains(challenge) {
                            info!(gist = %gist_url, "Gist verification successful");
                            return true;
                        } else {
                            info!(gist = %gist_url, "Challenge not found in gist");
                        }
                    }
                    Err(e) => {
                        warn!(gist = %gist_url, error = %e, "Failed to read gist body");
                    }
                }
            } else {
                info!(gist = %gist_url, status = %response.status(), "Gist returned non-200 status");
            }
        }
        Err(e) => {
            info!(gist = %gist_url, error = %e, "Failed to fetch gist");
        }
    }

    false
}

/// Convert a gist.github.com URL to a raw content URL
fn convert_to_raw_gist_url(url: &str) -> String {
    let clean = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // If already a raw URL, just ensure https
    if clean.starts_with("gist.githubusercontent.com/") {
        return format!("https://{}", clean);
    }

    // Convert gist.github.com/user/id to raw URL
    // gist.github.com/username/gist_id -> gist.githubusercontent.com/username/gist_id/raw
    if clean.starts_with("gist.github.com/") {
        let path = clean.trim_start_matches("gist.github.com/");
        // Remove any trailing /raw or file names
        let base_path = path.split('/').take(2).collect::<Vec<_>>().join("/");
        return format!("https://gist.githubusercontent.com/{}/raw", base_path);
    }

    // Fallback: return as-is with https
    format!("https://{}", clean)
}

#[instrument(skip_all)]
async fn verify_https(domain: &str, challenge: &str) -> bool {
    verify_http_protocol(domain, challenge, "https").await
}

#[instrument(skip_all)]
async fn verify_http_protocol(domain: &str, challenge: &str, protocol: &str) -> bool {
    let client = Client::builder().timeout(Duration::from_secs(10)).build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to create HTTP client");
            return false;
        }
    };

    // Clean the domain of any protocol prefixes
    let clean_domain = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');

    // Try .well-known path first (standard location)
    let well_known_url = format!(
        "{}://{}/.well-known/w3registrar/{}",
        protocol, clean_domain, challenge
    );

    info!(url = %well_known_url, "Checking .well-known path");

    match client.get(&well_known_url).send().await {
        Ok(response) => {
            if response.status() == StatusCode::OK {
                match response.text().await {
                    Ok(body) => {
                        // Check if the response body contains the challenge or is exactly the challenge
                        let body_trimmed = body.trim();
                        if constant_time_eq(body_trimmed, challenge) || body_trimmed.contains(challenge) {
                            info!(domain = %domain, "HTTP verification successful via .well-known");
                            return true;
                        } else {
                            info!(domain = %domain, "Challenge mismatch in .well-known response");
                        }
                    }
                    Err(e) => {
                        warn!(domain = %domain, error = %e, "Failed to read .well-known response body");
                    }
                }
            } else {
                info!(domain = %domain, status = %response.status(), ".well-known path returned non-200 status");
            }
        }
        Err(e) => {
            info!(domain = %domain, error = %e, ".well-known path not accessible");
        }
    }

    // Try alternative path: /w3registrar-verify.txt
    let alt_url = format!("{}://{}/w3registrar-verify.txt", protocol, clean_domain);

    info!(url = %alt_url, "Checking alternative path");

    match client.get(&alt_url).send().await {
        Ok(response) => {
            if response.status() == StatusCode::OK {
                match response.text().await {
                    Ok(body) => {
                        let body_trimmed = body.trim();
                        if constant_time_eq(body_trimmed, challenge) || body_trimmed.contains(challenge) {
                            info!(domain = %domain, "HTTP verification successful via alternative path");
                            return true;
                        } else {
                            info!(domain = %domain, "Challenge mismatch in alternative path response");
                        }
                    }
                    Err(e) => {
                        warn!(domain = %domain, error = %e, "Failed to read alternative path response body");
                    }
                }
            } else {
                info!(domain = %domain, status = %response.status(), "Alternative path returned non-200 status");
            }
        }
        Err(e) => {
            info!(domain = %domain, error = %e, "Alternative path not accessible");
        }
    }

    info!(domain = %domain, "HTTP verification failed for all paths");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_cleaning() {
        let domains = vec![
            ("https://example.com", "example.com"),
            ("http://example.com/", "example.com"),
            ("example.com/", "example.com"),
            ("example.com", "example.com"),
        ];

        for (input, expected) in domains {
            let clean = input
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');
            assert_eq!(clean, expected);
        }
    }

    #[tokio::test]
    async fn test_http_verify_nonexistent() {
        let result = verify_http("example.com", "w3r-test-token-xyz").await;
        assert!(!result, "Should fail for domain without verification file");
    }

    #[test]
    fn test_is_github_gist() {
        assert!(is_github_gist("gist.github.com/user/abc123"));
        assert!(is_github_gist("https://gist.github.com/user/abc123"));
        assert!(is_github_gist("gist.githubusercontent.com/user/abc123/raw"));
        assert!(is_github_gist("https://gist.githubusercontent.com/user/abc123/raw"));
        assert!(!is_github_gist("github.com/user/repo"));
        assert!(!is_github_gist("example.com"));
    }

    #[test]
    fn test_convert_to_raw_gist_url() {
        assert_eq!(
            convert_to_raw_gist_url("gist.github.com/user/abc123"),
            "https://gist.githubusercontent.com/user/abc123/raw"
        );
        assert_eq!(
            convert_to_raw_gist_url("https://gist.github.com/user/abc123"),
            "https://gist.githubusercontent.com/user/abc123/raw"
        );
        assert_eq!(
            convert_to_raw_gist_url("gist.githubusercontent.com/user/abc123/raw"),
            "https://gist.githubusercontent.com/user/abc123/raw"
        );
        assert_eq!(
            convert_to_raw_gist_url("https://gist.githubusercontent.com/user/abc123/raw/file.txt"),
            "https://gist.githubusercontent.com/user/abc123/raw/file.txt"
        );
    }

    #[tokio::test]
    async fn test_verify_real_gist() {
        // Test with hitchhooker's real gist
        let result = verify_http(
            "https://gist.github.com/hitchhooker/b20acdcfcac24991fa91f0d211effd5f",
            "w3r-test-1766825251",
        )
        .await;
        assert!(result, "Should verify real gist containing token");
    }

    #[tokio::test]
    async fn test_verify_gist_wrong_token() {
        let result = verify_http(
            "https://gist.github.com/hitchhooker/b20acdcfcac24991fa91f0d211effd5f",
            "wrong-token-xyz",
        )
        .await;
        assert!(!result, "Should fail for gist with wrong token");
    }
}
