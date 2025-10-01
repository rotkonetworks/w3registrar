use reqwest::{Client, StatusCode};
use std::time::Duration;
use tracing::{info, instrument, warn};

#[instrument(skip_all)]
pub async fn verify_http(domain: &str, challenge: &str) -> bool {
    // Try HTTPS first, then HTTP
    if verify_https(domain, challenge).await {
        return true;
    }

    info!(domain = %domain, "HTTPS verification failed, trying HTTP");
    verify_http_protocol(domain, challenge, "http").await
}

#[instrument(skip_all)]
async fn verify_https(domain: &str, challenge: &str) -> bool {
    verify_http_protocol(domain, challenge, "https").await
}

#[instrument(skip_all)]
async fn verify_http_protocol(domain: &str, challenge: &str, protocol: &str) -> bool {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build();

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
    let well_known_url = format!("{}://{}/.well-known/w3registrar/{}", protocol, clean_domain, challenge);

    info!(url = %well_known_url, "Checking .well-known path");

    match client.get(&well_known_url).send().await {
        Ok(response) => {
            if response.status() == StatusCode::OK {
                match response.text().await {
                    Ok(body) => {
                        // Check if the response body contains the challenge or is exactly the challenge
                        let body_trimmed = body.trim();
                        if body_trimmed == challenge || body_trimmed.contains(challenge) {
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
                        if body_trimmed == challenge || body_trimmed.contains(challenge) {
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
        // This is a unit test to ensure domain cleaning works
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
}