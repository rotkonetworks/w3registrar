//! End-to-end test for Cloudflare DNS verification
//!
//! Usage:
//!   CF_API_TOKEN=your-token cargo run --example cloudflare_test --features cloudflare
//!
//! This test will:
//! 1. Create a TXT record on a test subdomain
//! 2. Verify it can be read via DNS
//! 3. Clean up the record

use anyhow::Result;
use std::env;

#[cfg(feature = "cloudflare")]
use w3registrar::adapter::cloudflare::CloudflareManager;

#[cfg(feature = "cloudflare")]
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let api_token = env::var("CF_API_TOKEN").expect("CF_API_TOKEN environment variable required");

    let test_domain = env::var("CF_TEST_DOMAIN").unwrap_or_else(|_| "w3reg-test.rotko.net".to_string());
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

        verified = w3registrar::adapter::web::dns::verify_txt(&test_domain, &challenge_token).await;
        if verified {
            println!("   DNS verification: SUCCESS on attempt {}", attempt);
            break;
        } else {
            println!("   DNS verification: not yet propagated");
        }
    }

    println!("3. Final DNS verification result: {}", if verified { "SUCCESS" } else { "FAILED" });

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

#[cfg(not(feature = "cloudflare"))]
fn main() {
    eprintln!("This example requires the 'cloudflare' feature.");
    eprintln!("Run with: cargo run --example cloudflare_test --features cloudflare");
}
