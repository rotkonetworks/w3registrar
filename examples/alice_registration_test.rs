//! Integration test for Alice registration flow
//!
//! This test simulates the complete registration flow:
//! 1. Connect to WebSocket and subscribe to account state
//! 2. Receive challenges for verification
//! 3. Verify challenges via web/dns verification
//! 4. Check that all challenges complete
//!
//! Prerequisites:
//! - Redis running on localhost:6379
//! - w3registrar service running (cargo run)
//! - For full test: DNS TXT record or HTTP file set up
//!
//! Usage:
//!   cargo run --example alice_registration_test
//!
//! Environment variables:
//!   WS_URL - WebSocket URL (default: ws://127.0.0.1:8081)
//!   TEST_ACCOUNT - Account to test (default: Alice dev account)
//!   TEST_NETWORK - Network to test (default: paseo)

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// Alice's well-known dev account
const ALICE_DEV_ACCOUNT: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

#[derive(Debug, Serialize, Deserialize)]
struct VersionedMessage {
    version: String,
    #[serde(rename = "type")]
    msg_type: String,
    payload: Value,
}

#[derive(Debug, Deserialize)]
struct ChallengeInfo {
    field: String,
    account_name: String,
    challenge: Option<String>,
    done: bool,
}

#[derive(Debug, Deserialize)]
struct AccountState {
    pending_challenges: Vec<ChallengeInfo>,
    all_done: bool,
}

#[derive(Debug)]
struct TestResult {
    connected: bool,
    received_state: bool,
    challenges: Vec<ChallengeInfo>,
    errors: Vec<String>,
}

async fn run_websocket_test(ws_url: &str, account: &str, network: &str) -> Result<TestResult> {
    let mut result = TestResult {
        connected: false,
        received_state: false,
        challenges: Vec::new(),
        errors: Vec::new(),
    };

    println!("connecting to {}", ws_url);

    let (ws_stream, response) = match timeout(
        Duration::from_secs(10),
        connect_async(ws_url)
    ).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            result.errors.push(format!("websocket connection failed: {}", e));
            return Ok(result);
        }
        Err(_) => {
            result.errors.push("connection timeout".to_string());
            return Ok(result);
        }
    };

    println!("connected! status: {}", response.status());
    result.connected = true;

    let (mut write, mut read) = ws_stream.split();

    // send subscription request
    let subscribe_msg = json!({
        "version": "1.0",
        "type": "SubscribeAccountState",
        "payload": {
            "network": network,
            "account": account
        }
    });

    println!("sending subscription: {}", serde_json::to_string_pretty(&subscribe_msg)?);

    write.send(Message::Text(subscribe_msg.to_string().into())).await?;

    // wait for response
    println!("waiting for response...");

    let response_timeout = Duration::from_secs(30);
    match timeout(response_timeout, read.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            println!("received response:\n{}", text);
            result.received_state = true;

            // try to parse response
            if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                if let Some(payload) = msg.get("payload") {
                    if let Some(message) = payload.get("message") {
                        // check for error
                        if let Some(error) = message.get("Error") {
                            result.errors.push(format!("server error: {}", error));
                        }

                        // check for account state
                        if let Some(state) = message.get("AccountState") {
                            if let Some(challenges) = state.get("pending_challenges") {
                                if let Ok(parsed) = serde_json::from_value::<Vec<ChallengeInfo>>(challenges.clone()) {
                                    result.challenges = parsed;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Some(Ok(Message::Close(frame)))) => {
            result.errors.push(format!("connection closed: {:?}", frame));
        }
        Ok(Some(Err(e))) => {
            result.errors.push(format!("read error: {}", e));
        }
        Ok(None) => {
            result.errors.push("stream ended".to_string());
        }
        Err(_) => {
            result.errors.push("response timeout".to_string());
        }
        _ => {
            // ignore other message types (ping, pong, binary, etc)
        }
    }

    // close connection
    let _ = write.close().await;

    Ok(result)
}

async fn test_dns_verification(domain: &str, challenge: &str) -> bool {
    w3registrar::adapter::web::dns::verify_txt(domain, challenge).await
}

async fn test_http_verification(domain: &str, challenge: &str) -> bool {
    w3registrar::adapter::web::http::verify_http(domain, challenge).await
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let ws_url = env::var("WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8081".to_string());
    let account = env::var("TEST_ACCOUNT").unwrap_or_else(|_| ALICE_DEV_ACCOUNT.to_string());
    let network = env::var("TEST_NETWORK").unwrap_or_else(|_| "paseo".to_string());

    println!("=== w3registrar integration test ===");
    println!("websocket url: {}", ws_url);
    println!("account: {}", account);
    println!("network: {}", network);
    println!();

    // test 1: websocket connection and state subscription
    println!("test 1: websocket subscription");
    println!("{}", "-".repeat(40));

    let result = run_websocket_test(&ws_url, &account, &network).await?;

    if !result.connected {
        println!("FAIL: could not connect to websocket");
        for err in &result.errors {
            println!("  error: {}", err);
        }
        println!();
        println!("make sure w3registrar is running:");
        println!("  cargo run");
        return Ok(());
    }

    println!("OK: connected to websocket");

    if !result.received_state {
        println!("FAIL: did not receive state response");
        for err in &result.errors {
            println!("  error: {}", err);
        }
        return Ok(());
    }

    if !result.errors.is_empty() {
        for err in &result.errors {
            println!("note: {}", err);
        }
    }

    println!("OK: received account state");
    println!();

    // test 2: check challenges
    println!("test 2: pending challenges");
    println!("{}", "-".repeat(40));

    if result.challenges.is_empty() {
        println!("no pending challenges found");
        println!("(account may not have requested judgement on-chain)");
    } else {
        println!("found {} challenges:", result.challenges.len());
        for challenge in &result.challenges {
            let status = if challenge.done { "done" } else { "pending" };
            let token = challenge.challenge.as_deref().unwrap_or("(none)");
            println!(
                "  - {}: {} [{}]",
                challenge.field, challenge.account_name, status
            );
            if !challenge.done && challenge.challenge.is_some() {
                println!("    token: {}", token);
            }
        }
    }
    println!();

    // test 3: verify web challenges if present
    println!("test 3: web verification");
    println!("{}", "-".repeat(40));

    let web_challenges: Vec<_> = result.challenges.iter()
        .filter(|c| c.field == "web" && !c.done && c.challenge.is_some())
        .collect();

    if web_challenges.is_empty() {
        println!("no pending web challenges to verify");
    } else {
        for challenge in web_challenges {
            let domain = &challenge.account_name;
            let token = challenge.challenge.as_ref().unwrap();

            println!("verifying domain: {}", domain);

            // try http first
            println!("  checking http...");
            if test_http_verification(domain, token).await {
                println!("  HTTP: OK");
            } else {
                println!("  HTTP: not found");
            }

            // try dns
            println!("  checking dns txt...");
            if test_dns_verification(domain, token).await {
                println!("  DNS: OK");
            } else {
                println!("  DNS: not found");
            }

            println!("  to verify this domain, either:");
            println!("    1. create file at https://{}/.well-known/w3registrar/{}", domain, token);
            println!("    2. add dns txt record: {}", token);
        }
    }
    println!();

    // test 4: test email verification lookup (if present)
    println!("test 4: email challenges");
    println!("{}", "-".repeat(40));

    let email_challenges: Vec<_> = result.challenges.iter()
        .filter(|c| c.field == "email" && !c.done)
        .collect();

    if email_challenges.is_empty() {
        println!("no pending email challenges");
    } else {
        for challenge in email_challenges {
            println!("email: {}", challenge.account_name);
            if let Some(token) = &challenge.challenge {
                println!("  challenge token: {}", token);
                println!("  to verify: send email with token to w3registrar inbox");
            } else {
                println!("  (awaiting outbound challenge)");
            }
        }
    }
    println!();

    println!("=== test complete ===");

    let pending = result.challenges.iter().filter(|c| !c.done).count();
    let done = result.challenges.iter().filter(|c| c.done).count();

    println!("summary: {} pending, {} done", pending, done);

    if pending == 0 && !result.challenges.is_empty() {
        println!("all challenges verified - identity should be registered");
    }

    Ok(())
}
