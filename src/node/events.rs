//! Shared event processing for identity pallet events
//!
//! This module provides a reusable event processor that can be used by both
//! the real-time NodeListener and the historical Indexer.

use crate::api::Network;
use crate::node::identity::events::{
    AuthorityAdded, AuthorityRemoved, DanglingUsernameRemoved, IdentityCleared, IdentityKilled,
    IdentitySet, JudgementGiven, JudgementRequested, JudgementUnrequested, PreapprovalExpired,
    PrimaryUsernameSet, RegistrarAdded, SubIdentityAdded, SubIdentityRemoved, SubIdentityRevoked,
    UsernameKilled, UsernameQueued, UsernameSet,
};
use crate::postgres::{IdentityEvent, IdentityEventType, PostgresConnection};

use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use tracing::{error, info};

/// Result of processing a single event
#[derive(Debug, Clone)]
pub struct ProcessedEvent {
    pub event_type: IdentityEventType,
    pub account: Option<AccountId32>,
    pub registrar_index: Option<u32>,
    pub data: Option<serde_json::Value>,
}

/// Extract and process all identity events from a block's events
pub async fn process_identity_events(
    events: &subxt::events::Events<SubstrateConfig>,
    network: &Network,
    block_number: u32,
    block_hash: &str,
) -> Vec<ProcessedEvent> {
    let mut processed = Vec::new();

    for event_result in events.iter() {
        let Ok(event) = event_result else { continue };

        if let Some(processed_event) = extract_identity_event(&event) {
            // Store to database
            store_event(
                &processed_event,
                network,
                block_number,
                block_hash,
            )
            .await;

            processed.push(processed_event);
        }
    }

    processed
}

/// Extract identity event data from a raw event
fn extract_identity_event(
    event: &subxt::events::EventDetails<SubstrateConfig>,
) -> Option<ProcessedEvent> {
    // JudgementRequested
    if let Ok(Some(req)) = event.as_event::<JudgementRequested>() {
        info!(requester = %req.who, "judgement requested");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::JudgementRequested,
            account: Some(req.who.clone()),
            registrar_index: Some(req.registrar_index),
            data: None,
        });
    }

    // JudgementUnrequested
    if let Ok(Some(req)) = event.as_event::<JudgementUnrequested>() {
        info!(requester = %req.who, "judgement unrequested");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::JudgementUnrequested,
            account: Some(req.who.clone()),
            registrar_index: Some(req.registrar_index),
            data: None,
        });
    }

    // JudgementGiven
    if let Ok(Some(jud)) = event.as_event::<JudgementGiven>() {
        info!(target = %jud.target, registrar = jud.registrar_index, "judgement given");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::JudgementGiven,
            account: Some(jud.target.clone()),
            registrar_index: Some(jud.registrar_index),
            data: None,
        });
    }

    // IdentitySet
    if let Ok(Some(evt)) = event.as_event::<IdentitySet>() {
        info!(who = %evt.who, "identity set");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::IdentitySet,
            account: Some(evt.who.clone()),
            registrar_index: None,
            data: None,
        });
    }

    // IdentityCleared
    if let Ok(Some(evt)) = event.as_event::<IdentityCleared>() {
        info!(who = %evt.who, "identity cleared");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::IdentityCleared,
            account: Some(evt.who.clone()),
            registrar_index: None,
            data: None,
        });
    }

    // IdentityKilled
    if let Ok(Some(evt)) = event.as_event::<IdentityKilled>() {
        info!(who = %evt.who, "identity killed");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::IdentityKilled,
            account: Some(evt.who.clone()),
            registrar_index: None,
            data: None,
        });
    }

    // SubIdentityAdded
    if let Ok(Some(evt)) = event.as_event::<SubIdentityAdded>() {
        info!(sub = %evt.sub, main = %evt.main, "sub identity added");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::SubIdentityAdded,
            account: Some(evt.sub.clone()),
            registrar_index: None,
            data: Some(serde_json::json!({"main": evt.main.to_string()})),
        });
    }

    // SubIdentityRemoved
    if let Ok(Some(evt)) = event.as_event::<SubIdentityRemoved>() {
        info!(sub = %evt.sub, main = %evt.main, "sub identity removed");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::SubIdentityRemoved,
            account: Some(evt.sub.clone()),
            registrar_index: None,
            data: Some(serde_json::json!({"main": evt.main.to_string()})),
        });
    }

    // SubIdentityRevoked
    if let Ok(Some(evt)) = event.as_event::<SubIdentityRevoked>() {
        info!(sub = %evt.sub, "sub identity revoked");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::SubIdentityRevoked,
            account: Some(evt.sub.clone()),
            registrar_index: None,
            data: None,
        });
    }

    // RegistrarAdded
    if let Ok(Some(evt)) = event.as_event::<RegistrarAdded>() {
        info!(registrar_index = evt.registrar_index, "registrar added");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::RegistrarAdded,
            account: None, // System event
            registrar_index: Some(evt.registrar_index),
            data: None,
        });
    }

    // AuthorityAdded
    if let Ok(Some(evt)) = event.as_event::<AuthorityAdded>() {
        info!(authority = %evt.authority, "authority added");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::AuthorityAdded,
            account: Some(evt.authority.clone()),
            registrar_index: None,
            data: None,
        });
    }

    // AuthorityRemoved
    if let Ok(Some(evt)) = event.as_event::<AuthorityRemoved>() {
        info!(authority = %evt.authority, "authority removed");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::AuthorityRemoved,
            account: Some(evt.authority.clone()),
            registrar_index: None,
            data: None,
        });
    }

    // UsernameSet
    if let Ok(Some(evt)) = event.as_event::<UsernameSet>() {
        let username = String::from_utf8_lossy(&evt.username.0).to_string();
        info!(who = %evt.who, username = %username, "username set");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::UsernameSet,
            account: Some(evt.who.clone()),
            registrar_index: None,
            data: Some(serde_json::json!({"username": username})),
        });
    }

    // UsernameQueued
    if let Ok(Some(evt)) = event.as_event::<UsernameQueued>() {
        let username = String::from_utf8_lossy(&evt.username.0).to_string();
        info!(who = %evt.who, username = %username, "username queued");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::UsernameQueued,
            account: Some(evt.who.clone()),
            registrar_index: None,
            data: Some(serde_json::json!({"username": username})),
        });
    }

    // UsernameKilled
    if let Ok(Some(evt)) = event.as_event::<UsernameKilled>() {
        let username = String::from_utf8_lossy(&evt.username.0).to_string();
        info!(username = %username, "username killed");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::UsernameKilled,
            account: None, // No account, just username
            registrar_index: None,
            data: Some(serde_json::json!({"username": username})),
        });
    }

    // PrimaryUsernameSet
    if let Ok(Some(evt)) = event.as_event::<PrimaryUsernameSet>() {
        let username = String::from_utf8_lossy(&evt.username.0).to_string();
        info!(who = %evt.who, username = %username, "primary username set");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::PrimaryUsernameSet,
            account: Some(evt.who.clone()),
            registrar_index: None,
            data: Some(serde_json::json!({"username": username})),
        });
    }

    // DanglingUsernameRemoved
    if let Ok(Some(evt)) = event.as_event::<DanglingUsernameRemoved>() {
        let username = String::from_utf8_lossy(&evt.username.0).to_string();
        info!(who = %evt.who, username = %username, "dangling username removed");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::DanglingUsernameRemoved,
            account: Some(evt.who.clone()),
            registrar_index: None,
            data: Some(serde_json::json!({"username": username})),
        });
    }

    // PreapprovalExpired
    if let Ok(Some(evt)) = event.as_event::<PreapprovalExpired>() {
        info!(whose = %evt.whose, "preapproval expired");
        return Some(ProcessedEvent {
            event_type: IdentityEventType::PreapprovalExpired,
            account: Some(evt.whose.clone()),
            registrar_index: None,
            data: None,
        });
    }

    None
}

/// Store a processed event to the database
async fn store_event(
    processed: &ProcessedEvent,
    network: &Network,
    block_number: u32,
    block_hash: &str,
) {
    let Ok(conn) = PostgresConnection::default().await else {
        error!("failed to connect to postgres for event storage");
        return;
    };

    // Use system account (all zeros) for events without an account
    let account = processed
        .account
        .clone()
        .unwrap_or_else(|| AccountId32::from([0u8; 32]));

    let mut event = IdentityEvent::new(
        &account,
        network,
        processed.event_type.clone(),
        block_number,
        block_hash,
    );

    if let Some(idx) = processed.registrar_index {
        event = event.with_registrar(idx);
    }
    if let Some(ref d) = processed.data {
        event = event.with_data(d.clone());
    }

    if let Err(e) = conn.store_identity_event(&event).await {
        error!(error = %e, "failed to store identity event");
    }
}

/// Check if an event is a JudgementRequested event and return the details
pub fn is_judgement_requested(processed: &ProcessedEvent) -> Option<(AccountId32, u32)> {
    if processed.event_type == IdentityEventType::JudgementRequested {
        if let (Some(account), Some(registrar_index)) =
            (processed.account.clone(), processed.registrar_index)
        {
            return Some((account, registrar_index));
        }
    }
    None
}

/// Check if an event is a JudgementUnrequested event and return the details
pub fn is_judgement_unrequested(processed: &ProcessedEvent) -> Option<(AccountId32, u32)> {
    if processed.event_type == IdentityEventType::JudgementUnrequested {
        if let (Some(account), Some(registrar_index)) =
            (processed.account.clone(), processed.registrar_index)
        {
            return Some((account, registrar_index));
        }
    }
    None
}

/// Check if an event is a JudgementGiven event and return the details
pub fn is_judgement_given(processed: &ProcessedEvent) -> Option<(AccountId32, u32)> {
    if processed.event_type == IdentityEventType::JudgementGiven {
        if let (Some(account), Some(registrar_index)) =
            (processed.account.clone(), processed.registrar_index)
        {
            return Some((account, registrar_index));
        }
    }
    None
}
