#![allow(dead_code)]

#[subxt::subxt(runtime_metadata_path = "./identity.scale")]
pub mod api {}

use anyhow::{anyhow, Result};
use sp_core::blake2_256;
use sp_core::Encode;
use std::str::FromStr;
use subxt::ext::sp_core::sr25519::Pair as Sr25519Pair;
use subxt::ext::sp_core::Pair;
use subxt::SubstrateConfig;
use tracing::info;
use futures::StreamExt;

use api::runtime_types::pallet_identity::types::Registration;
use api::runtime_types::people_rococo_runtime::people::IdentityInfo;
use subxt::utils::AccountId32;

pub use api::*;

pub type Client = subxt::OnlineClient<SubstrateConfig>;
pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
pub type BlockHash = <SubstrateConfig as subxt::Config>::Hash;
type PairSigner = subxt::tx::PairSigner<SubstrateConfig, Sr25519Pair>;

/// subscribe to latest blocks
pub async fn subscribe_blocks(client: &Client) -> Result<impl futures::Stream<Item = Result<Block>>> {
    client.blocks().subscribe_best().await.map_err(|e| anyhow!(e))
}

/// get events from a block
pub async fn get_block_events(block: Block) -> Result<Vec<api::runtime_types::pallet_identity::pallet::Event>> {
    let mut identity_events = Vec::new();
    
    for event in block.events().await?.iter() {
        let event = event?;
        if let Ok(Some(identity_event)) = event.as_event::<api::runtime_types::pallet_identity::pallet::Event>() {
            identity_events.push(identity_event);
        }
    }
    
    Ok(identity_events)
}

/// monitor for judgement requests/given 
pub async fn process_block_events(block: Block, client: &Client, expected_registrar: u32) -> Result<Vec<EventAction>> {
    let events = get_block_events(block).await?;
    
    let mut actions = Vec::new();
    for event in events {
        match event {
            api::runtime_types::pallet_identity::pallet::Event::JudgementRequested { who, registrar_index } => {
                info!("JudgementRequested: account {:?}, registrar: {}", who, registrar_index);
                if is_registrar(registrar_index, expected_registrar) {
                    actions.push(EventAction::HandleJudgement { who, reg_index: registrar_index });
                } else {
                    info!("Ignoring request for different registrar (got: {}, expected: {})", 
                          registrar_index, expected_registrar);
                }
            },
            api::runtime_types::pallet_identity::pallet::Event::JudgementGiven { target, registrar_index } => {
                info!("Judgement given to {:?} by registrar {}", target, registrar_index);
                actions.push(EventAction::LogJudgement { target, registrar: registrar_index });
            },
            _ => {
                info!("Other identity event: {:?}", event);
                actions.push(EventAction::Log(format!("Unhandled event: {:?}", event)));
            }
        }
    }
    
    Ok(actions)
}

//
// Storage Operations
//

/// fetch identityOf from storage
pub async fn get_registration(
    client: &Client,
    who: &AccountId32,
) -> Result<Registration<u128, IdentityInfo>> {
    let storage = client.storage().at_latest().await?;
    let identity = super::node::storage().identity().identity_of(who);
    info!("identity: {:?}", identity);
    match storage.fetch(&identity).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}

//
// Identity Operations
//

/// check if fee has been paid for identity verification
pub fn has_paid_fee(judgements: &[(u32, api::runtime_types::pallet_identity::types::Judgement<u128>)]) -> bool {
    judgements.iter().any(|(_, j)| matches!(j, api::runtime_types::pallet_identity::types::Judgement::FeePaid(_)))
}

/// check if registrar index matches our expected registrar
pub fn is_registrar(reg_index: u32, expected_registrar: u32) -> bool {
    reg_index == expected_registrar
}

/// provide_judgement  TODO: add possibility to wrap with proxy
pub async fn register_identity(
    client: &Client,
    who: AccountId32,
    reg_index: u32,
    expected_registrar: u32,
) -> Result<&'static str> {
    if !is_registrar(reg_index, expected_registrar) {
        return Err(anyhow!("Wrong registrar index: expected {}, got {}", 
                          expected_registrar, reg_index));
    }

    let registration = get_registration(client, &who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));
    
    let judgement = api::tx().identity().provide_judgement(
        reg_index,
        subxt::utils::MultiAddress::Address32(who.to_owned().0),
        runtime_types::pallet_identity::types::Judgement::Reasonable,
        api::identity::calls::types::provide_judgement::Identity::from_str(&hash)
            .map_err(|e| anyhow!("Failed to parse hash: {}", e))?,
    );

    let singer: PairSigner = {
        let acc = Sr25519Pair::from_string("//ALICE", None)
            .map_err(|e| anyhow!("Failed to create signer: {}", e))?;
        PairSigner::new(acc)
    };

    let conf = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new().build();
    client
        .tx()
        .sign_and_submit_then_watch_default(&judgement, &singer)
        .await
        .map_err(|e| anyhow!("Failed to submit judgement: {}", e))?
        .wait_for_finalized_success()
        .await
        .map_err(|e| anyhow!("Failed to wait for finalization: {}", e))?;

    Ok("Reasonable")
}

#[derive(Debug)]
pub enum EventAction {
    HandleJudgement {
        who: AccountId32,
        reg_index: u32,
    },
    LogJudgement {
        target: AccountId32,
        registrar: u32,
    },
    Log(String),
}

impl EventAction {
    pub async fn execute(self, client: &Client, expected_registrar: u32) -> Result<()> {
        match self {
            EventAction::HandleJudgement { who, reg_index } => {
                // check if ours
                if !is_registrar(reg_index, expected_registrar) {
                    return Ok(());
                }

                let registration = get_registration(client, &who).await?;
                if has_paid_fee(&registration.judgements.0) {
                    info!("Processing judgement request for {:?}", who);
                    register_identity(client, who, reg_index, expected_registrar).await?;
                } else {
                    info!("Fee not paid for {:?}", who);
                }
            },
            EventAction::LogJudgement { target, registrar } => {
                info!("Logged judgement for {:?} by registrar {}", target, registrar);
            },
            EventAction::Log(msg) => {
                info!("{}", msg);
            },
        }
        Ok(())
    }
}
