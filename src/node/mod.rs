#![allow(unused_imports)]

mod substrate;

use subxt::{OnlineClient, SubstrateConfig};

// RE-EXPORTS

pub use substrate::api::Event;
pub use substrate::api::runtime_types::pallet_identity::pallet::Event as IdentityEvent;
pub use subxt::utils::H256 as BlockHash;
pub use subxt::utils::AccountId32 as AccountId;

// TYPES

pub type RegistrarIndex = u32;

pub type Client = OnlineClient<SubstrateConfig>;

pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
