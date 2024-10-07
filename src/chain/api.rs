use crate::chain::substrate::api;

use subxt::{OnlineClient, SubstrateConfig};

// RE-EXPORTS

pub use api::Event;
pub use api::runtime_types::pallet_identity::pallet::Event as IdentityEvent;
pub use api::runtime_types::people_rococo_runtime::people::IdentityInfo;
pub use api::runtime_types::pallet_identity::types::Data;

pub use api::storage;

pub use subxt::utils::AccountId32 as AccountId;
pub use subxt::utils::H256 as BlockHash;

// TYPES

pub type Registration = api::runtime_types::pallet_identity::types::Registration<u128, IdentityInfo>;

pub type Judgement = api::runtime_types::pallet_identity::types::Judgement<u128>;

pub type Client = OnlineClient<SubstrateConfig>;

pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
