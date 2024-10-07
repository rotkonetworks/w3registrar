pub mod substrate;

use subxt::{OnlineClient, SubstrateConfig};

// RE-EXPORTS

pub use substrate::api::Event;
pub use substrate::api::runtime_types::pallet_identity::pallet::Event as IdentityEvent;
pub use substrate::api::runtime_types::people_rococo_runtime::people::IdentityInfo;
pub use substrate::api::runtime_types::pallet_identity::types::Data;

pub use substrate::api::storage;

pub use subxt::utils::AccountId32 as AccountId;
pub use subxt::utils::H256 as BlockHash;

// TYPES

pub type Registration = substrate::api::runtime_types::pallet_identity::types::Registration<u128, IdentityInfo>;

pub type Judgement = substrate::api::runtime_types::pallet_identity::types::Judgement<u128>;

pub type Client = OnlineClient<SubstrateConfig>;

pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
