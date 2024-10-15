#![allow(dead_code)]
#![allow(unused_imports)]

use super::substrate::api;

// RE-EXPORTS

pub use api::Event;
pub use api::runtime_types::pallet_identity::pallet::Event as IdentityEvent;
pub use api::runtime_types::people_kusama_runtime::people::IdentityInfo;
pub use api::runtime_types::pallet_identity::types::Data;

pub use api::storage;

// ALIASES

pub type Registration =
api::runtime_types::pallet_identity::types::Registration<u128, IdentityInfo>;

pub type Judgement = api::runtime_types::pallet_identity::types::Judgement<u128>;

