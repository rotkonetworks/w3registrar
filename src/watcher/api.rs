#![allow(unused_imports)]

use subxt::{OnlineClient, SubstrateConfig};

pub use crate::watcher::substrate::api::storage;

pub use crate::watcher::substrate::api::Event;
pub use crate::watcher::substrate::api::identity::storage::types::identity_of::IdentityOf;
pub use crate::watcher::substrate::api::runtime_types::pallet_identity::types::Data;
pub use crate::watcher::substrate::api::runtime_types::people_rococo_runtime::people::IdentityInfo;
pub use crate::watcher::substrate::api::runtime_types::pallet_identity::pallet::Event as IdentityEvent;
pub use crate::watcher::substrate::api::identity::calls::types::request_judgement::MaxFee;
pub use crate::watcher::substrate::api::Call;

pub type Client = OnlineClient<SubstrateConfig>;

pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;

pub use subxt::utils::AccountId32 as AccountId;
