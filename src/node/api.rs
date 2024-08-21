#![allow(unused_imports)]

use subxt::{OnlineClient, SubstrateConfig};

pub use crate::node::substrate::api::storage;

pub use crate::node::substrate::api::Event;
pub use crate::node::substrate::api::identity::storage::types::identity_of::IdentityOf;
pub use crate::node::substrate::api::runtime_types::pallet_identity::types::Data;
pub use crate::node::substrate::api::runtime_types::people_rococo_runtime::people::IdentityInfo;
pub use crate::node::substrate::api::runtime_types::pallet_identity::pallet::Event as IdentityEvent;
pub use crate::node::substrate::api::identity::calls::types::request_judgement::MaxFee;

pub type Client = OnlineClient<SubstrateConfig>;
