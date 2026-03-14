//! People Polkadot chain types

#[subxt::subxt(
    runtime_metadata_path = "./metadata/people_polkadot.scale",
    derive_for_all_types = "parity_scale_codec::Encode"
)]
pub mod runtime {}

pub use runtime::runtime_types::pallet_identity::types::{Judgement, Registration};
pub use runtime::runtime_types::people_polkadot_runtime::people::IdentityInfo;
pub use runtime::runtime_types::people_polkadot_runtime::ProxyType;
pub use runtime::runtime_types::people_polkadot_runtime::RuntimeCall;
