//! Chain-specific subxt modules
//!
//! Each chain has its own generated types from metadata.
//! The identity pallet is the same across all chains, but runtime wrappers differ.

pub mod kusama;
pub mod paseo;
pub mod polkadot;
