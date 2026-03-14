//! API module for W3Registrar
//!
//! This module contains:
//! - `types`: Core types (Account, AccountType, Network, verification types)
//! - `messages`: WebSocket message types and request/response structures
//! - `server`: Server infrastructure (WebSocket, HTTP, Redis subscriber)

pub mod http;
pub mod messages;
pub mod redis_subscriber;
pub mod server;
pub mod types;
pub mod validation;

// Re-export commonly used types
pub use messages::{FieldsFilter, Filter, IncomingSearchRequest, TimeFilter};

pub use types::{
    identity_data_tostring, Account, AccountType, AccountVerification, Network,
    VerificationFields,
};

// Re-export server functions
pub use http::{spawn_http_serv, spawn_identity_indexer};
pub use redis_subscriber::spawn_redis_subscriber;
pub use server::spawn_ws_serv;

// Re-export node listener from node module
pub use crate::node::listener::spawn_node_listener;
