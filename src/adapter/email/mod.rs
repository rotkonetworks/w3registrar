pub mod jmap;

pub use jmap::{initialize_jmap_sender, watch_jmap_server};

// Re-export for use by api.rs when sending challenges on registration
#[allow(unused_imports)]
pub use jmap::send_email_challenge;
