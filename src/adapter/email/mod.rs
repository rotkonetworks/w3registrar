pub mod imap;
pub mod jmap;

// Re-export main functions for backward compatibility
pub use imap::watch_mailserver;
pub use jmap::{initialize_jmap_sender, watch_jmap_server};