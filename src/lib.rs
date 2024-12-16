mod public_key;
mod signature;
mod signing_key;

pub use public_key::PublicKey;
pub use signature::builder::SignatureBuilder;
pub use signature::{Message, Signature};
pub use signing_key::SigningKey;

pub mod error {
    pub use crate::signature::builder::SignatureBuilderError;
    pub use crate::signature::SignatureError;
}

use jiff::Timestamp;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Metadata<T> {
    created_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    expired_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<T>,
}

impl<T> Default for Metadata<T> {
    fn default() -> Self {
        Self {
            created_at: Timestamp::now(),
            expired_at: None,
            comment: None,
        }
    }
}

impl<T> Metadata<T> {
    pub fn with_comment(mut self, comment: T) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn with_expiration(mut self, timestamp: Timestamp) -> Self {
        self.expired_at = Some(timestamp);
        self
    }
}
