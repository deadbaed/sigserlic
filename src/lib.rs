mod public_key;
mod signature;
mod signing_key;
mod timestamp;

pub use public_key::PublicKey;
pub use signature::builder::SignatureBuilder;
pub use signature::{Message, Signature};
pub use signing_key::SigningKey;

use snafu::{ResultExt, Snafu};

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

pub mod error {
    pub use crate::signature::builder::SignatureBuilderError;
    pub use crate::signature::SignatureError;
}

use jiff::Timestamp;

#[derive(Debug, Snafu)]
#[snafu(display("Failed to parse timestamp {timestamp}"))]
pub struct TimestampError {
    timestamp: i64,
    source: jiff::Error,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Metadata<T> {
    #[serde(with = "timestamp::required")]
    created_at: Timestamp,

    #[serde(with = "timestamp::optional")]
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

    pub fn with_expiration(mut self, timestamp: i64) -> Result<Self, TimestampError> {
        let timestamp = Timestamp::from_second(timestamp).context(TimestampSnafu { timestamp })?;
        self.expired_at = Some(timestamp);
        Ok(self)
    }
}
