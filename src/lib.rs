mod metadata;
mod public_key;
mod signature;
mod signing_key;
mod timestamp;

pub(crate) use metadata::Metadata;
pub use public_key::PublicKey;
pub use signature::builder::SignatureBuilder;
pub use signature::{Message, Signature};
pub use signing_key::SigningKey;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

pub mod error {
    pub use crate::signature::builder::SignatureBuilderError;
    pub use crate::signature::SignatureError;
    pub use crate::timestamp::TimestampError;
}
