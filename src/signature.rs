pub(crate) mod builder;

use crate::PublicKey;
use base64ct::Encoding;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Message<T> {
    data: T,
    timestamp: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<Timestamp>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Signature<T, C> {
    /// The signed artifact
    signed_artifact: Message<T>,
    /// Base64 signature
    signature: String,
    /// Untrusted comment
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<C>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("decoding signature")]
    Signature(libsignify::Error),
    #[error("decoding base64: {0}")]
    Base64(#[from] base64ct::Error),
    #[error("encoding message in binary format")]
    Bincode,
    #[error("verify signature with public key")]
    Verify(libsignify::Error),
}

impl<'de, T: Serialize + Deserialize<'de>, C> Signature<T, C> {
    pub fn verify<CPubKey>(
        self,
        public_key: &PublicKey<CPubKey>,
    ) -> Result<Message<T>, SignatureError> {
        let signature = self.signature()?;

        let message_bytes =
            bincode::serde::encode_to_vec(&self.signed_artifact, bincode::config::standard())
                .map_err(|_| SignatureError::Bincode)?;

        public_key
            .verify(&message_bytes, &signature)
            .map_err(SignatureError::Verify)?;

        Ok(self.signed_artifact)
    }

    pub fn signature(&self) -> Result<libsignify::Signature, SignatureError> {
        use libsignify::Codeable;

        let bytes = base64ct::Base64::decode_vec(&self.signature)?;
        libsignify::Signature::from_bytes(&bytes).map_err(SignatureError::Verify)
    }

    pub fn comment(&self) -> Option<&C> {
        self.comment.as_ref()
    }
}
