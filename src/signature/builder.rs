use crate::{Message, Signature, SigningKey};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub struct SignatureBuilder<M: Serialize, C> {
    message: M,

    /// If value is None, timestamp will be set when message will be signed
    timestamp: Option<Timestamp>,

    expires_at: Option<Timestamp>,

    comment: Option<C>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureBuilderError {
    #[error("expiration is before timestamp")]
    PastExpiration,
    #[error("encoding message in binary format")]
    Bincode,
}

impl<'de, M: Serialize + Deserialize<'de>, C> SignatureBuilder<M, C> {
    pub fn new(message: M) -> Self {
        Self {
            message,
            timestamp: None,
            expires_at: None,
            comment: None,
        }
    }

    /// This timestamp **will be** signed with the message.
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// If set, this timestamp **will be** signed with the message.
    pub fn expiration(mut self, timestamp: Timestamp) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// The comment is not signed
    pub fn comment(mut self, comment: C) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn sign<S>(
        self,
        signing_key: &SigningKey<S>,
    ) -> Result<Signature<M, C>, SignatureBuilderError> {
        use base64ct::Encoding;
        use libsignify::Codeable;

        let timestamp = self.timestamp.unwrap_or(Timestamp::now());
        if let Some(expiration) = self.expires_at {
            (timestamp <= expiration)
                .then_some(())
                .ok_or(SignatureBuilderError::PastExpiration)?;
        }

        // Encode message in bytes
        let message = Message {
            data: self.message,
            timestamp,
            expiration: self.expires_at,
        };
        let message_bytes = bincode::serde::encode_to_vec(&message, bincode::config::standard())
            .map_err(|_| SignatureBuilderError::Bincode)?;

        // Sign the message with secret key, and encode to a base64 string
        let signature = signing_key.sign(&message_bytes);
        let bytes = signature.as_bytes();
        let signature = base64ct::Base64::encode_string(&bytes);

        Ok(Signature {
            signed_data: message,
            signature,
            comment: self.comment,
        })
    }
}
