use crate::{Message, Signature, SigningKey, TimestampError, TimestampSnafu};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

pub struct SignatureBuilder<M: Serialize, C> {
    message: M,

    /// If value is None, timestamp will be set when message will be signed
    timestamp: Option<Timestamp>,

    expires_at: Option<Timestamp>,

    comment: Option<C>,
}

#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum SignatureBuilderError {
    #[snafu(display("expiration {expiration} is before timestamp {timestamp}"))]
    PastExpiration {
        expiration: Timestamp,
        timestamp: Timestamp,
    },
    #[snafu(display("encoding message in binary format"))]
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
    pub fn timestamp(mut self, timestamp: i64) -> Result<Self, TimestampError> {
        let timestamp = Timestamp::from_second(timestamp).context(TimestampSnafu { timestamp })?;
        self.timestamp = Some(timestamp);
        Ok(self)
    }

    /// If set, this timestamp **will be** signed with the message.
    pub fn expiration(mut self, timestamp: i64) -> Result<Self, TimestampError> {
        let timestamp = Timestamp::from_second(timestamp).context(TimestampSnafu { timestamp })?;
        self.expires_at = Some(timestamp);
        Ok(self)
    }

    /// The comment is not signed -> openbsd signify "untrusted comment"
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
            (timestamp <= expiration).then_some(()).ok_or(
                SignatureBuilderError::PastExpiration {
                    expiration,
                    timestamp,
                },
            )?;
        }

        // Encode message in bytes
        let message = Message {
            data: self.message,
            timestamp,
            expiration: self.expires_at,
        };
        let message_bytes = bincode::serde::encode_to_vec(&message, crate::BINCODE_CONFIG)
            .map_err(|_| SignatureBuilderError::Bincode)?;

        // Sign the message with secret key, and encode to a base64 string
        let signature = signing_key.secret_key.sign(&message_bytes);
        let bytes = signature.as_bytes();
        let signature = base64ct::Base64::encode_string(&bytes);

        Ok(Signature {
            signed_artifact: message,
            signature,
            comment: self.comment,
        })
    }
}
