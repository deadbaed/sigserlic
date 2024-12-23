pub(crate) mod builder;

use crate::PublicKey;
use base64ct::Encoding;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Message<T> {
    data: T,

    #[serde(with = "crate::timestamp::required")]
    timestamp: Timestamp,

    #[serde(with = "crate::timestamp::optional")]
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

#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum SignatureError {
    #[snafu(display("decoding signature"))]
    Signature { source: libsignify::Error },
    #[snafu(display("decoding base64"))]
    Base64 { source: base64ct::Error },
    #[snafu(display("encoding message in binary format"))]
    Bincode,
    #[snafu(display("verify signature with public key"))]
    Verify { source: libsignify::Error },
}

impl<'de, T: Serialize + Deserialize<'de>, C> Signature<T, C> {
    pub fn verify<CPubKey>(
        self,
        public_key: &PublicKey<CPubKey>,
    ) -> Result<Message<T>, SignatureError> {
        let signature = self.signature()?;

        let message_bytes =
            bincode::serde::encode_to_vec(&self.signed_artifact, crate::BINCODE_CONFIG)
                .map_err(|_| SignatureError::Bincode)?;

        public_key
            .verify(&message_bytes, &signature)
            .context(VerifySnafu)?;

        Ok(self.signed_artifact)
    }

    pub fn signature(&self) -> Result<libsignify::Signature, SignatureError> {
        use libsignify::Codeable;

        let bytes = base64ct::Base64::decode_vec(&self.signature).context(Base64Snafu)?;
        libsignify::Signature::from_bytes(&bytes).context(SignatureSnafu)
    }

    pub fn comment(&self) -> Option<&C> {
        self.comment.as_ref()
    }
}
