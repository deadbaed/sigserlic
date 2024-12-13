use crate::Metadata;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningKey<C> {
    #[serde(with = "signing_key_serde")]
    pub(crate) secret_key: libsignify::PrivateKey,
    #[serde(flatten)]
    pub(crate) metadata: Metadata<C>,
}

impl<Comment: std::fmt::Debug> std::fmt::Debug for SigningKey<Comment> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("id", &self.secret_key.public().keynum())
            .field("secret_key", &"<secret>")
            .field("metadata", &self.metadata)
            .finish()
    }
}

mod signing_key_serde {
    use libsignify::{Codeable, PrivateKey};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key_in_hex = hex::encode(key.as_bytes());
        serializer.serialize_str(&key_in_hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key_in_hex: String = Deserialize::deserialize(deserializer)?;
        let key_in_bytes = hex::decode(key_in_hex).map_err(serde::de::Error::custom)?;
        PrivateKey::from_bytes(&key_in_bytes).map_err(serde::de::Error::custom)
    }
}

impl<C> SigningKey<C> {
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng {};
        let secret_key =
            libsignify::PrivateKey::generate(&mut rng, libsignify::NewKeyOpts::NoEncryption)
                .expect("private key without encryption");

        Self {
            secret_key,
            metadata: Default::default(),
        }
    }

    pub fn with_comment(self, comment: C) -> Self {
        Self {
            metadata: self.metadata.with_comment(comment),
            secret_key: self.secret_key,
        }
    }

    pub fn set_expiration(self, timestamp: jiff::Timestamp) -> Self {
        Self {
            metadata: Metadata {
                expired_at: Some(timestamp),
                ..Default::default()
            },
            secret_key: self.secret_key,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> libsignify::Signature {
        self.secret_key.sign(msg)
    }
}