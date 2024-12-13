use crate::{SigningKey, Metadata};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicKey<C> {
    #[serde(with = "public_key_serde")]
    public_key: libsignify::PublicKey,
    #[serde(flatten)]
    metadata: Metadata<C>,
}

mod public_key_serde {
    use libsignify::{Codeable, PublicKey};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key_in_hex = hex::encode(key.as_bytes());
        serializer.serialize_str(&key_in_hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key_in_hex: String = Deserialize::deserialize(deserializer)?;
        let key_in_bytes = hex::decode(key_in_hex).map_err(serde::de::Error::custom)?;
        PublicKey::from_bytes(&key_in_bytes).map_err(serde::de::Error::custom)
    }
}

impl<C> From<SigningKey<C>> for PublicKey<C> {
    fn from(value: SigningKey<C>) -> Self {
        Self {
            public_key: value.secret_key.public(),
            metadata: value.metadata,
        }
    }
}

impl<C> PublicKey<C> {
    pub fn keynum(&self) -> libsignify::KeyNumber {
        self.public_key.keynum()
    }

    pub fn verify(&self, msg: &[u8], signature: &libsignify::Signature) -> Result<(), libsignify::Error> {
        self.public_key.verify(msg, signature)
    }
}
