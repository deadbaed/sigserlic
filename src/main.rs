use base64ct::Encoding;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(serde::Serialize, serde::Deserialize)]
struct SigningKey<C> {
    #[serde(with = "private_key_serde")]
    secret_key: libsignify::PrivateKey,
    #[serde(flatten)]
    metadata: Metadata<C>,
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

mod private_key_serde {
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

    pub fn set_expiration(self, timestamp: Timestamp) -> Self {
        Self {
            metadata: Metadata {
                expired_at: Some(timestamp),
                ..Default::default()
            },
            secret_key: self.secret_key,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PublicKey<C> {
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
}

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
    pub fn with_comment(self, comment: T) -> Self {
        Self {
            comment: Some(comment),
            ..self
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Message<T> {
    data: T,
    timestamp: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<Timestamp>,
}

struct SignatureBuilder<M: Serialize, C> {
    message: M,

    /// If value is None, timestamp will be set when message will be signed
    timestamp: Option<Timestamp>,

    expires_at: Option<Timestamp>,

    comment: Option<C>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum SignatureBuilderError {
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
        let signature = signing_key.secret_key.sign(&message_bytes);
        let bytes = signature.as_bytes();
        let signature = base64ct::Base64::encode_string(&bytes);

        Ok(Signature {
            signed_data: message,
            signature,
            comment: self.comment,
        })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Signature<T, C> {
    /// The data signed
    signed_data: Message<T>,
    /// Base64 signature
    signature: String,
    /// Metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<C>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum SignatureError {
    #[error("decoding signature: {0}")]
    Signature(#[from] libsignify::Error),
    #[error("decoding base64: {0}")]
    Base64(#[from] base64ct::Error),
    #[error("encoding message in binary format")]
    Bincode,
}

impl<'de, T: Serialize + Deserialize<'de>, C> Signature<T, C> {
    pub fn verify<CPubKey>(
        self,
        public_key: &PublicKey<CPubKey>,
    ) -> Result<Message<T>, SignatureError> {
        let signature = self.signature()?;

        let message_bytes =
            bincode::serde::encode_to_vec(&self.signed_data, bincode::config::standard())
                .map_err(|_| SignatureError::Bincode)?;
        public_key
            .public_key
            .verify(&message_bytes, &signature)
            .unwrap();

        Ok(self.signed_data)
    }

    pub fn signature(&self) -> Result<libsignify::Signature, SignatureError> {
        use libsignify::Codeable;

        let bytes = base64ct::Base64::decode_vec(&self.signature)?;
        Ok(libsignify::Signature::from_bytes(&bytes)?)
    }

    pub fn comment(&self) -> Option<&C> {
        self.comment.as_ref()
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct MyData {
    name: String,
    action: String,
    age: u8,
}

#[derive(Serialize, Deserialize, Debug)]
struct MyComment {
    uuid: String,
    user: String,
    signature: String,
}

fn main() {
    let gen: SigningKey<()> = SigningKey::generate();
    let expiration = jiff::civil::datetime(2025, 2, 15, 22, 23, 42, 0)
        .intz("Europe/Paris")
        .unwrap();
    let gen = gen.set_expiration(expiration.timestamp());
    let json = serde_json::to_string(&gen).unwrap();
    println!("{json}");

    let gen = SigningKey::generate().with_comment(MyData {
        name: "Phil".into(),
        action: "mange du gateau".into(),
        age: 24,
    });
    let json = serde_json::to_string(&gen).unwrap();
    println!("{json}");

    let gen = SigningKey::generate().with_comment("toto mange du gateau");
    let json = serde_json::to_string(&gen).unwrap();
    println!("{json}");

    let sec: SigningKey<&str> = serde_json::from_str(&json).unwrap();

    let to_sign = SignatureBuilder::new(MyData {
        name: "toto".into(),
        action: "mange du gateau".into(),
        age: 43,
    })
    .timestamp(Timestamp::now())
    .expiration(expiration.timestamp())
    .comment(MyComment {
        uuid: "uuuuuuiiiiiddd".into(),
        user: "toto".into(),
        signature: "sssss".into(),
    });
    let signature = to_sign.sign(&sec).expect("failed to sign");
    let signature_json = serde_json::to_string(&signature).unwrap();
    println!("{signature_json}");

    let signature: Signature<MyData, MyComment> = serde_json::from_str(&signature_json).unwrap();

    let comment = signature.comment();
    println!("comment on signature {:?}", comment);

    let sig = signature.signature().expect("failed to parse signature");
    println!("signing key used {:?}", sig.signer_keynum());

    let public_key = PublicKey::from(sec);
    println!("pub key keynum {:?}", public_key.keynum());

    let message = signature.verify(&public_key).expect("failed to verify signature with public key");
    let message_json = serde_json::to_string(&message).unwrap();
    println!("{message_json}");
}
