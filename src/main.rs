use base64ct::Encoding;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(serde::Serialize, serde::Deserialize)]
struct SigningKey<C> {
    #[serde(with = "signify_serde")]
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

mod signify_serde {
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

    pub fn sign<S>(self, signing_key: &SigningKey<S>) -> Signature<M, C> {
        use libsignify::Codeable;

        let timestamp = self.timestamp.unwrap_or(Timestamp::now());
        if let Some(expiration) = self.expires_at {
            if expiration <= timestamp {
                // TODO: unwrap
                panic!("cannot happen");
            }
        }

        // Encode message in bytes
        let message = Message {
            data: self.message,
            timestamp,
            expiration: self.expires_at,
        };
        // TODO: unwrap
        let message_bytes =
            bincode::serde::encode_to_vec(&message, bincode::config::standard()).expect("bincode");

        // Sign the message with secret key, and encode to a base64 string
        let signature = signing_key.secret_key.sign(&message_bytes);
        let bytes = signature.as_bytes();
        let signature = base64ct::Base64::encode_string(&bytes);

        Signature {
            signed_data: message,
            signature,
            comment: self.comment,
        }
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

impl<'de, T: Serialize + Deserialize<'de>, C> Signature<T, C> {
    pub fn verify(self, public_key: libsignify::PublicKey) -> Message<T> {
        use libsignify::Codeable;

        // TODO: unwrap
        let bytes = base64ct::Base64::decode_vec(&self.signature).unwrap();
        // TODO: unwrap
        let signature = libsignify::Signature::from_bytes(&bytes).unwrap();

        // TODO: unwrap, error handling
        let message_bytes =
            bincode::serde::encode_to_vec(&self.signed_data, bincode::config::standard()).expect("bincode");
        public_key.verify(&message_bytes, &signature).unwrap();

        self.signed_data
    }

    pub fn signature(&self) -> &str {
        &self.signature
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

    let sec: SigningKey<String> = serde_json::from_str(&json).unwrap();

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
    // .set_comment("toto mange du gateau");
    let signature = to_sign.sign(&sec);
    let signature_json = serde_json::to_string(&signature).unwrap();
    println!("{signature_json}");

    let signature: Signature<MyData, MyComment> = serde_json::from_str(&signature_json).unwrap();
    let message = signature.verify(sec.secret_key.public());
    let message_json = serde_json::to_string(&message).unwrap();
    println!("{message_json}");
}
