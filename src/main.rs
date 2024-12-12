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

// impl<Comment: std::fmt::Debug> std::fmt::Debug for SigningKey<Comment> {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("SigningKey")
//             .field("id", &self.secret_key.public().keynum())
//             .field("secret_key", &"<secret>")
//             .field("metadata", &self.metadata)
//             .finish()
//     }
// }

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
struct Signature<T, C> {
    /// The data signed
    signed_data: T,
    /// Base64 signature
    signature: String,
    /// Metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<C>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Message<T> {
    data: T,
    timestamp: Timestamp,
}

impl<CKey> SigningKey<CKey> {
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

    pub fn with_comment(self, comment: CKey) -> Self {
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

    // TODO: move to struct SignatureBuilder
    // TODO: option to set when signature will expire
    pub fn sign<M: Serialize, CSignature>(
        &self,
        message: M,
        comment: Option<CSignature>,
    ) -> Signature<Message<M>, CSignature> {
        use libsignify::Codeable;

        // Encode message in bytes
        let message_to_sign = Message {
            data: message,
            timestamp: Timestamp::now(),
        };
        // TODO: unwrap
        let message_bytes =
            bincode::serde::encode_to_vec(&message_to_sign, bincode::config::standard())
                .expect("bincode");

        // Sign the message with secret key, and encode to a base64 string
        let signature = self.secret_key.sign(&message_bytes);
        let bytes = signature.as_bytes();
        let signature = base64ct::Base64::encode_string(&bytes);

        Signature {
            signed_data: message_to_sign,
            signature,
            comment,
        }
    }

    // TODO: trait "Signing" and "Verifying" ? -> NO just use Codable
    pub fn verify(&self) {
        // self.secret_key.public.verify()
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

    let message = MyData {
        name: "toto".into(),
        action: "mange du gateau".into(),
        age: 43,
    };

    // let comment = Some("gateau au chocolat");
    let comment = Some(MyComment {
        uuid: "uuuuuuiiiiiddd".into(),
        user: "toto".into(),
        signature: "sssss".into(),
    });
    // let comment: Option<String> = None;
    let signature = sec.sign(message, comment);
    let signature_json = serde_json::to_string(&signature).unwrap();
    println!("{signature_json}");
}
