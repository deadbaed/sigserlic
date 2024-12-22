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

#[cfg(feature = "generate")]
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

    pub fn with_comment(mut self, comment: C) -> Self {
        self.metadata = self.metadata.with_comment(comment);
        self
    }

    pub fn with_expiration(mut self, timestamp: i64) -> Result<Self, crate::TimestampError> {
        self.metadata = self.metadata.with_expiration(timestamp)?;
        Ok(self)
    }
}

impl<C> SigningKey<C> {
    pub fn sign(&self, msg: &[u8]) -> libsignify::Signature {
        self.secret_key.sign(msg)
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "generate")]
    mod generate_key {
        use super::super::*;

        #[test]
        fn without_comment() {
            type NoCommentSK = SigningKey<()>;

            // Generate and export key
            let generated_key = NoCommentSK::generate();
            assert!(generated_key.metadata.comment.is_none());
            assert!(generated_key.metadata.expired_at.is_none());
            let json = serde_json::to_string(&generated_key).unwrap();

            // Import key
            let imported_key: NoCommentSK = serde_json::from_str(&json).unwrap();
            assert_eq!(
                generated_key.secret_key.public().keynum(),
                imported_key.secret_key.public().keynum()
            );
        }

        #[test]
        fn primitive_comment() {
            type PrimitiveCommentSK = SigningKey<String>;

            // Generate key
            let generated_key =
                PrimitiveCommentSK::generate().with_comment("toto mange du gateau".to_string());
            assert!(generated_key.metadata.comment.is_some());
            assert!(generated_key.metadata.expired_at.is_none());

            // Export and import key
            let json = serde_json::to_string(&generated_key).unwrap();
            let imported_key: PrimitiveCommentSK = serde_json::from_str(&json).unwrap();
            assert_eq!(
                imported_key.metadata.comment.as_deref(),
                Some("toto mange du gateau")
            );
        }

        #[test]
        fn struct_comment() {
            #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
            struct Action {
                name: String,
                awesome: bool,
            }
            #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
            struct MyStruct {
                name: String,
                age: u8,
                action: Option<Action>,
            }
            type StructCommentSK = SigningKey<MyStruct>;

            // Generate key
            let generated_key = StructCommentSK::generate().with_comment(MyStruct {
                name: "Toto".into(),
                age: 24,
                action: Some(Action {
                    name: "mange du gateau".into(),
                    awesome: true,
                }),
            });
            assert!(generated_key.metadata.comment.is_some());
            assert!(generated_key.metadata.expired_at.is_none());

            // Export and import key
            let json = serde_json::to_string(&generated_key).unwrap();
            let imported_key: StructCommentSK = serde_json::from_str(&json).unwrap();
            assert_eq!(
                imported_key.metadata.comment.map(|c| c.action),
                Some(Some(Action {
                    name: "mange du gateau".into(),
                    awesome: true,
                })),
            );
        }

        #[test]
        fn with_expiration_without_comment() {
            type NoCommentSK = SigningKey<()>;

            // Generate and export key
            let generated_key = NoCommentSK::generate().with_expiration(1734885666).unwrap();
            assert!(generated_key.metadata.comment.is_none());
            assert!(generated_key.metadata.expired_at.is_some());
            let json = serde_json::to_string(&generated_key).unwrap();

            // Import key
            let imported_key: NoCommentSK = serde_json::from_str(&json).unwrap();
            assert_eq!(
                imported_key
                    .metadata
                    .expired_at
                    .as_ref()
                    .map(ToString::to_string),
                Some("2024-12-22T16:41:06Z".into())
            );
        }

        #[test]
        fn with_expiration_and_comment() {
            type PrimitiveCommentSK = SigningKey<String>;

            // Generate and export key
            let generated_key = PrimitiveCommentSK::generate()
                .with_expiration(1734885666)
                .unwrap()
                .with_comment("toto mange du gateau".into());
            assert!(generated_key.metadata.comment.is_some());
            assert!(generated_key.metadata.expired_at.is_some());
            let json = serde_json::to_string(&generated_key).unwrap();

            // Import key
            let imported_key: PrimitiveCommentSK = serde_json::from_str(&json).unwrap();
            assert_eq!(
                imported_key.metadata.comment,
                Some("toto mange du gateau".into())
            );
            assert_eq!(
                imported_key
                    .metadata
                    .expired_at
                    .as_ref()
                    .map(ToString::to_string),
                Some("2024-12-22T16:41:06Z".into())
            );
        }
    }
}
