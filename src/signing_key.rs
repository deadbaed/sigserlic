use crate::KeyMetadata;
use crate::Metadata;
use crate::error::TimestampError;

#[derive(serde::Serialize, serde::Deserialize)]
/// A key with the capability of signing data, producing a [`Signature`](crate::Signature), which can be
/// verified by a [`PublicKey`](crate::PublicKey).
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
    use base64ct::Encoding;
    use libsignify::{Codeable, PrivateKey};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64ct::Base64::encode_string(key.as_bytes().as_ref());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key_in_base64: String = Deserialize::deserialize(deserializer)?;
        let key_in_bytes =
            base64ct::Base64::decode_vec(&key_in_base64).map_err(serde::de::Error::custom)?;
        PrivateKey::from_bytes(&key_in_bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "generate")]
impl<C> SigningKey<C> {
    /// Generate a new signing key
    ///
    /// ```
    /// # use sigserlic::KeyMetadata;
    /// type Comment = (); // No comment for this key
    /// type MyKey = sigserlic::SigningKey::<Comment>;
    ///
    /// let signing_key = MyKey::generate();
    /// ```
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

    /// Set comment to the key, where the type must implement [`Debug`], [`serde::Serialize`], [`serde::Deserialize`]
    ///
    /// ```
    /// # use sigserlic::KeyMetadata;
    /// #[derive(Debug, serde::Serialize, serde::Deserialize)]
    /// struct MyComment {
    ///     name: String,
    ///     data: Vec<u8>,
    ///     age: u8,
    ///     awesome: bool,
    /// }
    /// type MyKey = sigserlic::SigningKey::<MyComment>;
    ///
    /// let signing_key = MyKey::generate().with_comment(MyComment {
    ///    name: "Phil".into(),
    ///    data: vec![0xde, 0xad, 0xba, 0xed],
    ///    age: 42,
    ///    awesome: true,
    /// });
    /// assert!(signing_key.comment().is_some_and(|c| c.awesome == true));
    /// ```
    pub fn with_comment(mut self, comment: C) -> Self {
        self.metadata = self.metadata.with_comment(comment);
        self
    }

    /// Declare when the key is supposed to expire
    ///
    /// ```
    /// # use sigserlic::KeyMetadata;
    /// # use jiff::ToSpan;
    /// # let now = jiff::Timestamp::now();
    /// #[derive(Debug, serde::Serialize, serde::Deserialize)]
    /// struct MyComment {
    ///     name: String,
    ///     data: Vec<u8>,
    ///     age: u8,
    ///     awesome: bool,
    /// }
    /// type MyKey = sigserlic::SigningKey::<()>;
    /// let signing_key = MyKey::generate();
    ///
    /// # let expiration = (now + 2.hours()).as_second();
    /// let signing_key = signing_key.with_expiration(expiration).unwrap();
    /// assert!(signing_key.expired_at().is_some_and(|e| e > signing_key.created_at()));
    /// ```
    pub fn with_expiration(mut self, timestamp: i64) -> Result<Self, TimestampError> {
        // TODO: return error if timestamp is before generation timestamp
        self.metadata = self.metadata.with_expiration(timestamp)?;
        Ok(self)
    }
}

impl<C> SigningKey<C> {
    /// Consume a [`SignatureBuilder`](crate::SignatureBuilder) to produce a
    /// [`Signature`](crate::Signature)
    ///
    /// See [`SignatureBuilder::sign()`](crate::SignatureBuilder::sign()) for an example.
    pub fn sign<'de, Message: serde::Serialize + serde::Deserialize<'de>, MessageComment>(
        &self,
        signature_builder: crate::SignatureBuilder<Message, MessageComment>,
    ) -> Result<crate::Signature<Message, MessageComment>, crate::error::SignatureBuilderError>
    {
        signature_builder.sign(self)
    }
}

impl<C> KeyMetadata<C> for SigningKey<C> {
    fn created_at(&self) -> i64 {
        self.metadata.created_at.as_second()
    }

    fn expired_at(&self) -> Option<i64> {
        self.metadata.expired_at.map(|e| e.as_second())
    }

    fn keynum(&self) -> libsignify::KeyNumber {
        self.secret_key.public().keynum()
    }

    fn comment(&self) -> Option<&C> {
        self.metadata.comment.as_ref()
    }

    fn usage(&self) -> crate::KeyUsage {
        crate::KeyUsage::Signing
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn debug_fmt_do_not_leak_secret_key() {
        let json = r#"{"secret_key":"RWRCSwAAAAD7Od0ms9qjK7pDPi1+07phkG3M+2u/tP+Xrjfqh35YjNsnWGP4FPXiY52Ai99W3A0UKrt65iZ9bYhInAZx63D4dopB2KUGoLLQLZtDMySVeFow8Zp/0X9465QjzovIsCY=","created_at":"2024-12-23T00:12:54.53753Z","expired_at":null}"#;
        let key: SigningKey<()> = serde_json::from_str(json).unwrap();

        assert!(format!("{key:?}").contains("<secret>"));
    }

    #[cfg(feature = "generate")]
    mod generate {
        use super::*;

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
                crate::PublicKey::from(generated_key).keynum(),
                crate::PublicKey::from(imported_key).keynum(),
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

    mod import {

        mod no_comment_no_expiration {
            use super::super::super::*;

            #[test]
            fn json() {
                let json = r#"{"secret_key":"RWRCSwAAAAD7Od0ms9qjK7pDPi1+07phkG3M+2u/tP+Xrjfqh35YjNsnWGP4FPXiY52Ai99W3A0UKrt65iZ9bYhInAZx63D4dopB2KUGoLLQLZtDMySVeFow8Zp/0X9465QjzovIsCY=","created_at":"2024-12-23T00:12:54.53753Z","expired_at":null}"#;
                let key: SigningKey<()> = serde_json::from_str(json).unwrap();
                assert!(key.metadata.comment.is_none());
                assert!(key.metadata.expired_at.is_none());
            }

            #[test]
            fn cbor() {
                let cbor: [u8; 274] = [
                    191, 106, 115, 101, 99, 114, 101, 116, 95, 107, 101, 121, 120, 208, 52, 53, 54,
                    52, 52, 50, 52, 98, 48, 48, 48, 48, 48, 48, 48, 48, 102, 98, 51, 57, 100, 100,
                    50, 54, 98, 51, 100, 97, 97, 51, 50, 98, 98, 97, 52, 51, 51, 101, 50, 100, 55,
                    101, 100, 51, 98, 97, 54, 49, 57, 48, 54, 100, 99, 99, 102, 98, 54, 98, 98,
                    102, 98, 52, 102, 102, 57, 55, 97, 101, 51, 55, 101, 97, 56, 55, 55, 101, 53,
                    56, 56, 99, 100, 98, 50, 55, 53, 56, 54, 51, 102, 56, 49, 52, 102, 53, 101, 50,
                    54, 51, 57, 100, 56, 48, 56, 98, 100, 102, 53, 54, 100, 99, 48, 100, 49, 52,
                    50, 97, 98, 98, 55, 97, 101, 54, 50, 54, 55, 100, 54, 100, 56, 56, 52, 56, 57,
                    99, 48, 54, 55, 49, 101, 98, 55, 48, 102, 56, 55, 54, 56, 97, 52, 49, 100, 56,
                    97, 53, 48, 54, 97, 48, 98, 50, 100, 48, 50, 100, 57, 98, 52, 51, 51, 51, 50,
                    52, 57, 53, 55, 56, 53, 97, 51, 48, 102, 49, 57, 97, 55, 102, 100, 49, 55, 102,
                    55, 56, 101, 98, 57, 52, 50, 51, 99, 101, 56, 98, 99, 56, 98, 48, 50, 54, 106,
                    99, 114, 101, 97, 116, 101, 100, 95, 97, 116, 120, 26, 50, 48, 50, 52, 45, 49,
                    50, 45, 50, 51, 84, 48, 48, 58, 49, 50, 58, 53, 52, 46, 53, 51, 55, 53, 51, 90,
                    106, 101, 120, 112, 105, 114, 101, 100, 95, 97, 116, 246, 255,
                ];
                let key: SigningKey<String> = ciborium::from_reader(cbor.as_slice()).unwrap();
                assert!(key.metadata.comment.is_none());
                assert!(key.metadata.expired_at.is_none());
            }
        }

        mod primitive_comment_no_expiration {
            use super::super::super::*;

            #[test]
            fn json() {
                let json = r#"{"secret_key":"RWRCSwAAAAAqoN8nUn93E6gEYuiqdfJBYnt5X0f+VQ1cik6b4ImX143umMij6LwAkQfu/7VJkmbyEmMR1tW1LaH5ngNFQ/wEyaDyljmdcpUXX96KyiAUDacFzdWN3MNHEcuE83VyxWY=","created_at":"2024-12-22T23:21:47.572035Z","expired_at":null,"comment":"testing key"}"#;

                let key: SigningKey<String> = serde_json::from_str(json).unwrap();
                assert_eq!(key.metadata.comment, Some("testing key".into()));
                assert!(key.metadata.expired_at.is_none());
            }

            #[test]
            fn cbor() {
                let cbor: [u8; 295] = [
                    191, 106, 115, 101, 99, 114, 101, 116, 95, 107, 101, 121, 120, 208, 52, 53, 54,
                    52, 52, 50, 52, 98, 48, 48, 48, 48, 48, 48, 48, 48, 50, 97, 97, 48, 100, 102,
                    50, 55, 53, 50, 55, 102, 55, 55, 49, 51, 97, 56, 48, 52, 54, 50, 101, 56, 97,
                    97, 55, 53, 102, 50, 52, 49, 54, 50, 55, 98, 55, 57, 53, 102, 52, 55, 102, 101,
                    53, 53, 48, 100, 53, 99, 56, 97, 52, 101, 57, 98, 101, 48, 56, 57, 57, 55, 100,
                    55, 56, 100, 101, 101, 57, 56, 99, 56, 97, 51, 101, 56, 98, 99, 48, 48, 57, 49,
                    48, 55, 101, 101, 102, 102, 98, 53, 52, 57, 57, 50, 54, 54, 102, 50, 49, 50,
                    54, 51, 49, 49, 100, 54, 100, 53, 98, 53, 50, 100, 97, 49, 102, 57, 57, 101,
                    48, 51, 52, 53, 52, 51, 102, 99, 48, 52, 99, 57, 97, 48, 102, 50, 57, 54, 51,
                    57, 57, 100, 55, 50, 57, 53, 49, 55, 53, 102, 100, 101, 56, 97, 99, 97, 50, 48,
                    49, 52, 48, 100, 97, 55, 48, 53, 99, 100, 100, 53, 56, 100, 100, 99, 99, 51,
                    52, 55, 49, 49, 99, 98, 56, 52, 102, 51, 55, 53, 55, 50, 99, 53, 54, 54, 106,
                    99, 114, 101, 97, 116, 101, 100, 95, 97, 116, 120, 27, 50, 48, 50, 52, 45, 49,
                    50, 45, 50, 50, 84, 50, 51, 58, 50, 49, 58, 52, 55, 46, 53, 55, 50, 48, 51, 53,
                    90, 106, 101, 120, 112, 105, 114, 101, 100, 95, 97, 116, 246, 103, 99, 111,
                    109, 109, 101, 110, 116, 107, 116, 101, 115, 116, 105, 110, 103, 32, 107, 101,
                    121, 255,
                ];

                let key: SigningKey<String> = ciborium::from_reader(cbor.as_slice()).unwrap();
                assert_eq!(key.metadata.comment, Some("testing key".into()));
                assert!(key.metadata.expired_at.is_none());
            }
        }

        mod struct_comment_with_expiration {
            use super::super::super::*;

            #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
            struct MyStruct {
                name: String,
                age: u8,
                awesome: bool,
            }

            #[test]
            fn json() {
                let json = r#"{"secret_key":"RWRCSwAAAADEfue6i+LO83WVojLGXwcpkXy3tUtt2LODHh/s4smBUJII6JfWumGl5tUJjAnuZ9QAJAnoDddk5eo6yAxDyYDy6SsVrGfELIc3dP2zR10+WII9flLCBGXZriq5IHku2+4=","created_at":"2024-12-23T00:27:59.297345Z","expired_at":"2025-06-15T15:06:40Z","comment":{"name":"Phil","age":24,"awesome":true}}"#;

                let key: SigningKey<MyStruct> = serde_json::from_str(json).unwrap();
                assert_eq!(
                    key.metadata.comment,
                    Some(MyStruct {
                        name: "Phil".into(),
                        age: 24,
                        awesome: true
                    })
                );
                assert_eq!(
                    key.metadata.expired_at.map(|e| e.as_second()),
                    Some(1750000000)
                );
            }

            #[test]
            fn cbor() {
                let cbor: [u8; 329] = [
                    191, 106, 115, 101, 99, 114, 101, 116, 95, 107, 101, 121, 120, 208, 52, 53, 54,
                    52, 52, 50, 52, 98, 48, 48, 48, 48, 48, 48, 48, 48, 99, 52, 55, 101, 101, 55,
                    98, 97, 56, 98, 101, 50, 99, 101, 102, 51, 55, 53, 57, 53, 97, 50, 51, 50, 99,
                    54, 53, 102, 48, 55, 50, 57, 57, 49, 55, 99, 98, 55, 98, 53, 52, 98, 54, 100,
                    100, 56, 98, 51, 56, 51, 49, 101, 49, 102, 101, 99, 101, 50, 99, 57, 56, 49,
                    53, 48, 57, 50, 48, 56, 101, 56, 57, 55, 100, 54, 98, 97, 54, 49, 97, 53, 101,
                    54, 100, 53, 48, 57, 56, 99, 48, 57, 101, 101, 54, 55, 100, 52, 48, 48, 50, 52,
                    48, 57, 101, 56, 48, 100, 100, 55, 54, 52, 101, 53, 101, 97, 51, 97, 99, 56,
                    48, 99, 52, 51, 99, 57, 56, 48, 102, 50, 101, 57, 50, 98, 49, 53, 97, 99, 54,
                    55, 99, 52, 50, 99, 56, 55, 51, 55, 55, 52, 102, 100, 98, 51, 52, 55, 53, 100,
                    51, 101, 53, 56, 56, 50, 51, 100, 55, 101, 53, 50, 99, 50, 48, 52, 54, 53, 100,
                    57, 97, 101, 50, 97, 98, 57, 50, 48, 55, 57, 50, 101, 100, 98, 101, 101, 106,
                    99, 114, 101, 97, 116, 101, 100, 95, 97, 116, 120, 27, 50, 48, 50, 52, 45, 49,
                    50, 45, 50, 51, 84, 48, 48, 58, 50, 55, 58, 53, 57, 46, 50, 57, 55, 51, 52, 53,
                    90, 106, 101, 120, 112, 105, 114, 101, 100, 95, 97, 116, 116, 50, 48, 50, 53,
                    45, 48, 54, 45, 49, 53, 84, 49, 53, 58, 48, 54, 58, 52, 48, 90, 103, 99, 111,
                    109, 109, 101, 110, 116, 163, 100, 110, 97, 109, 101, 100, 80, 104, 105, 108,
                    99, 97, 103, 101, 24, 24, 103, 97, 119, 101, 115, 111, 109, 101, 245, 255,
                ];

                let key: SigningKey<MyStruct> = ciborium::from_reader(cbor.as_slice()).unwrap();
                assert_eq!(
                    key.metadata.comment,
                    Some(MyStruct {
                        name: "Phil".into(),
                        age: 24,
                        awesome: true
                    })
                );
                assert_eq!(
                    key.metadata.expired_at.map(|e| e.as_second()),
                    Some(1750000000)
                );
            }
        }
    }
}
