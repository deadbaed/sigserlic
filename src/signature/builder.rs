use crate::error::TimestampError;
use crate::{Message, Signature, SigningKey};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

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
        let timestamp = crate::timestamp::parse_timestamp(timestamp)?;
        self.timestamp = Some(timestamp);
        Ok(self)
    }

    /// If set, this timestamp **will be** signed with the message.
    pub fn expiration(mut self, timestamp: i64) -> Result<Self, TimestampError> {
        let timestamp = crate::timestamp::parse_timestamp(timestamp)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_KEY_JSON: &str = r#"{"secret_key":"4564424b00000000fb39dd26b3daa32bba433e2d7ed3ba61906dccfb6bbfb4ff97ae37ea877e588cdb275863f814f5e2639d808bdf56dc0d142abb7ae6267d6d88489c0671eb70f8768a41d8a506a0b2d02d9b43332495785a30f19a7fd17f78eb9423ce8bc8b026","created_at":"2024-12-23T00:12:54.53753Z","expired_at":null}"#;

    const TIMESTAMP_1: i64 = 1700000000;
    const TIMESTAMP_2: i64 = 1800000000;

    const NOTHING: () = ();
    const PRIMITIVE_STR: &str = "toto mange du gateau";
    const PRIMITIVE_BYTES: [u8; 5] = [1, 2, 3, 4, 5];
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct MyStruct {
        name: &'static str,
        age: u8,
        awesome: bool,
    }
    const STRUCT: MyStruct = MyStruct {
        name: "Phil",
        age: 24,
        awesome: true,
    };
    type SignatureBuilderNothing = SignatureBuilder<(), ()>;

    #[test]
    fn default() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilderNothing::new(NOTHING);

        let signature = builder.sign(&signing_key).unwrap();
        assert!(signature.comment().is_none());
    }

    #[test]
    fn timestamp() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilderNothing::new(NOTHING);

        let builder = builder.timestamp(TIMESTAMP_1).unwrap();

        let signature = builder.sign(&signing_key).unwrap();
        assert_eq!(
            signature.signed_artifact.timestamp,
            Timestamp::from_second(TIMESTAMP_1).unwrap()
        );
    }

    #[test]
    fn expiration() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilderNothing::new(NOTHING);

        let builder = builder.expiration(TIMESTAMP_2).unwrap();

        let signature = builder.sign(&signing_key).unwrap();
        assert_eq!(
            signature.signed_artifact.expiration,
            Some(Timestamp::from_second(TIMESTAMP_2).unwrap())
        );
    }

    #[test]
    fn timestamp_and_expiration() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilderNothing::new(NOTHING);

        let builder = builder
            .timestamp(TIMESTAMP_1)
            .unwrap()
            .expiration(TIMESTAMP_2)
            .unwrap();

        let signature = builder.sign(&signing_key).unwrap();
        assert_eq!(
            signature.signed_artifact.timestamp,
            Timestamp::from_second(TIMESTAMP_1).unwrap()
        );
        assert_eq!(
            signature.signed_artifact.expiration,
            Some(Timestamp::from_second(TIMESTAMP_2).unwrap())
        );
    }

    #[test]
    fn expiration_before_timestamp() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilderNothing::new(NOTHING);

        let builder = builder
            .expiration(TIMESTAMP_1)
            .unwrap()
            .timestamp(TIMESTAMP_2)
            .unwrap();

        let signature = builder.sign(&signing_key).unwrap_err();
        assert_eq!(
            signature,
            SignatureBuilderError::PastExpiration {
                expiration: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                timestamp: Timestamp::from_second(TIMESTAMP_2).unwrap()
            },
        );
    }

    #[test]
    fn message_primitive_no_comment() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilder::<&str, ()>::new(PRIMITIVE_STR);

        let signature = builder.sign(&signing_key).unwrap();
        assert!(signature.comment().is_none());
        assert_eq!(signature.signed_artifact.data, "toto mange du gateau");
    }

    #[test]
    fn message_primitive_comment_primitive() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilder::new(PRIMITIVE_BYTES).comment(PRIMITIVE_STR);

        let signature = builder.sign(&signing_key).unwrap();
        assert_eq!(signature.comment(), Some("toto mange du gateau").as_ref());
        assert_eq!(signature.signed_artifact.data, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn message_primitive_comment_struct() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilder::new(PRIMITIVE_BYTES).comment(STRUCT);

        let signature = builder.sign(&signing_key).unwrap();
        assert_eq!(
            signature.comment(),
            Some(MyStruct {
                name: "Phil",
                age: 24,
                awesome: true
            })
            .as_ref()
        );
        assert_eq!(signature.signed_artifact.data, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn message_struct_comment_primitive() {
        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilder::new(STRUCT).comment(PRIMITIVE_BYTES);

        let signature = builder.sign(&signing_key).unwrap();
        assert_eq!(signature.comment(), Some([1, 2, 3, 4, 5]).as_ref());
        assert_eq!(
            signature.signed_artifact.data,
            MyStruct {
                name: "Phil",
                age: 24,
                awesome: true
            }
        );
    }

    #[test]
    fn message_struct_comment_struct() {
        #[derive(Debug, PartialEq)]
        struct Comment {
            name: &'static str,
            action: &'static str,
        }

        let signing_key: SigningKey<()> = serde_json::from_str(SIGNING_KEY_JSON).unwrap();
        let builder = SignatureBuilder::new(STRUCT).comment(Comment {
            name: "toto",
            action: "mange du gateau",
        });

        let signature = builder.sign(&signing_key).unwrap();
        assert_eq!(
            signature.comment(),
            Some(Comment {
                name: "toto",
                action: "mange du gateau",
            })
            .as_ref()
        );
        assert_eq!(
            signature.signed_artifact.data,
            MyStruct {
                name: "Phil",
                age: 24,
                awesome: true
            }
        );
    }
}
