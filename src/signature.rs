pub(crate) mod builder;

use crate::PublicKey;
use base64ct::Encoding;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Message<T> {
    data: T,

    #[serde(with = "crate::timestamp::required")]
    timestamp: Timestamp,

    #[serde(with = "crate::timestamp::optional")]
    expiration: Option<Timestamp>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[cfg(test)]

mod tests {
    use super::*;

    const PUBLIC_KEY_JSON: &str = r#"{"public_key":"456497ae37ea877e588c768a41d8a506a0b2d02d9b43332495785a30f19a7fd17f78eb9423ce8bc8b026","created_at":"2024-12-23T00:12:54.53753Z","expired_at":null}"#;
    const PUBLIC_KEY2_JSON: &str = r#"{"public_key":"456427254b836a259fd8101e9abb36221085a8e216e88be8b73e89a5202ae1c879e560bfaf3fdfab4998","created_at":"2024-12-23T16:39:25.85933Z","expired_at":null}"#;
    const TIMESTAMP_1: i64 = 1700000000;
    const TIMESTAMP_2: i64 = 1800000000;

    #[derive(Debug, PartialEq, serde::Deserialize)]
    struct Comment {
        name: String,
        cake_eater: bool,
    }

    #[test]
    fn altered_signature() {
        let json = r#"{"signed_artifact":{"data":"toto mange du gateau","timestamp":"2023-11-14T22:13:20Z","expiration":null},"signature":"RWSXrjfqh35YjFYE0S3ovNmiatN3eMHcBTqA+Qjl3P2togZWlNsvMR+V4DpKpEzj4rXecooNquf2GcHoARDKLMhV1+gdX+bWqAg="}"#;
        let signature: Signature<String, ()> = serde_json::from_str(json).unwrap();
        let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

        assert_eq!(
            signature.verify(&pubkey).unwrap_err(),
            SignatureError::Verify {
                source: libsignify::Error::BadSignature
            }
        )
    }

    #[test]
    fn wrong_public_key() {
        let json = r#"{"signed_artifact":{"data":"toto mange du gateau","timestamp":"2023-11-14T22:13:20Z","expiration":null},"signature":"RWSXrjfqh35YjFYE0S3ovNmiatN3eMHcBTqA+Qjl3P2togZWlNsvMR+V4DpKpEzj4rXecooNquf2GcHoARDKLMhV0+gdX+bWqAg="}"#;
        let signature: Signature<String, ()> = serde_json::from_str(json).unwrap();
        let good_pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();
        let wrong_pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY2_JSON).unwrap();

        assert_eq!(
            signature.verify(&wrong_pubkey).unwrap_err(),
            SignatureError::Verify {
                source: libsignify::Error::MismatchedKey {
                    expected: good_pubkey.keynum(),
                    found: wrong_pubkey.keynum()
                }
            }
        );
    }

    mod without_comment_without_expiration {
        use super::*;

        #[test]
        fn json() {
            let json = r#"{"signed_artifact":{"data":"toto mange du gateau","timestamp":"2023-11-14T22:13:20Z","expiration":null},"signature":"RWSXrjfqh35YjFYE0S3ovNmiatN3eMHcBTqA+Qjl3P2togZWlNsvMR+V4DpKpEzj4rXecooNquf2GcHoARDKLMhV0+gdX+bWqAg="}"#;
            let signature: Signature<String, ()> = serde_json::from_str(json).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert!(signature.comment().is_none());
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: None,
                })
            );
        }

        #[test]
        fn cbor() {
            let cbor: [u8; 199] = [
                162, 111, 115, 105, 103, 110, 101, 100, 95, 97, 114, 116, 105, 102, 97, 99, 116,
                163, 100, 100, 97, 116, 97, 116, 116, 111, 116, 111, 32, 109, 97, 110, 103, 101,
                32, 100, 117, 32, 103, 97, 116, 101, 97, 117, 105, 116, 105, 109, 101, 115, 116,
                97, 109, 112, 116, 50, 48, 50, 51, 45, 49, 49, 45, 49, 52, 84, 50, 50, 58, 49, 51,
                58, 50, 48, 90, 106, 101, 120, 112, 105, 114, 97, 116, 105, 111, 110, 246, 105,
                115, 105, 103, 110, 97, 116, 117, 114, 101, 120, 100, 82, 87, 83, 88, 114, 106,
                102, 113, 104, 51, 53, 89, 106, 70, 89, 69, 48, 83, 51, 111, 118, 78, 109, 105, 97,
                116, 78, 51, 101, 77, 72, 99, 66, 84, 113, 65, 43, 81, 106, 108, 51, 80, 50, 116,
                111, 103, 90, 87, 108, 78, 115, 118, 77, 82, 43, 86, 52, 68, 112, 75, 112, 69, 122,
                106, 52, 114, 88, 101, 99, 111, 111, 78, 113, 117, 102, 50, 71, 99, 72, 111, 65,
                82, 68, 75, 76, 77, 104, 86, 48, 43, 103, 100, 88, 43, 98, 87, 113, 65, 103, 61,
            ];
            let signature: Signature<String, Comment> =
                ciborium::from_reader(cbor.as_slice()).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert!(signature.comment().is_none());
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: None,
                })
            );
        }
    }

    mod without_comment_with_expiration {
        use super::*;

        #[test]
        fn json() {
            let json = r#"{"signed_artifact":{"data":"toto mange du gateau","timestamp":"2023-11-14T22:13:20Z","expiration":"2027-01-15T08:00:00Z"},"signature":"RWSXrjfqh35YjEVaXHKe/xHx9lB3zZc6uCqELgnqvHY6eeOB6ixhes/JR0VrYzu7FrBG2mdNtqjZt3I7ET9XoS2KTWtgzAnXWA8="}"#;
            let signature: Signature<String, ()> = serde_json::from_str(json).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert!(signature.comment().is_none());
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: Some(Timestamp::from_second(TIMESTAMP_2).unwrap())
                })
            );
        }

        #[test]
        fn cbor() {
            let cbor: [u8; 219] = [
                162, 111, 115, 105, 103, 110, 101, 100, 95, 97, 114, 116, 105, 102, 97, 99, 116,
                163, 100, 100, 97, 116, 97, 116, 116, 111, 116, 111, 32, 109, 97, 110, 103, 101,
                32, 100, 117, 32, 103, 97, 116, 101, 97, 117, 105, 116, 105, 109, 101, 115, 116,
                97, 109, 112, 116, 50, 48, 50, 51, 45, 49, 49, 45, 49, 52, 84, 50, 50, 58, 49, 51,
                58, 50, 48, 90, 106, 101, 120, 112, 105, 114, 97, 116, 105, 111, 110, 116, 50, 48,
                50, 55, 45, 48, 49, 45, 49, 53, 84, 48, 56, 58, 48, 48, 58, 48, 48, 90, 105, 115,
                105, 103, 110, 97, 116, 117, 114, 101, 120, 100, 82, 87, 83, 88, 114, 106, 102,
                113, 104, 51, 53, 89, 106, 69, 86, 97, 88, 72, 75, 101, 47, 120, 72, 120, 57, 108,
                66, 51, 122, 90, 99, 54, 117, 67, 113, 69, 76, 103, 110, 113, 118, 72, 89, 54, 101,
                101, 79, 66, 54, 105, 120, 104, 101, 115, 47, 74, 82, 48, 86, 114, 89, 122, 117,
                55, 70, 114, 66, 71, 50, 109, 100, 78, 116, 113, 106, 90, 116, 51, 73, 55, 69, 84,
                57, 88, 111, 83, 50, 75, 84, 87, 116, 103, 122, 65, 110, 88, 87, 65, 56, 61,
            ];
            let signature: Signature<String, Comment> =
                ciborium::from_reader(cbor.as_slice()).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert!(signature.comment().is_none());
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: Some(Timestamp::from_second(TIMESTAMP_2).unwrap())
                })
            );
        }
    }

    mod with_comment_with_expiration {
        use super::*;

        #[test]
        fn json() {
            let json = r#"{"signed_artifact":{"data":"toto mange du gateau","timestamp":"2023-11-14T22:13:20Z","expiration":"2027-01-15T08:00:00Z"},"signature":"RWSXrjfqh35YjEVaXHKe/xHx9lB3zZc6uCqELgnqvHY6eeOB6ixhes/JR0VrYzu7FrBG2mdNtqjZt3I7ET9XoS2KTWtgzAnXWA8=","comment":{"name":"Toto","cake_eater":true}}"#;
            let signature: Signature<String, Comment> = serde_json::from_str(json).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert_eq!(
                signature.comment(),
                Some(Comment {
                    name: "Toto".into(),
                    cake_eater: true
                })
                .as_ref()
            );
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: Some(Timestamp::from_second(TIMESTAMP_2).unwrap())
                })
            );
        }

        #[test]
        fn cbor() {
            let cbor: [u8; 250] = [
                163, 111, 115, 105, 103, 110, 101, 100, 95, 97, 114, 116, 105, 102, 97, 99, 116,
                163, 100, 100, 97, 116, 97, 116, 116, 111, 116, 111, 32, 109, 97, 110, 103, 101,
                32, 100, 117, 32, 103, 97, 116, 101, 97, 117, 105, 116, 105, 109, 101, 115, 116,
                97, 109, 112, 116, 50, 48, 50, 51, 45, 49, 49, 45, 49, 52, 84, 50, 50, 58, 49, 51,
                58, 50, 48, 90, 106, 101, 120, 112, 105, 114, 97, 116, 105, 111, 110, 116, 50, 48,
                50, 55, 45, 48, 49, 45, 49, 53, 84, 48, 56, 58, 48, 48, 58, 48, 48, 90, 105, 115,
                105, 103, 110, 97, 116, 117, 114, 101, 120, 100, 82, 87, 83, 88, 114, 106, 102,
                113, 104, 51, 53, 89, 106, 69, 86, 97, 88, 72, 75, 101, 47, 120, 72, 120, 57, 108,
                66, 51, 122, 90, 99, 54, 117, 67, 113, 69, 76, 103, 110, 113, 118, 72, 89, 54, 101,
                101, 79, 66, 54, 105, 120, 104, 101, 115, 47, 74, 82, 48, 86, 114, 89, 122, 117,
                55, 70, 114, 66, 71, 50, 109, 100, 78, 116, 113, 106, 90, 116, 51, 73, 55, 69, 84,
                57, 88, 111, 83, 50, 75, 84, 87, 116, 103, 122, 65, 110, 88, 87, 65, 56, 61, 103,
                99, 111, 109, 109, 101, 110, 116, 162, 100, 110, 97, 109, 101, 100, 84, 111, 116,
                111, 106, 99, 97, 107, 101, 95, 101, 97, 116, 101, 114, 245,
            ];
            let signature: Signature<String, Comment> =
                ciborium::from_reader(cbor.as_slice()).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert_eq!(
                signature.comment(),
                Some(Comment {
                    name: "Toto".into(),
                    cake_eater: true
                })
                .as_ref()
            );
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: Some(Timestamp::from_second(TIMESTAMP_2).unwrap())
                })
            );
        }
    }

    mod with_comment_without_expiration {
        use super::*;

        #[test]
        fn json() {
            let json = r#"{"signed_artifact":{"data":"toto mange du gateau","timestamp":"2023-11-14T22:13:20Z","expiration":null},"signature":"RWSXrjfqh35YjFYE0S3ovNmiatN3eMHcBTqA+Qjl3P2togZWlNsvMR+V4DpKpEzj4rXecooNquf2GcHoARDKLMhV0+gdX+bWqAg=","comment":{"name":"Toto","cake_eater":true}}"#;
            let signature: Signature<String, Comment> = serde_json::from_str(json).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert_eq!(
                signature.comment(),
                Some(Comment {
                    name: "Toto".into(),
                    cake_eater: true
                })
                .as_ref()
            );
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: None,
                })
            );
        }

        #[test]
        fn cbor() {
            let cbor: [u8; 230] = [
                163, 111, 115, 105, 103, 110, 101, 100, 95, 97, 114, 116, 105, 102, 97, 99, 116,
                163, 100, 100, 97, 116, 97, 116, 116, 111, 116, 111, 32, 109, 97, 110, 103, 101,
                32, 100, 117, 32, 103, 97, 116, 101, 97, 117, 105, 116, 105, 109, 101, 115, 116,
                97, 109, 112, 116, 50, 48, 50, 51, 45, 49, 49, 45, 49, 52, 84, 50, 50, 58, 49, 51,
                58, 50, 48, 90, 106, 101, 120, 112, 105, 114, 97, 116, 105, 111, 110, 246, 105,
                115, 105, 103, 110, 97, 116, 117, 114, 101, 120, 100, 82, 87, 83, 88, 114, 106,
                102, 113, 104, 51, 53, 89, 106, 70, 89, 69, 48, 83, 51, 111, 118, 78, 109, 105, 97,
                116, 78, 51, 101, 77, 72, 99, 66, 84, 113, 65, 43, 81, 106, 108, 51, 80, 50, 116,
                111, 103, 90, 87, 108, 78, 115, 118, 77, 82, 43, 86, 52, 68, 112, 75, 112, 69, 122,
                106, 52, 114, 88, 101, 99, 111, 111, 78, 113, 117, 102, 50, 71, 99, 72, 111, 65,
                82, 68, 75, 76, 77, 104, 86, 48, 43, 103, 100, 88, 43, 98, 87, 113, 65, 103, 61,
                103, 99, 111, 109, 109, 101, 110, 116, 162, 100, 110, 97, 109, 101, 100, 84, 111,
                116, 111, 106, 99, 97, 107, 101, 95, 101, 97, 116, 101, 114, 245,
            ];
            let signature: Signature<String, Comment> =
                ciborium::from_reader(cbor.as_slice()).unwrap();
            let pubkey: PublicKey<()> = serde_json::from_str(PUBLIC_KEY_JSON).unwrap();

            assert_eq!(
                signature.comment(),
                Some(Comment {
                    name: "Toto".into(),
                    cake_eater: true
                })
                .as_ref()
            );
            assert_eq!(
                signature.verify(&pubkey),
                Ok(Message {
                    data: "toto mange du gateau".into(),
                    timestamp: Timestamp::from_second(TIMESTAMP_1).unwrap(),
                    expiration: None,
                })
            );
        }
    }
}
