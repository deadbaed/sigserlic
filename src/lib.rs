#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))] // https://stackoverflow.com/a/61417700/4809297

/*!

The **sig**nify **ser**de **lic**ense system.

Rust library to combine [serde](https://serde.rs) with [libsignify](https://docs.rs/libsignify). Based on [openbsd signify](https://man.openbsd.org/signify).

# Quickstart

## Generate or import a key

```
use sigserlic::SigningKey;

// Generate
type Comment = (); // This key will not have a comment
let key = SigningKey::<Comment>::generate();

// Import an existing key (here encoded in json)
let json = r#"{
  "secret_key": "RWRCSwAAAADSJSpBLNHNIzTs0FMnX7paPcnmr795lupZeb8cfPFAOqtZeVxFArUaQirh3mbooWQkKXzG8pxBJ9Phf24z0b1QYYp6GWtCHbEYK7PUbXVsv6tU4lS3MH5sylrYLGdOcRs=",
  "created_at": "2024-12-24T15:02:48.845298Z",
  "expired_at": null,
  "comment": "testing key, do not use"
}"#;
let key: SigningKey<String> = serde_json::from_str(json).unwrap();
```

## Extract public key from signing key

```
# let json = r#"{
#   "secret_key": "RWRCSwAAAADSJSpBLNHNIzTs0FMnX7paPcnmr795lupZeb8cfPFAOqtZeVxFArUaQirh3mbooWQkKXzG8pxBJ9Phf24z0b1QYYp6GWtCHbEYK7PUbXVsv6tU4lS3MH5sylrYLGdOcRs=",
#   "created_at": "2024-12-24T15:02:48.845298Z",
#   "expired_at": null,
#   "comment": "testing key, do not use"
# }"#;
# let key: sigserlic::SigningKey<String> = serde_json::from_str(json).unwrap();
use sigserlic::PublicKey;
let public_key = PublicKey::from(key);

assert_eq!(serde_json::to_string_pretty(&public_key).unwrap(), r#"{
  "public_key": "RWRZeb8cfPFAOmGKehlrQh2xGCuz1G11bL+rVOJUtzB+bMpa2CxnTnEb",
  "created_at": "2024-12-24T15:02:48.845298Z",
  "expired_at": null,
  "comment": "testing key, do not use"
}"#);

```

## Sign data, create a signature

```
# let json = r#"{
#   "secret_key": "RWRCSwAAAADSJSpBLNHNIzTs0FMnX7paPcnmr795lupZeb8cfPFAOqtZeVxFArUaQirh3mbooWQkKXzG8pxBJ9Phf24z0b1QYYp6GWtCHbEYK7PUbXVsv6tU4lS3MH5sylrYLGdOcRs=",
#   "created_at": "2024-12-24T15:02:48.845298Z",
#   "expired_at": null,
#   "comment": "testing key, do not use"
# }"#;
# let key: sigserlic::SigningKey<String> = serde_json::from_str(json).unwrap();
#[derive(serde::Serialize, serde::Deserialize)]
struct MyMessage {
    string: String,
    bytes: Vec<u8>,
    int: i32,
    boolean: bool,
}
let message = MyMessage {
    string: "Toto mange du gateau".into(),
    bytes: vec![0xde, 0xad, 0xba, 0xed],
    int: -1,
    boolean: true,
};

type Comment = String;
let comment: Comment = "anybody can change me :)".into();

// Prepare data to be signed
type MySignatureBuilder = sigserlic::SignatureBuilder<MyMessage, Comment>;
let builder = MySignatureBuilder::new(message).comment(comment);

// You can set the timestamp and the expiration if you want
let builder = builder.timestamp(1735311570).unwrap();
let builder = builder.expiration(1735397970).unwrap();

// Let's sign our message!
let signature = key.sign(builder).unwrap();
assert_eq!(serde_json::to_string_pretty(&signature).unwrap(), r#"{
  "signed_artifact": {
    "data": {
      "string": "Toto mange du gateau",
      "bytes": [
        222,
        173,
        186,
        237
      ],
      "int": -1,
      "boolean": true
    },
    "timestamp": "2024-12-27T14:59:30Z",
    "expiration": "2024-12-28T14:59:30Z"
  },
  "signature": "RWRZeb8cfPFAOouGiUofEwLJ20MoKD3jG7FpIsNYFMlATrJL/Pdk0Muag+QMa2CLLecQV1Ycho6Ui3QjicTyxTcF68oDAIrnlQo=",
  "comment": "anybody can change me :)"
}"#);

```

## Verify data, get original data

```
// Define what are the used types in this signature
# #[derive(serde::Serialize, serde::Deserialize)]
# struct MyMessage {
#     string: String,
#     bytes: Vec<u8>,
#     int: i32,
#     boolean: bool,
# }
# type Comment = String;
# let json = r#"{
#   "signed_artifact": {
#     "data": {
#       "string": "Toto mange du gateau",
#       "bytes": [
#         222,
#         173,
#         186,
#         237
#       ],
#       "int": -1,
#       "boolean": true
#     },
#     "timestamp": "2024-12-27T14:59:30Z",
#     "expiration": "2024-12-28T14:59:30Z"
#   },
#   "signature": "RWRZeb8cfPFAOouGiUofEwLJ20MoKD3jG7FpIsNYFMlATrJL/Pdk0Muag+QMa2CLLecQV1Ycho6Ui3QjicTyxTcF68oDAIrnlQo=",
#   "comment": "anybody can change me :)"
# }"#;
type MySignature = sigserlic::Signature<MyMessage, Comment>;
let signature: MySignature = serde_json::from_str(json).unwrap();
# let public_key: sigserlic::PublicKey<String> = serde_json::from_str(r#"{
    "public_key": "RWRZeb8cfPFAOmGKehlrQh2xGCuz1G11bL+rVOJUtzB+bMpa2CxnTnEb",
#   "created_at": "2024-12-24T15:02:48.845298Z",
#   "expired_at": null,
#   "comment": "testing key, do not use"
# }"#).unwrap();

// Let's verify the signature with our public key, and get the signed message!
let message = signature.verify(&public_key).unwrap();

// Now we can finally get the original data
let data: &MyMessage = message.data();
assert_eq!(data.string, "Toto mange du gateau");

```
*/

mod key;
mod metadata;
mod public_key;
mod signature;
mod signing_key;
mod timestamp;

pub use key::{KeyMetadata, KeyUsage};
pub(crate) use metadata::Metadata;
pub use public_key::PublicKey;
pub use signature::builder::SignatureBuilder;
pub use signature::{Message, Signature};
pub use signing_key::SigningKey;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

/// Error which can occur when using the crate
pub mod error {
    pub use crate::signature::SignatureError;
    pub use crate::signature::builder::SignatureBuilderError;
    pub use crate::timestamp::TimestampError;
}
