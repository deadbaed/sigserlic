//! Run this example with the following command in a terminal:
//!
//! ```console
//! $ cargo run --example from_signing_key_to_public_key
//! ```

use sigserlic::{PublicKey, SigningKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Let's say we have an existing signing key somewhere
    let json = r#"{"secret_key":"RWRCSwAAAADSJSpBLNHNIzTs0FMnX7paPcnmr795lupZeb8cfPFAOqtZeVxFArUaQirh3mbooWQkKXzG8pxBJ9Phf24z0b1QYYp6GWtCHbEYK7PUbXVsv6tU4lS3MH5sylrYLGdOcRs=","created_at":"2024-12-24T15:02:48.845298Z","expired_at":null,"comment":"testing key, do not use"}"#;

    // We can import it as a signing key
    // We know the type of the comment is a string, we specify it
    let key: SigningKey<&str> =
        serde_json::from_str(json).expect("SigningKey deserialized from json");

    // Consume private part of the key, keep the public part
    let public = PublicKey::from(key);

    // Let's export the public key!
    let json = serde_json::to_string(&public).expect("PublicKey serialized to json");
    println!("{json}");

    Ok(())
}
