//! Run this example with the following command in a terminal:
//!
//! ```console
//! $ cargo run --example import_public_key
//! ```
//!
//! This example will read a public key in json on stdin.
//! If you do not have one, get one and pipe to this example:
//! ```console
//! $ cargo run --example from_signing_key_to_public_key | cargo run --example import_public_key
//! ```

use sigserlic::{KeyMetadata, PublicKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read json from stdin
    let mut json = String::new();
    std::io::stdin().read_line(&mut json)?;

    // NOTE: The type of the comment must be the same or compatible with the input type
    // Deserialization will fail otherwise
    let public_key: PublicKey<serde_json::Value> =
        serde_json::from_str(&json).expect("Deserialize PublicKey from json");

    // Get timestamp when key was created.
    let timestamp = public_key.created_at();
    let timestamp = jiff::Timestamp::from_second(timestamp).expect("Timestamp of key creation");

    // Pretty print key number
    let keynum = {
        use base64ct::Encoding;
        base64ct::Base64::encode_string(public_key.keynum().as_ref())
    };

    // Display key information
    println!("Key `{keynum}` was created on {timestamp}");

    Ok(())
}
