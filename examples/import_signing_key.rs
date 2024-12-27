//! Run this example with the following command in a terminal:
//!
//! ```console
//! $ cargo run --example import_signing_key
//! ```
//!
//! This example will read a private key in json on stdin.
//! If you do not have one, generate one and pipe to this example:
//! ```console
//! $ cargo run --example generate_key_json --features="generate" "testing signing keys" | cargo run --example import_signing_key
//! ```

use sigserlic::SigningKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read json from stdin
    let mut json = String::new();
    std::io::stdin().read_line(&mut json)?;

    // NOTE: The type of the comment must be the same or compatible with the input type
    // Deserialization will fail otherwise
    let signing_key: SigningKey<serde_json::Value> =
        serde_json::from_str(&json).expect("Deserialize SigningKey from json");

    // Get timestamp when key was created.
    let timestamp = signing_key.created_at();
    let timestamp = jiff::Timestamp::from_second(timestamp).expect("Timestamp of key creation");

    // Pretty print key number
    let keynum = {
        use base64ct::Encoding;
        base64ct::Base64::encode_string(signing_key.keynum().as_ref())
    };

    // Display key information
    println!("Key `{keynum}` was created on {timestamp}");

    Ok(())
}
