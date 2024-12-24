//! Run this example with the following command in a terminal:
//!
//! ```console
//! $ cargo run --example from_signing_key_to_public_key
//! ```

use signify_serde::{PublicKey, SigningKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Let's say we have an existing signing key somewhere
    let json = r#"{"secret_key":"4564424b00000000d2252a412cd1cd2334ecd053275fba5a3dc9e6afbf7996ea5979bf1c7cf1403aab59795c4502b51a422ae1de66e8a16424297cc6f29c4127d3e17f6e33d1bd50618a7a196b421db1182bb3d46d756cbfab54e254b7307e6cca5ad82c674e711b","created_at":"2024-12-24T15:02:48.845298Z","expired_at":null,"comment":"testing key, do not use"}"#;

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
