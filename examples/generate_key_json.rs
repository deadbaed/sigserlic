//! Run this example with the following command in a terminal:
//!
//! ```console
//! $ cargo run --example generate_key_json --features="generate" -- "testing key"
//! ```

use signify_serde::SigningKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate signing key
    let key = SigningKey::generate();

    // Get cli argument, use first argument as comment
    let args: Vec<String> = std::env::args().collect();
    let key = if let Some(comment) = args.get(1) {
        key.with_comment(comment)
    } else {
        key
    };

    // Once key is generated, you can use it right awway, and serialize it anyhwere (json in this example)
    let json = serde_json::to_string(&key).expect("SigningKey serialized in json");
    println!("{json}");

    Ok(())
}
