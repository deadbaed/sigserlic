//! Run this example with the following command in a terminal:
//!
//! ```console
//! $ cargo run --example sign_message
//! ```

use sigserlic::{SignatureBuilder, SigningKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Import signing key
    let signing_key = r#"{"secret_key":"4564424b00000000d2252a412cd1cd2334ecd053275fba5a3dc9e6afbf7996ea5979bf1c7cf1403aab59795c4502b51a422ae1de66e8a16424297cc6f29c4127d3e17f6e33d1bd50618a7a196b421db1182bb3d46d756cbfab54e254b7307e6cca5ad82c674e711b","created_at":"2024-12-24T15:02:48.845298Z","expired_at":null,"comment":"testing key, do not use"}"#;
    let signing_key: SigningKey<&str> =
        serde_json::from_str(signing_key).expect("SigningKey deserialized from json");

    // Optional: you can put comments alongside the signature, although **it will not be signed**.
    type Comment = String;
    let comment: Comment = "don't trust me, but the cake is awesome!".into();

    // Type of message must implement *both* `Serialize` and `Deserialize`, comment is optional
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Message {
        name: String,
        action: String,
        age: u8,
        awesome: bool,
    }
    type MyMessage = Message;

    // Create message to sign
    let message = Message {
        name: "Toto".into(),
        action: "eat cake".into(),
        age: 42,
        awesome: true,
    };

    // You need to specify which types you are going to construct
    type MySignatureBuilder = SignatureBuilder<MyMessage, Comment>;

    // Now let's prepare the signature
    let builder = MySignatureBuilder::new(message);
    // We can add a comment but it will not be cryptographically signed
    let builder = builder.comment(comment);

    // Optional: Manually specify when signature starts to be valid
    // If not set, moment of signature will be used
    // It will have no effect, but it can be programatically used
    let builder = builder
        .timestamp(1740000000)
        .expect("Signature with starting timestamp");
    // Comment the previous statement to use current timestamp when signing message.

    // Optional: Set an expiration date for the signature
    // It will have no effect, but it can be programatically used
    let builder = builder
        .expiration(1750000000)
        .expect("Signature with expiration timestamp");
    // Comment the previous statement to make the signature never expire.

    // Sign the message using the signing key!
    let signature = signing_key.sign(builder).expect("Signed message");

    // Let's display the signed message!
    let json = serde_json::to_string(&signature).expect("Signature serialized to json");
    println!("{json}");

    Ok(())
}
