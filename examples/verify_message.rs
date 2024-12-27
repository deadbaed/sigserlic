//! Run this example with the following command in a terminal:
//!
//! ```console
//! $ cargo run --example verify_message
//! ```

use sigserlic::{PublicKey, Signature};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Receive a signature, compare
    let signature = r#"{"signed_artifact":{"data":{"name":"Toto","action":"eat cake","age":42,"awesome":true},"timestamp":"2024-12-24T16:20:43.44666Z","expiration":null},"signature":"RWRZeb8cfPFAOgRE7OeT1PjkIz5tio+AIq2aw9IPlg3Zwcdnomp9OSHpFq7JUF86e4AiFjpRCjolDkNwHCxb3RvJWLk15USiowg=","comment":"don't trust me, but the cake is awful!"}"#;

    // You need to specify which types you are expecting
    type Comment = String;

    // Message must implement `Deserialize` at least
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Message {
        name: String,
        action: String,
        age: u8,
        awesome: bool,
    }
    type MyMessage = Message;
    type MySignature = Signature<MyMessage, Comment>;

    // Deserialize signature
    let signature: MySignature =
        serde_json::from_str(signature).expect("Message deserialized from json");

    // We can inspect the untrusted comment
    let comment = signature.comment();
    println!(
        "Is there a comment on this signature: {}",
        comment.is_some()
    );

    // Which public key is expected to verify the message
    let keynum = {
        let signature = signature.signature().expect("Valid signature");

        use base64ct::Encoding;
        base64ct::Base64::encode_string(signature.signer_keynum().as_ref())
    };
    println!("Key `{keynum} has been used to sign this message");

    // Import public key
    let public_key: PublicKey<String> = serde_json::from_str(r#"{"public_key":"45645979bf1c7cf1403a618a7a196b421db1182bb3d46d756cbfab54e254b7307e6cca5ad82c674e711b","created_at":"2024-12-24T15:02:48.845298Z","expired_at":null,"comment":"testing key, do not use"}"#).expect("Deserialize public key");

    // Use public key to verify signature
    let original_message = signature.verify(&public_key).expect("Valid message");
    println!(
        "This message was signed on `{}` and should be valid until {}",
        original_message.timestamp(),
        original_message
            .expiration()
            .map(|e| e.to_string())
            .unwrap_or("the end of time".into())
    );

    // Now we can finally extract the original data we wanted to sign at the beggining
    let original_data = original_message.data();
    assert!(original_data.awesome);
    println!("YEAH cake is awesome!");

    Ok(())
}
