use signify_test::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct MyData {
    name: String,
    action: String,
    age: u8,
}

#[derive(Serialize, Deserialize, Debug)]
struct MyComment {
    uuid: String,
    user: String,
    signature: String,
}

fn main() {
    let gen: SigningKey<()> = SigningKey::generate();
    let expiration = jiff::civil::datetime(2025, 2, 15, 22, 23, 42, 0)
        .intz("Europe/Paris")
        .unwrap();
    let gen = gen.set_expiration(expiration.timestamp());
    let json = serde_json::to_string(&gen).unwrap();
    println!("{json}");

    let gen = SigningKey::generate().with_comment(MyData {
        name: "Phil".into(),
        action: "mange du gateau".into(),
        age: 24,
    });
    let json = serde_json::to_string(&gen).unwrap();
    println!("{json}");

    let gen = SigningKey::generate().with_comment("toto mange du gateau");
    let json = serde_json::to_string(&gen).unwrap();
    println!("{json}");

    let sec: SigningKey<&str> = serde_json::from_str(&json).unwrap();

    let to_sign = SignatureBuilder::new(MyData {
        name: "toto".into(),
        action: "mange du gateau".into(),
        age: 43,
    })
    .timestamp(jiff::Timestamp::now())
    .expiration(expiration.timestamp())
    .comment(MyComment {
        uuid: "uuuuuuiiiiiddd".into(),
        user: "toto".into(),
        signature: "sssss".into(),
    });
    let signature = to_sign.sign(&sec).expect("failed to sign");
    let signature_json = serde_json::to_string(&signature).unwrap();
    println!("{signature_json}");

    let signature: Signature<MyData, MyComment> = serde_json::from_str(&signature_json).unwrap();

    let comment = signature.comment();
    println!("comment on signature {:?}", comment);

    let sig = signature.signature().expect("failed to parse signature");
    println!("signing key used {:?}", sig.signer_keynum());

    let public_key = PublicKey::from(sec);
    println!("pub key keynum {:?}", public_key.keynum());

    let message = signature.verify(&public_key).expect("failed to verify signature with public key");
    let message_json = serde_json::to_string(&message).unwrap();
    println!("{message_json}");
}
