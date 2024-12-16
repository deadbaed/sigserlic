use serde::{Deserialize, Serialize};
use signify_serde::*;

#[derive(Serialize, Deserialize, Debug)]
struct MyData {
    name: String,
    action: String,
    age: u8,
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct MyComment {
    uuid: String,
    user: String,
    signature: String,
}

fn main() {
    // let gen: SigningKey<()> = SigningKey::generate();
    let expiration = jiff::civil::datetime(2025, 2, 15, 22, 23, 42, 0)
        .intz("Europe/Paris")
        .unwrap();
    // let gen = gen.set_expiration(expiration.timestamp());

    let gen = SigningKey::generate()
        .with_comment(MyData {
            name: "Phil".into(),
            action: "mange du gateau".into(),
            age: 24,
            bytes: vec![1, 2, 3, 4, 5],
        })
        .set_expiration(expiration.timestamp());
    println!("generated key {:?}", gen);

    // cbor
    let mut key = Vec::new();
    ciborium::into_writer(&gen, &mut key).unwrap();
    println!("{:?}", key);

    let json = serde_json::to_string(&gen).unwrap();
    println!("{json}");
    // let messagepack = rmp_serde::to_vec(&gen).unwrap();
    // let toml = toml::to_string(&gen).unwrap();
    // println!("{}", toml);
    // let bson = bson::to_bson(&gen).unwrap();
    // println!("{}", bson);
    // let yaml = serde_yaml::to_string(&gen).unwrap();
    // println!("{}", yaml);

    // let gen = SigningKey::generate().with_comment("toto mange du gateau");
    // let json = serde_json::to_string(&gen).unwrap();
    // println!("{json}");

    let sec: SigningKey<MyData> = serde_json::from_str(&json).unwrap();
    // let sec: SigningKey<String> = bson::from_bson(bson).unwrap();
    // let sec: SigningKey<String> = toml::from_str(&toml).unwrap();
    // let sec : SigningKey<&str> = serde_yaml::from_str(&yaml).unwrap();
    // let sec: SigningKey<MyData> = ciborium::from_reader(key.as_slice()).unwrap();
    // let sec: SigningKey<MyData> = rmp_serde::from_slice(&messagepack).unwrap();

    println!("signing key {:?}", sec);

    let to_sign = SignatureBuilder::new(MyData {
        name: "toto".into(),
        action: "mange du gateau".into(),
        age: 43,
        bytes: vec![1, 2, 3, 4, 5],
    })
    // let to_sign = SignatureBuilder::new(String::from("toto mange du gateau"))
    // let to_sign: SignatureBuilder<_, ()> = SignatureBuilder::new(123)
    .timestamp(jiff::Timestamp::now())
    // .expiration(expiration.timestamp())
        // .comment(456);
        // .comment("coucou");
    .comment(MyComment {
        uuid: "uuuuuuiiiiiddd".into(),
        user: "toto".into(),
        signature: "sssss".into(),
    });
    let signature = to_sign.sign(&sec).expect("failed to sign");
    println!("signed signature struct {:?}", signature);

    // let mut sig= Vec::new();
    // ciborium::into_writer(&signature, &mut sig).unwrap();
    // println!("signature {:?}", sig);

    let sig = serde_json::to_string(&signature).unwrap();
    // let sig = serde_yaml::to_string(&signature).unwrap();
    // let sig = toml::to_string(&signature).unwrap();
    // let sig = bson::to_bson(&signature).unwrap();
    println!("{}", sig);

    // let sig = rmp_serde::to_vec(&signature).unwrap();
    // println!("{:?}", sig);

    // let mut buffer = Vec::new();
    // let signature: Signature<MyData, MyComment> = ciborium::from_reader(sig.as_slice()).unwrap();

    let signature: Signature<MyData, MyComment> = serde_json::from_str(&sig).unwrap();
    // let signature: Signature<MyData, MyComment> = rmp_serde::from_slice(&sig).unwrap();
    // let signature: Signature<MyData, MyComment> = serde_yaml::from_str(&sig).unwrap();
    // let signature: Signature<MyData, MyComment> = toml::from_str(&sig).unwrap();
    // let signature: Signature<MyData, MyComment> = bson::from_bson(sig).unwrap();

    println!("signature {:?}", signature);
    println!("comment on signature {:?}", signature.comment());

    let public_key = PublicKey::from(sec);
    // println!("pub key keynum {:?}", public_key.keynum());

    let message = signature
        .verify(&public_key)
        .expect("failed to verify signature with public key");

    // let mut msg = Vec::new();
    // ciborium::into_writer(&message, &mut msg).unwrap();
    // println!("message {:?}", msg);

    // let message_yaml = serde_yaml::to_string(&message).unwrap();
    // println!("{message_yaml}");
    //
    // let message_toml = toml::to_string(&message).unwrap();
    // println!("{message_toml}");
    //
    // let message_bson = bson::to_bson(&message).unwrap();
    // println!("{message_bson}");
    //
    let message_json = serde_json::to_string(&message).unwrap();
    println!("{message_json}");

    // let message_messagepack = rmp_serde::to_vec(&message).unwrap();
    // println!("message {:?}", message_messagepack);

    // let message: Message<MyData> = ciborium::from_reader(msg.as_slice()).unwrap();
    let message: Message<MyData> = serde_json::from_str(&message_json).unwrap();
    println!("{:?}", message);
}
