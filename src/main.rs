use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKey<Comment> {
    #[serde(with = "signify_serde")]
    secret_key: libsignify::PrivateKey,
    comment: Option<Comment>,
    created_at: Timestamp,
    expired_at: Option<Timestamp>,
}

// TODO: same struct but for public key: generic over impl Codable?

mod signify_serde {
    use libsignify::{Codeable, PrivateKey};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.as_bytes();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        PrivateKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl<Comment: std::fmt::Debug> std::fmt::Debug for SigningKey<Comment> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("id", &self.secret_key.public().keynum())
            .field("secret_key", &"<secret>")
            .field("comment", &self.comment)
            .field("created_at", &self.created_at)
            .field("expired_at", &self.expired_at)
            .finish()
    }
}

impl<Comment> SigningKey<Comment> {
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng {};
        let secret_key =
            libsignify::PrivateKey::generate(&mut rng, libsignify::NewKeyOpts::NoEncryption)
                .expect("private key without encryption");

        Self {
            secret_key,
            comment: None,
            created_at: Timestamp::now(),
            expired_at: None,
        }
    }
    pub fn with_comment(self, comment: Comment) -> Self {
        Self {
            comment: Some(comment),
            ..self
        }
    }

    pub fn sign<M: AsRef<[u8]>>(&self, message: M, comment: impl AsRef<str>) -> String {
        use libsignify::Codeable;

        // TODO: just use codable everywhere

        let signature = self.secret_key.sign(message.as_ref());
        let bytes = signature.to_file_encoding(comment.as_ref());
        String::from_utf8(bytes).expect("base64 encoding")
    }

    // TODO: trait "Signing" and "Verifying" ? -> NO just use Codable
    pub fn verify(&self) {
        // self.secret_key.public.verify()
    }

}

#[derive(Serialize, Deserialize, Debug)]
struct MyComment {
    name: String,
    age: u8,
}

fn main() {
    // let gen = SigningKey::generate().with_comment("toto mange du gateau");
    // let gen = SigningKey::generate().with_comment(MyComment {
    //     name: "Phil".into(),
    //     age: 24,
    // });
    // let json = serde_json::to_string(&gen).unwrap();
    // println!("{json}");

    // let gen = r#"{"secret_key":[69,100,66,75,0,0,0,0,105,201,194,244,251,62,153,176,92,59,183,247,172,248,179,36,155,247,135,20,234,184,33,176,163,149,107,85,134,139,219,139,240,1,204,4,162,102,160,160,158,143,19,229,6,97,179,186,122,27,210,145,126,142,179,215,113,189,199,202,15,247,138,21,104,1,197,3,216,62,128,164,73,219,136,94,138,111,36,31,104,9,117,147,52,231,255,213,19,205,249,6,74,61,120,139],"comment":"toto mange du gateau","created_at":"2024-12-09T22:33:36.688418Z","expired_at":null}"#;
    // let sec: SigningKey<String> = serde_json::from_str(gen).unwrap();
    //
    let gen = r#"{"secret_key":[69,100,66,75,0,0,0,0,193,1,162,183,109,65,98,188,97,139,235,93,140,98,53,186,202,208,113,42,161,178,179,7,87,221,143,102,135,87,13,140,136,244,70,2,30,91,191,198,243,109,75,71,9,217,137,44,96,189,164,188,176,38,169,89,84,15,82,98,46,230,103,70,170,0,244,181,175,11,120,68,34,26,63,143,221,132,62,90,240,243,85,224,249,49,155,248,244,227,30,149,128,105,180,153],"comment":{"name":"Phil","age":24},"created_at":"2024-12-09T22:43:19.808324Z","expired_at":null}"#;
    let sec: SigningKey<MyComment> = serde_json::from_str(gen).unwrap();

    println!("{:?}", sec);

    let message = "toto mange du gateau";
    let comment = "gateau au chocolat";
    let signature = sec.sign(message, comment);
    println!("`````\n{signature}\n``````");
}
