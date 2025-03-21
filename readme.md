# sigserlic

![CI status](https://github.com/deadbaed/sigserlic/actions/workflows/ci.yml/badge.svg)
[![crates.io version](https://img.shields.io/crates/v/sigserlic)](https://crates.io/crates/sigserlic)
[![docs.rs](https://img.shields.io/docsrs/sigserlic)](https://docs.rs/sigserlic)

The **sig**nify **ser**de **lic**ense system.

Rust library to combine [serde](https://serde.rs) with [libsignify](https://docs.rs/libsignify). Based on [openbsd signify](https://man.openbsd.org/signify).

## History

My goal is to have some kind of licensing system for a project I am working on.

I was always wondering how a licensing sytem was working, and from time to time I was reading [some](https://matradomski.com/posts/local_license_key_verification_theory/) [articles](https://keygen.sh/blog/how-to-generate-license-keys/) on the subject, but I never had the time and need to implement that, until now!

Having the prior experience of coding an auth service with JWTs I tried [pasetors](https://docs.rs/pasetors/), a Rust implementation of [paseto](https://paseto.io). It worked pretty well and I liked the format, but paseto is for signing short-lived access tokens, and I am not doing that. (in retrospect paseto can be used for long-lived tokens, and I could have used paseto for this licensing system)

I got a link (thanks Lara!) to [this excellent blog post](https://soatok.blog/2024/11/15/what-to-use-instead-of-pgp/), it is a great read! It gave me some ideas for my licensing system.

I originally wanted to use [minisign](https://jedisct1.github.io/minisign/), but the Rust implementations did not suit me, even though I prefer minisign over signify.

After learning that minisign was compatible at some point with signify, I read [the paper introducing signify](https://www.openbsd.org/papers/bsdcan-signify.html), discovered the [portable version of openbsd's signify](https://github.com/aperezdc/signify), and finally landed on [libsignify](https://docs.rs/libsignify)!

## Why combining serde with signify?

My only problem with signify is that it is too basic: you can only sign/verify files and that's it (which is actually good, less is more).

I want to sign some data programatically, and also access that data programatically, not just whole files.

Also, I am not a huge fan of have the signature and the signed data in two different places, why not combine them in a single place?

## Features

- Generate signing keys, extract public key from signing key
- Sign anything implementing [Serialize](https://serde.rs/impl-serialize.html) and [Deserialize](https://serde.rs/impl-deserialize.html)!
- The signature and data are serialized/deserialized together
- Timestamps when signing data, with optional expiration
- Human readable: Keys and signatures are encoded in base64, timestamps in ISO 8601
- Attach unsigned comment along side the signed data (like in openbsd signify)

Once you have generated keys/signatures, use the power of serde to pass your data anywhere!

## Samples

For simplicity, these samples will be serialized in json.

Comments and expiration are optional if you do not have a need for them.

### Private key

```json
{
  "secret_key": "4564424b00000000d2252a412cd1cd2334ecd053275fba5a3dc9e6afbf7996ea5979bf1c7cf1403aab59795c4502b51a422ae1de66e8a16424297cc6f29c4127d3e17f6e33d1bd50618a7a196b421db1182bb3d46d756cbfab54e254b7307e6cca5ad82c674e711b",
  "created_at": "2024-12-24T15:02:48.845298Z",
  "expired_at": null,
  "comment": "testing key, do not use"
}
```

### Public key

```json
{
  "public_key": "45645979bf1c7cf1403a618a7a196b421db1182bb3d46d756cbfab54e254b7307e6cca5ad82c674e711b",
  "created_at": "2024-12-24T15:02:48.845298Z",
  "expired_at": null,
  "comment": "testing key, do not use"
}
```

### Signature

```json
{
  "signed_artifact": {
    "data": {
      "string": "Toto mange du gateau",
      "bytes": [
        222,
        173,
        186,
        237
      ],
      "int": -1,
      "boolean": true
    },
    "timestamp": "2024-12-27T14:59:30Z",
    "expiration": "2024-12-28T14:59:30Z"
  },
  "signature": "RWRZeb8cfPFAOrlQsaAKcOTnSpCwkqzVsQRb2gZ4IAkvlwQwWBOts3bUbZ8+pNJHPuZXSEMuUPua+FuLkrpteTeh1DiGSoORUAg=",
  "comment": "anybody can change me :)"
}
```

The struct holding `data` is this:
```rust
struct MyData {
    string: String,
    bytes: Vec<u8>,
    int: i32,
    boolean: bool,
}
```

## Notes when using the crate

### Use the same structure

When deserializing a signature, you need to use the same structure you used for the serialization, otherwise deserialization will fail.

### Versionning

My usage of this crate is in a setup like this:

```
                "Signing authority"                         
               ┌───────────────────────────────────────────┐
               │                                           │
               │  - Key management: generation, rotation   │
               │                                           │
          ┌────┼─── Sign data: produce signatures          │
          │    │                                           │
Transfer  │    └───────────────────────────────────────────┘
over the  │                                                 
internet  │    ┌──────────────────────────────────┐         
          │    │                                  │         
          └────►  - Verify signatures + validity  │         
               │                                  │         
               │  - Use data if authentic         │         
               │                                  │         
               └──────────────────────────────────┘         
                "Signature consumer"
```

Both the authority and consumer are going to use the same crate, meaning there is no built-in versionning. But it should be easy to do it yourself.

### Key rotation

Key rotation can be pretty simple to do: with an existing key `a`:
1. Generate a new key `b`
2. Stop emitting signatures with signing key `a`
3. Introduce public key `b` for verifying signatures
4. Emit signatures with signing key `b`
5. When you are ready, remove the public key `a` for verifying signatures.

When implementating a key rotation system, do not forget what should happen for existing signatures from signing key `a`:
- Should you re-emit signatures with signing key `b`?
- Should thoses signatures expire?

## TODO

- [ ] Actually enforce expiration on keys/signatures, they do nothing at the moment
- [ ] Support passphrases on keys
- [ ] Better types when wanting to sign or verify signatures, maybe behind features?

## License

MIT
