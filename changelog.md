# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com).

## Unreleased

## 0.2.0 - 2025-04-30

### Changed

- Encoding of secret and public keys switched from hexadecimal (base16) to base64.

## 0.1.0 - 2024-12-28

### Added

- Generate signing keys, extract public key from signing key.
- Sign anything implementing [Serialize](https://docs.rs/serde/latest/serde/trait.Serialize.html) and [Deserialize](https://docs.rs/serde/latest/serde/trait.Deserialize.html).
- The signature and data are serialized/deserialized together.
- Timestamps when signing data, with optional expiration (encoded in ISO 8601).
- Ability to attach unsigned comment along side the signed data (like in openbsd signify).
