# c2pa-opentdf-rs

C2PA + OpenTDF integration library in Rust - combining content authenticity with trusted data encryption.

## Overview

This library bridges [C2PA](https://c2pa.org/) (Coalition for Content Provenance and Authenticity) with [OpenTDF](https://github.com/arkavo-org/opentdf-rs) (Open Trusted Data Format), enabling you to:

1. **Sign content** with C2PA manifests to establish provenance and authenticity
2. **Encrypt signed content** using OpenTDF for access control and data protection
3. **Decrypt and verify** content to ensure both data integrity and authentic provenance

## Use Cases

- **Secure media distribution**: Sign images/video with C2PA provenance, then encrypt with attribute-based access control
- **Confidential content authenticity**: Prove content origin while keeping it encrypted until authorized access
- **Compliance workflows**: Combine tamper-evident provenance with policy-enforced encryption

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
c2pa_opentdf = { path = "../c2pa-opentdf-rs" }
```

For KAS (Key Access Service) support:

```toml
[dependencies]
c2pa_opentdf = { path = "../c2pa-opentdf-rs", features = ["kas"] }
```

## Quick Start

### Sign and Encrypt

```rust
use c2pa_opentdf::{C2paOpenTdf, Policy};

// Configure C2PA signing and OpenTDF encryption
let c2pa_tdf = C2paOpenTdf::builder()
    .certificate_and_key("cert.pem", "private.pem")
    .kas_url("https://kas.example.com")
    .build()?;

// Read your content (must be a supported media type like PNG, JPG, etc.)
let image_data = std::fs::read("input.png")?;

// Sign with C2PA and encrypt with OpenTDF
let encrypted = c2pa_tdf.sign_and_encrypt(
    &image_data,
    "My Authenticated Image",
    "output.tdf"
)?;
```

### With Access Control Policy

```rust
use c2pa_opentdf::{C2paOpenTdf, Policy};

let policy = Policy::new(
    "unique-id".to_string(),
    vec![], // attributes
    vec!["user@example.com".to_string()], // dissemination list
);

let c2pa_tdf = C2paOpenTdf::builder()
    .certificate_and_key("cert.pem", "private.pem")
    .kas_url("https://kas.example.com")
    .policy(policy)
    .build()?;

let encrypted = c2pa_tdf.sign_and_encrypt(
    &image_data,
    "Confidential Report",
    "report.tdf"
)?;
```

### Decrypt and Verify (with KAS feature)

```rust
use c2pa_opentdf::{C2paOpenTdf, kas::KasClient};

// Create KAS client for decryption
let kas_client = KasClient::new("https://kas.example.com", "auth-token")?;

let c2pa_tdf = C2paOpenTdf::builder()
    .certificate_and_key("cert.pem", "private.pem")
    .kas_url("https://kas.example.com")
    .build()?;

// Decrypt and verify C2PA provenance
let original_data = c2pa_tdf.decrypt_and_verify("report.tdf", &kas_client).await?;
```

## Architecture

### Integration Approach

The library follows the [OpenTDF specification](https://github.com/opentdf/spec) to integrate C2PA provenance with TDF encryption:

1. **C2PA Signing**: Content is signed using ES256 (ECDSA with SHA-256), embedding provenance manifests directly in the media file
2. **Data Hashing**: SHA-256 hash of the original data is stored as a C2PA assertion (`org.arkavo.c2pa_opentdf.data_hash`)
3. **TDF Encryption**: The C2PA-signed content is encrypted using OpenTDF's AES-256-GCM segmented encryption
4. **Manifest Storage**: OpenTDF manifest includes C2PA metadata via MIME type and assertions
5. **Verification Chain**: Decryption validates both TDF integrity (segments + GMAC) and C2PA provenance

### Workflow

```
Original Content → C2PA Sign → Signed Content → TDF Encrypt → Encrypted TDF
                    ↓                              ↓
                    Manifest                       Policy + KAS

Encrypted TDF → TDF Decrypt → Signed Content → C2PA Verify → Original Content
                 ↓                               ↓
                 KAS                             Manifest Check
```

## Features

- ✅ C2PA signing with ES256
- ✅ OpenTDF encryption with segmented AES-256-GCM
- ✅ Builder pattern for easy configuration
- ✅ Custom C2PA assertions for data integrity
- ✅ Integration with OpenTDF policy and KAS
- ✅ Decrypt and verify workflow (with `kas` feature)
- 📋 Support for additional C2PA signing algorithms
- 📋 Custom assertion schemas for enhanced metadata

## Development

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Run a Specific Test

```bash
cargo test test_sign_and_encrypt
```

## Certificates & Keys

Test certificates are stored in `tests/data/`. For production:

- Obtain proper C2PA signing certificates
- Source: https://github.com/contentauth/c2pa-rs/tree/main/sdk/tests/fixtures/certs
- Use ES256 (ECDSA with SHA-256) for signing

## OpenTDF Integration

This library depends on [opentdf-rs](https://github.com/arkavo-org/opentdf-rs) located at `../opentdf-rs`. Ensure the repository is cloned in the correct location.

## License

Apache-2.0 (same as opentdf-rs)

## Contributing

See [opentdf/spec](https://github.com/opentdf/spec) for TDF3/ZTDF specification details.

## References

- [C2PA Specification](https://c2pa.org/specifications/specifications/2.1/index.html)
- [OpenTDF Specification](https://github.com/opentdf/spec)
- [c2pa-rs SDK](https://github.com/contentauth/c2pa-rs)
- [opentdf-rs](https://github.com/arkavo-org/opentdf-rs)
