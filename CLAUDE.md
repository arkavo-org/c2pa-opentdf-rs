# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This library integrates **C2PA** (Coalition for Content Provenance and Authenticity) with **OpenTDF** (Open Trusted Data Format), combining content authenticity/provenance with attribute-based access control encryption. The integration follows the [OpenTDF specification](https://github.com/opentdf/spec) for TDF3/ZTDF formats.

**Key Dependencies:**
- `c2pa` (v0.67.1): Content authenticity SDK with file I/O features
- `opentdf` (local path `../opentdf-rs`): OpenTDF implementation with optional KAS support
- `thiserror`: Custom error types
- `sha2`: Hashing for data integrity assertions

## Build and Test Commands

**Build:**
```bash
cargo build
```

**Run all tests:**
```bash
cargo test
```

**Run a specific test:**
```bash
cargo test <test_name>
# Example: cargo test test_sign_and_encrypt
```

**Run tests with output:**
```bash
cargo test -- --nocapture
```

**Check code without building:**
```bash
cargo check
```

**Build with KAS support:**
```bash
cargo build --features kas
```

## Architecture

### Core Integration Pattern

The library follows a **sign-then-encrypt** pattern:

1. **C2PA Signing Phase** (src/signer.rs:39-77)
   - Original content (must be supported media: PNG, JPG, etc.) is signed with ES256
   - A SHA-256 hash of the original data is embedded as a C2PA assertion (`org.arkavo.c2pa_opentdf.data_hash`)
   - C2PA manifest is embedded directly in the media file
   - Temporary files require proper extensions (.png, .jpg) for C2PA to recognize the format

2. **OpenTDF Encryption Phase** (src/signer.rs:84-103)
   - The C2PA-signed content is encrypted using OpenTDF's segmented AES-256-GCM
   - OpenTDF manifest stores policy, KAS URL, and integrity information
   - MIME type is set to `application/c2pa` to indicate C2PA-signed content
   - Output is a ZIP archive containing encrypted segments and manifest

3. **Decryption and Verification** (src/signer.rs:117-146, requires `kas` feature)
   - TDF is decrypted using KAS client
   - C2PA manifest is verified using `c2pa::Reader`
   - Validation ensures both TDF integrity and C2PA provenance

### Error Handling

Custom error types in `src/error.rs` using `thiserror`:
- `C2paError`: C2PA signing/verification errors
- `OpenTdfError`: TDF encryption/decryption errors
- `IoError`, `SerializationError`: Standard errors
- `VerificationFailed`, `InvalidManifest`: Security-critical errors
- `Configuration`: Builder validation errors

### Builder Pattern

`C2paOpenTdfBuilder` (src/signer.rs:169-234) provides fluent API:
- Certificate/key loading from files or bytes
- KAS URL configuration
- Optional Policy for access control
- Signing algorithm selection (default: ES256)

### File Structure

```
src/
  ├── lib.rs          - Public API exports and basic tests
  ├── error.rs        - Error types using thiserror
  └── signer.rs       - Core C2paOpenTdf implementation
tests/data/           - Test certificates, keys, and sample files
  ├── cert.pem        - Test certificate for ES256 signing
  ├── private.pem     - Test private key (ES256)
  └── logo.png        - Sample PNG image for testing
target/tmp/           - Test output directory (auto-created)
```

## Important Notes

**C2PA Requirements:**
- Content MUST be a supported media type (PNG, JPG, MP4, etc.) - plain text/binary won't work
- Temporary files need proper file extensions or C2PA throws "type is unsupported"
- C2PA won't overwrite existing files - remove before signing (see src/signer.rs:78)
- Test certificates from https://github.com/contentauth/c2pa-rs/tree/main/sdk/tests/fixtures/certs

**OpenTDF Integration:**
- Depends on `opentdf-rs` from sibling directory (`../opentdf-rs`)
- KAS feature must be enabled for decrypt_and_verify: `--features kas`
- Follows TDF3 spec with segmented encryption (default 2MB segments)
- Assertions array in OpenTDF manifest can store C2PA metadata (see opentdf/spec)

**Testing:**
- Tests use `tempfile` with proper extensions to avoid conflicts
- `test_c2pa_basic_signing` - Pure C2PA workflow
- `test_builder_pattern` - Configuration validation
- `test_sign_and_encrypt` - Full integration workflow

**Common Issues:**
- "type is unsupported" → file extension missing on temp files
- "Destination file already exists" → C2PA won't overwrite, use `std::fs::remove_file` first
- "KAS URL is required" → Builder validation, must set KAS URL before `.build()`

## Development Patterns

**Adding new C2PA assertions:**
1. Define struct with `#[derive(Serialize)]`
2. Add to builder in `sign_and_encrypt` using `builder.add_assertion("org.arkavo.{name}", &data)`
3. Custom assertion naming: use `org.arkavo.*` namespace

**Extending OpenTDF metadata:**
1. OpenTDF assertions follow spec: `/Users/paul/Projects/opentdf/spec/schema/OpenTDF/assertion.md`
2. Add to TDF manifest via builder or custom TdfEncryptBuilder usage
3. Assertions require: id, type, scope, statement, optional binding

**Supporting new media types:**
C2PA SDK handles detection automatically based on file extension - no code changes needed for standard types (PNG, JPG, MP4, etc.)
