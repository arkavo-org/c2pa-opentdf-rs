//! FFI integration tests for c2pa_opentdf.
//!
//! These tests call the public FFI functions directly from Rust, exercising
//! the same code path a C/Swift consumer would use.
//!
//! Offline tests run with `cargo test`.
//! Server tests run with `cargo test -- --ignored`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;

use c2pa_opentdf::ffi::{
    c2pa_info_file, c2pa_sign_file, c2pa_string_free, c2pa_verify_file, C2paResultCode,
};

// ---------------------------------------------------------------------------
// FfiString — RAII guard that calls c2pa_string_free on drop
// ---------------------------------------------------------------------------

struct FfiString {
    ptr: *mut c_char,
}

impl FfiString {
    /// Wrap a raw pointer returned by an FFI function.
    fn new(ptr: *mut c_char) -> Self {
        Self { ptr }
    }

    /// Return the string as `&str`, or `None` if the pointer is null.
    fn as_str(&self) -> Option<&str> {
        if self.ptr.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(self.ptr) }.to_str().ok()
        }
    }
}

impl Drop for FfiString {
    fn drop(&mut self) {
        unsafe { c2pa_string_free(self.ptr) };
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn logo_path() -> CString {
    CString::new(test_data_dir().join("logo.png").to_str().unwrap()).unwrap()
}

fn cert_pem() -> Vec<u8> {
    std::fs::read(test_data_dir().join("cert.pem")).expect("cert.pem")
}

fn key_pem() -> Vec<u8> {
    std::fs::read(test_data_dir().join("private.pem")).expect("private.pem")
}

fn manifest_json() -> CString {
    CString::new(r#"{"title": "FFI Integration Test"}"#).unwrap()
}

/// Sign logo.png into a fresh temp file, returning (result_code, temp_file, error_string).
fn sign_to_temp() -> (C2paResultCode, tempfile::NamedTempFile, FfiString) {
    let tmp = tempfile::Builder::new()
        .suffix(".png")
        .tempfile()
        .expect("create temp file");
    let out_path = CString::new(tmp.path().to_str().unwrap()).unwrap();

    let cert = CString::new(cert_pem()).unwrap();
    let key = CString::new(key_pem()).unwrap();
    let json = manifest_json();

    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe {
        c2pa_sign_file(
            logo_path().as_ptr(),
            out_path.as_ptr(),
            json.as_ptr(),
            cert.as_ptr(),
            key.as_ptr(),
            &mut error,
        )
    };

    (code, tmp, FfiString::new(error))
}

// ===========================================================================
// Offline tests
// ===========================================================================

#[test]
fn test_sign_file_success() {
    let (code, tmp, err) = sign_to_temp();
    assert_eq!(code, C2paResultCode::Success, "error: {:?}", err.as_str());

    let input_size = std::fs::metadata(test_data_dir().join("logo.png"))
        .unwrap()
        .len();
    let output_size = std::fs::metadata(tmp.path()).unwrap().len();
    assert!(
        output_size > input_size,
        "signed file ({output_size}) should be larger than input ({input_size})"
    );
}

#[test]
fn test_sign_then_verify_roundtrip() {
    let (code, tmp, err) = sign_to_temp();
    assert_eq!(
        code,
        C2paResultCode::Success,
        "sign error: {:?}",
        err.as_str()
    );

    let file_path = CString::new(tmp.path().to_str().unwrap()).unwrap();
    let mut result_json: *mut c_char = ptr::null_mut();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe { c2pa_verify_file(file_path.as_ptr(), &mut result_json, &mut error) };
    let result = FfiString::new(result_json);
    let err = FfiString::new(error);

    assert_eq!(
        code,
        C2paResultCode::Success,
        "verify error: {:?}",
        err.as_str()
    );

    let json_str = result.as_str().expect("result_json should be non-null");
    let v: serde_json::Value = serde_json::from_str(json_str).expect("valid JSON");
    assert_eq!(v["has_manifest"], true, "manifest should be present");
    // Note: is_valid may be false with a self-signed test cert (trust chain validation)
    // but the manifest must be present and parseable
    assert!(
        v["manifest_json"].is_string(),
        "manifest_json should be a string"
    );
}

#[test]
fn test_sign_then_info_roundtrip() {
    let (code, tmp, err) = sign_to_temp();
    assert_eq!(
        code,
        C2paResultCode::Success,
        "sign error: {:?}",
        err.as_str()
    );

    let file_path = CString::new(tmp.path().to_str().unwrap()).unwrap();
    let mut info_json: *mut c_char = ptr::null_mut();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe { c2pa_info_file(file_path.as_ptr(), &mut info_json, &mut error) };
    let info = FfiString::new(info_json);
    let err = FfiString::new(error);

    assert_eq!(
        code,
        C2paResultCode::Success,
        "info error: {:?}",
        err.as_str()
    );

    let json_str = info.as_str().expect("info_json should be non-null");
    assert!(
        json_str.contains("FFI Integration Test"),
        "manifest JSON should contain title: {json_str}"
    );
}

#[test]
fn test_verify_unsigned_file() {
    let mut result_json: *mut c_char = ptr::null_mut();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe { c2pa_verify_file(logo_path().as_ptr(), &mut result_json, &mut error) };
    let result = FfiString::new(result_json);
    let err = FfiString::new(error);

    assert_eq!(code, C2paResultCode::Success, "error: {:?}", err.as_str());

    let json_str = result.as_str().expect("result_json should be non-null");
    let v: serde_json::Value = serde_json::from_str(json_str).expect("valid JSON");
    assert_eq!(
        v["has_manifest"], false,
        "unsigned file should have no manifest"
    );
}

#[test]
fn test_info_unsigned_file() {
    let mut info_json: *mut c_char = ptr::null_mut();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe { c2pa_info_file(logo_path().as_ptr(), &mut info_json, &mut error) };
    let _info = FfiString::new(info_json);
    let err = FfiString::new(error);

    assert_eq!(code, C2paResultCode::VerifyError);
    assert!(
        err.as_str().is_some(),
        "error message should be set for unsigned file"
    );
}

#[test]
fn test_sign_null_pointer() {
    let cert = CString::new(cert_pem()).unwrap();
    let key = CString::new(key_pem()).unwrap();
    let json = manifest_json();
    let out = CString::new("/tmp/unused.png").unwrap();
    let mut error: *mut c_char = ptr::null_mut();

    // null input_path
    let code = unsafe {
        c2pa_sign_file(
            ptr::null(),
            out.as_ptr(),
            json.as_ptr(),
            cert.as_ptr(),
            key.as_ptr(),
            &mut error,
        )
    };
    let err = FfiString::new(error);

    assert_eq!(code, C2paResultCode::NullPointer);
    assert!(
        err.as_str().unwrap_or("").contains("null"),
        "error should mention null: {:?}",
        err.as_str()
    );
}

#[test]
fn test_verify_null_pointer() {
    let mut result_json: *mut c_char = ptr::null_mut();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe { c2pa_verify_file(ptr::null(), &mut result_json, &mut error) };
    let _result = FfiString::new(result_json);
    let err = FfiString::new(error);

    assert_eq!(code, C2paResultCode::NullPointer);
    assert!(
        err.as_str().unwrap_or("").contains("null"),
        "error should mention null"
    );
}

#[test]
fn test_sign_invalid_json() {
    let tmp = tempfile::Builder::new()
        .suffix(".png")
        .tempfile()
        .expect("temp file");
    let out_path = CString::new(tmp.path().to_str().unwrap()).unwrap();
    let cert = CString::new(cert_pem()).unwrap();
    let key = CString::new(key_pem()).unwrap();
    let bad_json = CString::new("not valid json {{{").unwrap();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe {
        c2pa_sign_file(
            logo_path().as_ptr(),
            out_path.as_ptr(),
            bad_json.as_ptr(),
            cert.as_ptr(),
            key.as_ptr(),
            &mut error,
        )
    };
    let err = FfiString::new(error);

    assert_eq!(code, C2paResultCode::SignError);
    assert!(err.as_str().is_some(), "error message should be set");
}

#[test]
fn test_sign_invalid_cert() {
    let tmp = tempfile::Builder::new()
        .suffix(".png")
        .tempfile()
        .expect("temp file");
    let out_path = CString::new(tmp.path().to_str().unwrap()).unwrap();
    let bad_cert = CString::new("not a real certificate").unwrap();
    let bad_key = CString::new("not a real key").unwrap();
    let json = manifest_json();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe {
        c2pa_sign_file(
            logo_path().as_ptr(),
            out_path.as_ptr(),
            json.as_ptr(),
            bad_cert.as_ptr(),
            bad_key.as_ptr(),
            &mut error,
        )
    };
    let err = FfiString::new(error);

    assert_eq!(code, C2paResultCode::SignError);
    assert!(
        err.as_str().is_some(),
        "error message should be set for bad cert"
    );
}

#[test]
fn test_sign_nonexistent_input() {
    let tmp = tempfile::Builder::new()
        .suffix(".png")
        .tempfile()
        .expect("temp file");
    let out_path = CString::new(tmp.path().to_str().unwrap()).unwrap();
    let cert = CString::new(cert_pem()).unwrap();
    let key = CString::new(key_pem()).unwrap();
    let json = manifest_json();
    let bad_input = CString::new("/nonexistent/path/file.png").unwrap();
    let mut error: *mut c_char = ptr::null_mut();

    let code = unsafe {
        c2pa_sign_file(
            bad_input.as_ptr(),
            out_path.as_ptr(),
            json.as_ptr(),
            cert.as_ptr(),
            key.as_ptr(),
            &mut error,
        )
    };
    let err = FfiString::new(error);

    assert_eq!(code, C2paResultCode::SignError);
    assert!(err.as_str().is_some(), "error message should be set");
}

#[test]
fn test_string_free_null() {
    // c2pa_string_free(null) should be a safe no-op — just verify no crash
    unsafe { c2pa_string_free(ptr::null_mut()) };
}

#[test]
fn test_error_out_null_accepted() {
    // All functions should tolerate error_out = null without crash

    // sign with null error_out
    let code = unsafe {
        c2pa_sign_file(
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
        )
    };
    assert_eq!(code, C2paResultCode::NullPointer);

    // verify with null error_out
    let mut result_json: *mut c_char = ptr::null_mut();
    let code = unsafe { c2pa_verify_file(ptr::null(), &mut result_json, ptr::null_mut()) };
    let _result = FfiString::new(result_json);
    assert_eq!(code, C2paResultCode::NullPointer);

    // info with null error_out (null path → NullPointer before it reaches verify logic)
    let mut info_json: *mut c_char = ptr::null_mut();
    let code = unsafe { c2pa_info_file(ptr::null(), &mut info_json, ptr::null_mut()) };
    let _info = FfiString::new(info_json);
    assert_eq!(code, C2paResultCode::NullPointer);
}

// ===========================================================================
// Server tests (cargo test -- --ignored)
// ===========================================================================

#[test]
#[ignore]
fn test_server_sign() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let logo_bytes = std::fs::read(test_data_dir().join("logo.png")).expect("read logo.png");
    let hash = Sha256::digest(&logo_bytes);
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);

    let body = serde_json::json!({
        "asset_hash": hash_b64,
        "hash_algorithm": "SHA-256",
    });

    let response: serde_json::Value = ureq::post("https://100.arkavo.net/c2pa/v1/sign")
        .header("Content-Type", "application/json")
        .send_json(&body)
        .expect("POST /c2pa/v1/sign")
        .body_mut()
        .read_json()
        .expect("parse response JSON");

    assert_eq!(
        response["status"], "success",
        "server should return success: {response}"
    );
    assert!(
        response["manifest"].is_string(),
        "response should include manifest"
    );
    assert!(response["hash"].is_string(), "response should include hash");
}

#[test]
#[ignore]
fn test_server_sign_validate_roundtrip() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let logo_bytes = std::fs::read(test_data_dir().join("logo.png")).expect("read logo.png");
    let hash = Sha256::digest(&logo_bytes);
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);

    // Sign
    let sign_body = serde_json::json!({
        "asset_hash": hash_b64,
        "hash_algorithm": "SHA-256",
    });

    let sign_response: serde_json::Value = ureq::post("https://100.arkavo.net/c2pa/v1/sign")
        .header("Content-Type", "application/json")
        .send_json(&sign_body)
        .expect("POST /c2pa/v1/sign")
        .body_mut()
        .read_json()
        .expect("parse sign response");

    assert_eq!(sign_response["status"], "success");

    let manifest = sign_response["manifest"].as_str().expect("manifest string");

    // Validate
    let validate_body = serde_json::json!({
        "manifest": manifest,
        "asset_hash": hash_b64,
        "hash_algorithm": "SHA-256",
    });

    let validate_response: serde_json::Value =
        ureq::post("https://100.arkavo.net/c2pa/v1/validate")
            .header("Content-Type", "application/json")
            .send_json(&validate_body)
            .expect("POST /c2pa/v1/validate")
            .body_mut()
            .read_json()
            .expect("parse validate response");

    assert_eq!(
        validate_response["status"], "success",
        "validate should succeed: {validate_response}"
    );
}

#[test]
#[ignore]
fn test_server_invalid_hash() {
    let body = serde_json::json!({
        "asset_hash": "dG9vc2hvcnQ=",
        "hash_algorithm": "SHA-256",
    });

    let result = ureq::post("https://100.arkavo.net/c2pa/v1/sign")
        .header("Content-Type", "application/json")
        .send_json(&body);

    match result {
        Ok(mut resp) => {
            let response: serde_json::Value =
                resp.body_mut().read_json().expect("parse error response");
            assert_eq!(
                response["status"], "error",
                "invalid hash should return error: {response}"
            );
        }
        Err(ureq::Error::StatusCode(status)) => {
            assert!(
                status >= 400,
                "invalid hash should return 4xx/5xx, got {status}"
            );
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}
