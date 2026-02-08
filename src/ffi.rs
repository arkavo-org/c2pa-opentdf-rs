//! C FFI for C2PA signing, verification, and manifest extraction.
//!
//! This module exposes four `extern "C"` functions that can be called from
//! C or Swift via an XCFramework:
//!
//! - [`c2pa_sign_file`] — sign a media file with a C2PA manifest.
//! - [`c2pa_verify_file`] — verify a C2PA manifest and return structured JSON.
//! - [`c2pa_info_file`] — extract raw manifest JSON from a media file.
//! - [`c2pa_string_free`] — free any string allocated by the functions above.
//!
//! # Memory management
//!
//! Every out-string (`*error_out`, `*result_json`, `*info_json`) is heap-
//! allocated by this library. The **caller** must free each string exactly
//! once by passing it to [`c2pa_string_free`]. If a function is called
//! multiple times, the caller must free the previous out-string *before*
//! the next call, otherwise the previous allocation will leak.
//!
//! Each function clears its out-pointers to null at the start of execution,
//! so the caller can safely check for null to determine whether a string
//! was returned.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic;
use std::ptr;

use c2pa::{create_signer, Builder, Reader, SigningAlg};

/// Result codes returned by FFI functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C2paResultCode {
    /// Operation completed successfully.
    Success = 0,
    /// A null pointer was passed for a required argument.
    NullPointer = 1,
    /// A string argument contained invalid UTF-8.
    InvalidUtf8 = 2,
    /// C2PA signing failed.
    SignError = 3,
    /// C2PA verification / read failed.
    VerifyError = 4,
    /// An internal panic was caught.
    InternalError = 5,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write an error string into `*error_out` (if non-null).
///
/// If `msg` contains interior null bytes they are replaced with `?` so the
/// caller always receives a valid error description.
unsafe fn set_error(error_out: *mut *mut c_char, msg: &str) {
    if !error_out.is_null() {
        let sanitized = msg.replace('\0', "?");
        // SAFETY: `sanitized` is guaranteed to have no interior null bytes.
        let c = CString::new(sanitized).expect("sanitized string should not contain NUL");
        unsafe { *error_out = c.into_raw() };
    }
}

/// Convert a `*const c_char` to `&str`, returning `Err(C2paResultCode)` on failure.
unsafe fn cstr_to_str<'a>(
    p: *const c_char,
    error_out: *mut *mut c_char,
) -> Result<&'a str, C2paResultCode> {
    if p.is_null() {
        unsafe { set_error(error_out, "null pointer argument") };
        return Err(C2paResultCode::NullPointer);
    }
    unsafe { CStr::from_ptr(p) }.to_str().map_err(|e| {
        unsafe { set_error(error_out, &format!("invalid UTF-8: {e}")) };
        C2paResultCode::InvalidUtf8
    })
}

/// Write a Rust `String` into `*out` as a C string.
///
/// Interior null bytes in `s` are replaced with `?` so the caller always
/// receives a valid C string.
unsafe fn set_string_out(out: *mut *mut c_char, s: &str) {
    if !out.is_null() {
        let sanitized = s.replace('\0', "?");
        let c = CString::new(sanitized).expect("sanitized string should not contain NUL");
        unsafe { *out = c.into_raw() };
    }
}

// ---------------------------------------------------------------------------
// Public FFI
// ---------------------------------------------------------------------------

/// Sign a media file with a C2PA manifest.
///
/// # Safety
/// All pointer arguments must be valid C strings or null (for `error_out`).
/// The caller must free any string written to `*error_out` via [`c2pa_string_free`]
/// **before** calling this function again, or the previous string will leak.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sign_file(
    input_path: *const c_char,
    output_path: *const c_char,
    manifest_json: *const c_char,
    cert_pem: *const c_char,
    key_pem: *const c_char,
    error_out: *mut *mut c_char,
) -> C2paResultCode {
    // Clear error out
    if !error_out.is_null() {
        unsafe { *error_out = ptr::null_mut() };
    }

    let result = panic::catch_unwind(|| {
        let input = unsafe { cstr_to_str(input_path, error_out)? };
        let output = unsafe { cstr_to_str(output_path, error_out)? };
        let json = unsafe { cstr_to_str(manifest_json, error_out)? };
        let cert = unsafe { cstr_to_str(cert_pem, error_out)? };
        let key = unsafe { cstr_to_str(key_pem, error_out)? };

        let signer =
            create_signer::from_keys(cert.as_bytes(), key.as_bytes(), SigningAlg::Es256, None)
                .map_err(|e| {
                    unsafe { set_error(error_out, &format!("signer creation failed: {e}")) };
                    C2paResultCode::SignError
                })?;

        let mut builder = Builder::from_json(json).map_err(|e| {
            unsafe { set_error(error_out, &format!("manifest json parsing failed: {e}")) };
            C2paResultCode::SignError
        })?;

        // Remove output file if it exists (c2pa won't overwrite)
        let _ = std::fs::remove_file(output);

        builder.sign_file(&*signer, input, output).map_err(|e| {
            unsafe { set_error(error_out, &format!("signing failed: {e}")) };
            C2paResultCode::SignError
        })?;

        Ok(C2paResultCode::Success)
    });

    match result {
        Ok(Ok(code)) => code,
        Ok(Err(code)) => code,
        Err(_) => {
            unsafe { set_error(error_out, "internal panic in c2pa_sign_file") };
            C2paResultCode::InternalError
        }
    }
}

/// Verify a C2PA manifest in a media file.
///
/// On success, `*result_json` is set to a JSON string:
/// ```json
/// {"is_valid": true, "has_manifest": true, "manifest_json": "..."}
/// ```
///
/// # Safety
/// The caller must free `*result_json` and `*error_out` via [`c2pa_string_free`]
/// **before** calling this function again, or previous strings will leak.
#[no_mangle]
pub unsafe extern "C" fn c2pa_verify_file(
    file_path: *const c_char,
    result_json: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> C2paResultCode {
    if !error_out.is_null() {
        unsafe { *error_out = ptr::null_mut() };
    }
    if !result_json.is_null() {
        unsafe { *result_json = ptr::null_mut() };
    }

    let result = panic::catch_unwind(|| {
        let path = unsafe { cstr_to_str(file_path, error_out)? };

        match Reader::from_file(path) {
            Ok(reader) => {
                let manifest_json_str = reader.json();
                let has_manifest = reader.active_manifest().is_some();

                let validation = reader.validation_status();
                let is_valid = match validation {
                    Some(statuses) => statuses.is_empty(),
                    None => true,
                };

                let result_obj = serde_json::json!({
                    "is_valid": is_valid,
                    "has_manifest": has_manifest,
                    "manifest_json": manifest_json_str,
                });
                let json_str = serde_json::to_string(&result_obj).unwrap_or_default();
                unsafe { set_string_out(result_json, &json_str) };
                Ok(C2paResultCode::Success)
            }
            Err(e) => {
                // No manifest is not necessarily an error — return structured JSON
                let err_str = e.to_string();
                let result_obj = serde_json::json!({
                    "is_valid": false,
                    "has_manifest": false,
                    "error": err_str,
                });
                let json_str = serde_json::to_string(&result_obj).unwrap_or_default();
                unsafe { set_string_out(result_json, &json_str) };
                Ok(C2paResultCode::Success)
            }
        }
    });

    match result {
        Ok(Ok(code)) => code,
        Ok(Err(code)) => code,
        Err(_) => {
            unsafe { set_error(error_out, "internal panic in c2pa_verify_file") };
            C2paResultCode::InternalError
        }
    }
}

/// Extract C2PA manifest information from a media file.
///
/// On success, `*info_json` is set to the manifest JSON string.
///
/// # Safety
/// The caller must free `*info_json` and `*error_out` via [`c2pa_string_free`]
/// **before** calling this function again, or previous strings will leak.
#[no_mangle]
pub unsafe extern "C" fn c2pa_info_file(
    file_path: *const c_char,
    info_json: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> C2paResultCode {
    if !error_out.is_null() {
        unsafe { *error_out = ptr::null_mut() };
    }
    if !info_json.is_null() {
        unsafe { *info_json = ptr::null_mut() };
    }

    let result = panic::catch_unwind(|| {
        let path = unsafe { cstr_to_str(file_path, error_out)? };

        let reader = Reader::from_file(path).map_err(|e| {
            unsafe { set_error(error_out, &format!("manifest read failed: {e}")) };
            C2paResultCode::VerifyError
        })?;

        let json_str = reader.json();
        unsafe { set_string_out(info_json, &json_str) };
        Ok(C2paResultCode::Success)
    });

    match result {
        Ok(Ok(code)) => code,
        Ok(Err(code)) => code,
        Err(_) => {
            unsafe { set_error(error_out, "internal panic in c2pa_info_file") };
            C2paResultCode::InternalError
        }
    }
}

/// Free a string that was allocated by this library.
///
/// # Safety
/// `s` must be a pointer returned by one of the FFI functions, or null.
#[no_mangle]
pub unsafe extern "C" fn c2pa_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}
