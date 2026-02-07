mod error;
pub mod ffi;
mod signer;

pub use error::C2paOpenTdfError;
pub use signer::{C2paOpenTdf, C2paOpenTdfBuilder};

// Re-export commonly used types
pub use c2pa::{Builder, SigningAlg};
pub use opentdf::{Policy, Tdf};

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa::create_signer;

    #[test]
    fn test_c2pa_basic_signing() -> Result<(), Box<dyn std::error::Error>> {
        use serde::Serialize;

        #[derive(Serialize)]
        struct Test {
            my_tag: usize,
        }

        // Ensure output directory exists
        std::fs::create_dir_all("target/tmp")?;

        let signer = create_signer::from_keys(
            &std::fs::read("tests/data/cert.pem")?,
            &std::fs::read("tests/data/private.pem")?,
            SigningAlg::Es256,
            None,
        )?;

        let mut builder = Builder::from_json(r#"{"title": "Test"}"#)?;
        builder.add_assertion("org.arkavo.test", &Test { my_tag: 42 })?;

        // Remove old file if it exists
        let output_path = "target/tmp/logo_sign.png";
        let _ = std::fs::remove_file(output_path);

        builder.sign_file(&*signer, "tests/data/logo.png", output_path)?;

        // Verify output exists
        assert!(std::path::Path::new(output_path).exists());

        Ok(())
    }
}
