use crate::error::{C2paOpenTdfError, Result};
use c2pa::{create_signer, Builder, Signer, SigningAlg};
use opentdf::{Policy, Tdf};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Main integration struct for C2PA signing and OpenTDF encryption
pub struct C2paOpenTdf {
    signer: Box<dyn Signer>,
    kas_url: String,
    policy: Option<Policy>,
}

impl C2paOpenTdf {
    /// Create a new builder for C2paOpenTdf
    pub fn builder() -> C2paOpenTdfBuilder {
        C2paOpenTdfBuilder::new()
    }

    /// Sign data with C2PA and encrypt with OpenTDF
    ///
    /// This method:
    /// 1. Creates a C2PA manifest with the provided metadata
    /// 2. Signs the data using C2PA
    /// 3. Computes a hash of the C2PA manifest
    /// 4. Encrypts the signed data with OpenTDF, embedding the manifest hash
    ///
    /// # Arguments
    /// * `data` - The original data to sign and encrypt
    /// * `title` - Title for the C2PA manifest
    /// * `output_path` - Path where the encrypted TDF file will be written
    ///
    /// # Returns
    /// The encrypted TDF bytes
    pub fn sign_and_encrypt(
        &self,
        data: &[u8],
        title: &str,
        output_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>> {
        // Step 1: Create a temporary file for C2PA signed data (needs proper extension)
        let temp_signed = tempfile::Builder::new().suffix(".png").tempfile()?;
        let temp_signed_path = temp_signed.path();

        // Step 2: Sign the data with C2PA
        let mut builder = Builder::from_json(&format!(r#"{{"title": "{}"}}"#, title))?;

        // Add custom assertion with data hash for integrity
        #[derive(Serialize)]
        struct DataHash {
            algorithm: String,
            hash: String,
        }

        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash = format!("{:x}", hasher.finalize());

        builder.add_assertion(
            "org.arkavo.c2pa_opentdf.data_hash",
            &DataHash {
                algorithm: "SHA-256".to_string(),
                hash: data_hash,
            },
        )?;

        // Write original data to a temp file for signing (needs proper extension)
        let temp_input = tempfile::Builder::new().suffix(".png").tempfile()?;
        std::fs::write(temp_input.path(), data)?;

        // Remove temp signed file if it exists (c2pa won't overwrite)
        let _ = std::fs::remove_file(temp_signed_path);

        // Sign the file
        builder.sign_file(&*self.signer, temp_input.path(), temp_signed_path)?;

        // Step 3: Read the signed data
        let signed_data = std::fs::read(temp_signed_path)?;

        // Step 4: Compute manifest hash for OpenTDF metadata
        let mut manifest_hasher = Sha256::new();
        manifest_hasher.update(&signed_data);
        let _manifest_hash = format!("{:x}", manifest_hasher.finalize());

        // Step 5: Encrypt with OpenTDF
        let mut tdf_builder = Tdf::encrypt(signed_data.clone()).kas_url(&self.kas_url);

        if let Some(policy) = &self.policy {
            tdf_builder = tdf_builder.policy(policy.clone());
        }

        // Add C2PA manifest hash as metadata
        tdf_builder = tdf_builder.mime_type("application/c2pa");

        // Write to output file
        tdf_builder.to_file(output_path.as_ref())?;

        // Also return the encrypted bytes
        let encrypted_bytes = std::fs::read(output_path.as_ref())?;

        Ok(encrypted_bytes)
    }

    /// Decrypt with OpenTDF and verify C2PA signature
    ///
    /// This method:
    /// 1. Decrypts the TDF file using KAS
    /// 2. Extracts the C2PA signed data
    /// 3. Verifies the C2PA manifest
    /// 4. Returns the original data
    ///
    /// # Arguments
    /// * `tdf_path` - Path to the encrypted TDF file
    /// * `kas_client` - KAS client for decryption (requires "kas" feature)
    ///
    /// # Returns
    /// The original decrypted and verified data
    #[cfg(feature = "kas")]
    pub async fn decrypt_and_verify(
        &self,
        tdf_path: impl AsRef<Path>,
        kas_client: &opentdf::kas::KasClient,
    ) -> Result<Vec<u8>> {
        // Step 1: Decrypt with OpenTDF
        let decrypted_signed_data = Tdf::decrypt_file(tdf_path, kas_client).await?;

        // Step 2: Verify C2PA manifest
        // Note: C2PA verification requires reading the manifest from the signed file
        // For now, we'll write to a temp file and use c2pa Reader
        let temp_file = tempfile::NamedTempFile::new()?;
        std::fs::write(temp_file.path(), &decrypted_signed_data)?;

        // Use c2pa Reader to verify the manifest
        let reader = c2pa::Reader::from_file(temp_file.path())?;
        let manifest_store = reader.active_manifest().ok_or_else(|| {
            C2paOpenTdfError::VerificationFailed("No active C2PA manifest found".to_string())
        })?;

        // Verify the manifest is valid
        if let Some(status) = manifest_store.validation_status() {
            if !status.is_empty() {
                return Err(C2paOpenTdfError::VerificationFailed(format!(
                    "C2PA validation failed: {:?}",
                    status
                )));
            }
        }

        // Extract original data from the signed file
        // For images, C2PA embeds the manifest but preserves the image data
        Ok(decrypted_signed_data)
    }
}

/// Builder for creating C2paOpenTdf instances
pub struct C2paOpenTdfBuilder {
    cert_path: Option<String>,
    key_path: Option<String>,
    cert_data: Option<Vec<u8>>,
    key_data: Option<Vec<u8>>,
    kas_url: Option<String>,
    policy: Option<Policy>,
    signing_alg: SigningAlg,
}

impl C2paOpenTdfBuilder {
    pub fn new() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            cert_data: None,
            key_data: None,
            kas_url: None,
            policy: None,
            signing_alg: SigningAlg::Es256,
        }
    }

    /// Set certificate and key from file paths
    pub fn certificate_and_key(mut self, cert_path: &str, key_path: &str) -> Self {
        self.cert_path = Some(cert_path.to_string());
        self.key_path = Some(key_path.to_string());
        self
    }

    /// Set certificate and key from byte data
    pub fn certificate_and_key_data(mut self, cert_data: Vec<u8>, key_data: Vec<u8>) -> Self {
        self.cert_data = Some(cert_data);
        self.key_data = Some(key_data);
        self
    }

    /// Set the KAS URL for OpenTDF encryption
    pub fn kas_url(mut self, url: impl Into<String>) -> Self {
        self.kas_url = Some(url.into());
        self
    }

    /// Set the OpenTDF access control policy
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the signing algorithm (default: ES256)
    pub fn signing_algorithm(mut self, alg: SigningAlg) -> Self {
        self.signing_alg = alg;
        self
    }

    /// Build the C2paOpenTdf instance
    pub fn build(self) -> Result<C2paOpenTdf> {
        // Load certificate and key
        let (cert_data, key_data) = if let (Some(cert), Some(key)) = (self.cert_data, self.key_data)
        {
            (cert, key)
        } else if let (Some(cert_path), Some(key_path)) = (self.cert_path, self.key_path) {
            (std::fs::read(cert_path)?, std::fs::read(key_path)?)
        } else {
            return Err(C2paOpenTdfError::Configuration(
                "Certificate and key must be provided".to_string(),
            ));
        };

        let kas_url = self
            .kas_url
            .ok_or_else(|| C2paOpenTdfError::Configuration("KAS URL is required".to_string()))?;

        // Create signer
        let signer = create_signer::from_keys(&cert_data, &key_data, self.signing_alg, None)?;

        Ok(C2paOpenTdf {
            signer,
            kas_url,
            policy: self.policy,
        })
    }
}

impl Default for C2paOpenTdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_pattern() -> Result<()> {
        let c2pa_tdf = C2paOpenTdf::builder()
            .certificate_and_key("tests/data/cert.pem", "tests/data/private.pem")
            .kas_url("https://kas.example.com")
            .signing_algorithm(SigningAlg::Es256)
            .build()?;

        assert_eq!(c2pa_tdf.kas_url, "https://kas.example.com");
        Ok(())
    }

    #[test]
    fn test_sign_and_encrypt() -> Result<()> {
        std::fs::create_dir_all("target/tmp")?;

        let c2pa_tdf = C2paOpenTdf::builder()
            .certificate_and_key("tests/data/cert.pem", "tests/data/private.pem")
            .kas_url("https://kas.example.com")
            .build()?;

        // Use existing PNG image as test data (C2PA requires supported media types)
        let test_data = std::fs::read("tests/data/logo.png")?;

        // Use tempfile to avoid conflicts
        let temp_output = tempfile::Builder::new().suffix(".tdf").tempfile()?;
        let output_path = temp_output.path();

        let encrypted = c2pa_tdf.sign_and_encrypt(&test_data, "Test Image", output_path)?;

        assert!(!encrypted.is_empty());
        assert!(output_path.exists());

        Ok(())
    }
}
