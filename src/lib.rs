pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works_too() {
        let result = add(2, 2);
        assert_eq!(result, 4);}

    #[test]
    fn it_works() -> Result<(), Box<dyn std::error::Error>> {
        use c2pa::{create_signer, Builder, SigningAlg};
        use serde::Serialize;

        #[derive(Serialize)]
        struct Test {
            my_tag: usize,
        }
        let signer = create_signer::from_keys(
            &std::fs::read("tests/data/cert.pem")?,      // read certificate
            &std::fs::read("tests/data/private.pem")?,   // read private key
            SigningAlg::Es256,                // ECDSA with SHA-256
            None,                             // no timestamp authority
        )?;
        let mut builder = Builder::from_json(r#"{"title": "Test"}"#)?;
        builder.add_assertion("org.arkavo.test", &Test { my_tag: 42 })?;
        std::fs::remove_file("target/tmp/logo_sign.png")?;
        // embed a manifest using the signer
        builder.sign_file(
            &*signer,
            "tests/data/logo.png",
            "target/tmp/logo_sign.png",
        )?;        Ok(())
        }
}
