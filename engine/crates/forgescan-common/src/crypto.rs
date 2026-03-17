//! Cryptographic utilities for ForgeScan

use forgescan_core::{Error, Result};
use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of data
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash and return as hex string
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Verify a SHA-256 checksum
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> bool {
    sha256_hex(data).eq_ignore_ascii_case(expected_hex)
}

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed_cert(
    common_name: &str,
    _validity_days: u32,
) -> Result<(String, String)> {
    use rcgen::generate_simple_self_signed;

    let subject_alt_names = vec![common_name.to_string()];

    let cert = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| Error::Internal(format!("Failed to generate certificate: {}", e)))?;

    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| Error::Internal(format!("Failed to serialize certificate: {}", e)))?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem, key_pem))
}

/// Generate a certificate signing request (CSR)
pub fn generate_csr(common_name: &str) -> Result<(String, String)> {
    use rcgen::{Certificate, CertificateParams, KeyPair};

    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Internal(format!("Failed to generate key pair: {}", e)))?;

    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String(common_name.to_string()),
    );
    params.key_pair = Some(key_pair);

    let cert = Certificate::from_params(params)
        .map_err(|e| Error::Internal(format!("Failed to create certificate params: {}", e)))?;

    let csr_pem = cert
        .serialize_request_pem()
        .map_err(|e| Error::Internal(format!("Failed to serialize CSR: {}", e)))?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((csr_pem, key_pem))
}

/// Load a PEM-encoded certificate
pub fn load_certificate(pem: &str) -> Result<Vec<u8>> {
    let pem_parsed = pem::parse(pem)
        .map_err(|e| Error::Configuration(format!("Invalid PEM certificate: {}", e)))?;
    Ok(pem_parsed.contents().to_vec())
}

/// Load a PEM-encoded private key
pub fn load_private_key(pem: &str) -> Result<Vec<u8>> {
    let pem_parsed = pem::parse(pem)
        .map_err(|e| Error::Configuration(format!("Invalid PEM private key: {}", e)))?;
    Ok(pem_parsed.contents().to_vec())
}

/// Generate a random UUID-based identifier
pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a random API key (32 bytes, hex encoded = 64 chars)
pub fn generate_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256_hex(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_sha256() {
        let data = b"test data";
        let hash = sha256_hex(data);
        assert!(verify_sha256(data, &hash));
        assert!(!verify_sha256(data, "invalid"));
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let (cert, key) = generate_self_signed_cert("test.local", 365).unwrap();
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(key.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_id() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36); // UUID format
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hex_format() {
        let hash = sha256_hex(b"some data");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_sha256_case_insensitive() {
        let data = b"case test";
        let hash = sha256_hex(data);
        let upper = hash.to_uppercase();
        assert!(verify_sha256(data, &upper));
    }

    #[test]
    fn test_generate_api_key() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();

        assert_eq!(key1.len(), 64);
        assert!(key1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_load_certificate() {
        let (cert_pem, _key_pem) = generate_self_signed_cert("test.local", 1).unwrap();
        let cert_bytes = load_certificate(&cert_pem).unwrap();
        assert!(!cert_bytes.is_empty());
    }

    #[test]
    fn test_load_private_key() {
        let (_cert_pem, key_pem) = generate_self_signed_cert("test.local", 1).unwrap();
        let key_bytes = load_private_key(&key_pem).unwrap();
        assert!(!key_bytes.is_empty());
    }
}
