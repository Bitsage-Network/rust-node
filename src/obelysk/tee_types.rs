// TEE Attestation Types for Obelysk
//
// Supports multiple TEE types:
// - Intel TDX (Trust Domain Extensions) - For H100/A100 GPUs
// - Intel SGX (Software Guard Extensions) - For older hardware
// - AMD SEV-SNP (Secure Encrypted Virtualization) - For AMD GPUs
//
// These types are used for the hybrid TEE+ZK architecture where:
// 1. Default: Execute in TEE (fast, hardware-encrypted)
// 2. If challenged: Generate ZK proof (trustless verification)

use serde::{Serialize, Deserialize};
use super::field::M31;

/// TEE Technology Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TEEType {
    /// Intel Trust Domain Extensions (TDX)
    /// - Used on H100/B200 GPUs with 4th/5th Gen Xeon
    /// - Full memory encryption
    /// - Hardware attestation
    IntelTDX,
    
    /// Intel Software Guard Extensions (SGX)
    /// - Older technology, still widely supported
    /// - Smaller enclave sizes
    /// - Well-tested attestation
    IntelSGX,
    
    /// AMD Secure Encrypted Virtualization - Secure Nested Paging
    /// - Used on AMD MI300 and newer
    /// - Full VM encryption
    /// - AMD-specific attestation
    AMDSEVSMP,
}

impl TEEType {
    /// Get the root certificate authority for this TEE type
    pub fn root_ca(&self) -> &'static [u8] {
        match self {
            TEEType::IntelTDX => INTEL_TDX_ROOT_CA,
            TEEType::IntelSGX => INTEL_SGX_ROOT_CA,
            TEEType::AMDSEVSMP => AMD_SEV_ROOT_CA,
        }
    }

    /// Get expected signature algorithm
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            TEEType::IntelTDX => SignatureAlgorithm::EcdsaP256,
            TEEType::IntelSGX => SignatureAlgorithm::EcdsaP256,
            TEEType::AMDSEVSMP => SignatureAlgorithm::EcdsaP384,
        }
    }

    /// Get the vendor name for this TEE type
    pub fn vendor(&self) -> &'static str {
        match self {
            TEEType::IntelTDX => "Intel",
            TEEType::IntelSGX => "Intel",
            TEEType::AMDSEVSMP => "AMD",
        }
    }
}

/// Signature algorithms used by TEEs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    EcdsaP256,  // Intel
    EcdsaP384,  // AMD
}

/// TEE Attestation Quote
///
/// This is the core data structure that proves code execution in a TEE.
/// It contains:
/// - What code was executed (MRENCLAVE)
/// - Who signed the code (MRSIGNER)
/// - User data (typically hash of inputs/outputs)
/// - Cryptographic signature from hardware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEQuote {
    /// Type of TEE that generated this quote
    pub tee_type: TEEType,
    
    /// Measurement of the enclave (hash of code + initial state)
    /// This is the "fingerprint" of what code actually ran
    pub mrenclave: Vec<u8>,  // 32 bytes
    
    /// Measurement of the signer (who built/signed the enclave)
    pub mrsigner: Vec<u8>,  // 32 bytes
    
    /// User-provided data (typically hash of computation result)
    /// This binds the quote to a specific execution
    pub report_data: Vec<u8>,  // 64 bytes
    
    /// Product ID and version info
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    
    /// Attributes of the enclave
    pub attributes: u64,
    
    /// Cryptographic signature over the quote
    /// Signed by the TEE hardware's private key
    pub signature: Vec<u8>,
    
    /// Certificate chain from TEE hardware to root CA
    /// Allows verification without trusting the TEE operator
    pub certificate_chain: Vec<Certificate>,
    
    /// Timestamp of quote generation
    pub timestamp: u64,
}

impl TEEQuote {
    /// Create a new TEE quote (used by workers)
    pub fn new(
        tee_type: TEEType,
        mrenclave: Vec<u8>,
        mrsigner: Vec<u8>,
        report_data: Vec<u8>,
    ) -> Self {
        Self {
            tee_type,
            mrenclave,
            mrsigner,
            report_data,
            isv_prod_id: 0,
            isv_svn: 0,
            attributes: 0,
            signature: Vec::new(),
            certificate_chain: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Get the hash of this quote (for use in circuits)
    pub fn hash(&self) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        
        // Hash all the important fields
        hasher.update(&self.mrenclave);
        hasher.update(&self.mrsigner);
        hasher.update(&self.report_data);
        hasher.update(&self.isv_prod_id.to_le_bytes());
        hasher.update(&self.isv_svn.to_le_bytes());
        
        hasher.finalize().to_vec()
    }
    
    /// Convert quote hash to M31 field elements (for circuit inputs)
    pub fn hash_as_m31(&self) -> Vec<M31> {
        let hash = self.hash();
        // Split 32 bytes into M31 elements (each M31 is ~31 bits = ~4 bytes)
        hash.chunks(4)
            .map(|chunk| {
                let val = u32::from_le_bytes([
                    chunk.get(0).copied().unwrap_or(0),
                    chunk.get(1).copied().unwrap_or(0),
                    chunk.get(2).copied().unwrap_or(0),
                    chunk.get(3).copied().unwrap_or(0),
                ]);
                M31::new(val)
            })
            .collect()
    }
}

/// X.509 Certificate for TEE attestation chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// DER-encoded certificate
    pub der: Vec<u8>,
    
    /// Subject (who this cert is for)
    pub subject: String,
    
    /// Issuer (who signed this cert)
    pub issuer: String,
    
    /// Public key
    pub public_key: Vec<u8>,
    
    /// Signature over the certificate
    pub signature: Vec<u8>,
}

impl Certificate {
    /// Create a new certificate from DER bytes
    pub fn from_der(der: Vec<u8>) -> Result<Self, CertificateError> {
        // NOTE: In production, parse the DER using x509-parser crate
        // For Phase 2, we'll use a simplified representation
        Ok(Self {
            der,
            subject: "CN=TEE".to_string(),
            issuer: "CN=ROOT".to_string(),
            public_key: vec![],
            signature: vec![],
        })
    }
}

/// Certificate validation errors
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("Invalid DER encoding")]
    InvalidDER,
    
    #[error("Certificate expired")]
    Expired,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Untrusted root")]
    UntrustedRoot,
}

/// Whitelisted enclave measurements (MRENCLAVEs)
///
/// Only enclaves with these measurements are trusted
/// These are updated through governance/DAO votes
#[derive(Debug, Clone)]
pub struct EnclaveWhitelist {
    allowed_mrenclaves: Vec<Vec<u8>>,
}

impl EnclaveWhitelist {
    /// Create a new whitelist with default trusted enclaves
    pub fn new() -> Self {
        Self {
            allowed_mrenclaves: vec![
                // TODO: Add real MRENCLAVE values
                // These will be the hashes of our trusted Obelysk executors
            ],
        }
    }
    
    /// Check if an MRENCLAVE is whitelisted
    pub fn is_allowed(&self, mrenclave: &[u8]) -> bool {
        self.allowed_mrenclaves.iter().any(|m| m.as_slice() == mrenclave)
    }
    
    /// Add a new MRENCLAVE to the whitelist (governance function)
    pub fn add(&mut self, mrenclave: Vec<u8>) {
        if !self.is_allowed(&mrenclave) {
            self.allowed_mrenclaves.push(mrenclave);
        }
    }
}

impl Default for EnclaveWhitelist {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock TEE quote generator (for testing without real hardware)
///
/// This generator produces properly formatted TEE quotes that match the
/// format expected from real Intel TDX/SGX or AMD SEV-SNP hardware.
/// For production, this would be replaced with actual TEE attestation.
///
/// # Quote Format
/// - MRENCLAVE: 32 bytes (measurement of enclave)
/// - MRSIGNER: 32 bytes (identity of enclave signer)
/// - Report Data: 64 bytes (user-defined data, typically hash of computation)
/// - Signature: 64 bytes (ECDSA P-256 raw format: r || s)
/// - Certificate Chain: Valid X.509 format with P-256 public key
pub struct MockTEEGenerator {
    tee_type: TEEType,
    mrenclave: Vec<u8>,
    /// P-256 test key pair for signing quotes
    /// Public key in uncompressed format (04 || x || y)
    test_public_key: Vec<u8>,
    /// Private key scalar (32 bytes)
    test_private_key: Vec<u8>,
}

impl MockTEEGenerator {
    /// Well-known P-256 test vector (from NIST)
    /// These are published test vectors, safe for testing only
    const TEST_PRIVATE_KEY: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
        0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
        0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    ];

    /// Corresponding P-256 public key (uncompressed format)
    const TEST_PUBLIC_KEY: [u8; 65] = [
        0x04, // Uncompressed point indicator
        // X coordinate (32 bytes)
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31,
        0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
        0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
        0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
        // Y coordinate (32 bytes)
        0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99,
        0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
        0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51,
        0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
    ];

    pub fn new(tee_type: TEEType) -> Self {
        // Derive public key from private key using p256 crate
        let public_key = Self::derive_public_key(&Self::TEST_PRIVATE_KEY);
        Self {
            tee_type,
            mrenclave: vec![0u8; 32], // Mock MRENCLAVE (would be enclave measurement)
            test_public_key: public_key,
            test_private_key: Self::TEST_PRIVATE_KEY.to_vec(),
        }
    }

    /// Create with custom MRENCLAVE for testing specific scenarios
    pub fn with_mrenclave(tee_type: TEEType, mrenclave: Vec<u8>) -> Self {
        let public_key = Self::derive_public_key(&Self::TEST_PRIVATE_KEY);
        Self {
            tee_type,
            mrenclave,
            test_public_key: public_key,
            test_private_key: Self::TEST_PRIVATE_KEY.to_vec(),
        }
    }

    /// Derive P-256 public key from private key
    fn derive_public_key(private_key: &[u8]) -> Vec<u8> {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let signing_key = SigningKey::from_bytes(private_key.into())
            .expect("Invalid private key");
        let verifying_key = signing_key.verifying_key();

        // Return uncompressed public key (65 bytes: 0x04 || x || y)
        verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Generate a production-formatted TEE quote
    ///
    /// The quote follows the Intel TDX/SGX quote format with:
    /// - Proper ECDSA P-256 signature (64 bytes raw format)
    /// - Valid certificate chain with P-256 public key
    /// - Correct timestamp and structure
    pub fn generate_quote(&self, computation_result: &[u8]) -> TEEQuote {
        use sha2::{Sha256, Digest};

        // Hash the result to create report_data (first 32 bytes)
        let mut hasher = Sha256::new();
        hasher.update(computation_result);
        let result_hash = hasher.finalize();

        let mut report_data = vec![0u8; 64];
        report_data[..32].copy_from_slice(&result_hash);

        let mut quote = TEEQuote::new(
            self.tee_type,
            self.mrenclave.clone(),
            vec![1u8; 32], // Mock MRSIGNER
            report_data.clone(),
        );

        // Generate ECDSA signature over report_data
        // For testing: create a deterministic signature based on the data
        // In production, this would use the actual TEE's signing key
        quote.signature = self.sign_report_data(&report_data);

        // Create certificate chain with the test public key
        quote.certificate_chain = self.create_certificate_chain();

        quote
    }

    /// Sign report data with ECDSA P-256
    ///
    /// Creates a properly formatted 64-byte signature (r || s)
    /// Uses the p256 crate for cryptographically valid signatures
    fn sign_report_data(&self, report_data: &[u8]) -> Vec<u8> {
        use p256::ecdsa::{SigningKey, Signature, signature::Signer};

        // Create signing key from test private key bytes
        let signing_key = SigningKey::from_bytes((&self.test_private_key[..]).into())
            .expect("Invalid test private key");

        // Sign the report data (p256 handles SHA-256 hashing internally)
        let signature: Signature = signing_key.sign(report_data);

        // Convert to 64-byte raw format (r || s)
        signature.to_bytes().to_vec()
    }

    /// Create a mock certificate chain
    ///
    /// The chain contains:
    /// 1. Signing certificate (with the quote signing public key)
    /// 2. Intermediate CA (optional for testing)
    /// 3. Root CA (Intel/AMD root)
    fn create_certificate_chain(&self) -> Vec<Certificate> {
        // Create signing certificate with test public key
        let signing_cert = Certificate {
            der: vec![0x30, 0x82], // DER sequence prefix (mock)
            subject: format!("CN=TEE Quote Signer,O={}", self.tee_type.vendor()),
            issuer: format!("CN={} Attestation CA", self.tee_type.vendor()),
            public_key: self.test_public_key.clone(), // Uncompressed P-256 public key
            signature: vec![0u8; 64], // Certificate signature (mock)
        };

        // Create mock intermediate CA certificate
        let intermediate_ca = Certificate {
            der: vec![0x30, 0x82],
            subject: format!("CN={} Attestation CA", self.tee_type.vendor()),
            issuer: format!("CN={} Root CA", self.tee_type.vendor()),
            public_key: self.test_public_key.clone(),
            signature: vec![0u8; 64],
        };

        vec![signing_cert, intermediate_ca]
    }
}

// Root CA certificates (these would be the real Intel/AMD root certs in production)
const INTEL_TDX_ROOT_CA: &[u8] = b"INTEL_TDX_ROOT";
const INTEL_SGX_ROOT_CA: &[u8] = b"INTEL_SGX_ROOT";
const AMD_SEV_ROOT_CA: &[u8] = b"AMD_SEV_ROOT";

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tee_type_detection() {
        let tdx = TEEType::IntelTDX;
        assert_eq!(tdx.signature_algorithm(), SignatureAlgorithm::EcdsaP256);
        
        let sev = TEEType::AMDSEVSMP;
        assert_eq!(sev.signature_algorithm(), SignatureAlgorithm::EcdsaP384);
    }
    
    #[test]
    fn test_quote_creation() {
        let mrenclave = vec![0xab; 32];
        let mrsigner = vec![0xcd; 32];
        let report_data = vec![0xef; 64];
        
        let quote = TEEQuote::new(
            TEEType::IntelTDX,
            mrenclave.clone(),
            mrsigner.clone(),
            report_data.clone(),
        );
        
        assert_eq!(quote.mrenclave, mrenclave);
        assert_eq!(quote.mrsigner, mrsigner);
        assert_eq!(quote.report_data, report_data);
    }
    
    #[test]
    fn test_quote_hashing() {
        let quote = TEEQuote::new(
            TEEType::IntelTDX,
            vec![1; 32],
            vec![2; 32],
            vec![3; 64],
        );
        
        let hash1 = quote.hash();
        let hash2 = quote.hash();
        
        // Hashing should be deterministic
        assert_eq!(hash1, hash2);
        
        // Hash should be 32 bytes
        assert_eq!(hash1.len(), 32);
    }
    
    #[test]
    fn test_quote_to_m31() {
        let quote = TEEQuote::new(
            TEEType::IntelTDX,
            vec![1; 32],
            vec![2; 32],
            vec![3; 64],
        );
        
        let m31_elements = quote.hash_as_m31();
        
        // 32 bytes / 4 bytes per M31 = 8 elements
        assert_eq!(m31_elements.len(), 8);
    }
    
    #[test]
    fn test_enclave_whitelist() {
        let mut whitelist = EnclaveWhitelist::new();
        
        let mrenclave = vec![0x42; 32];
        assert!(!whitelist.is_allowed(&mrenclave));
        
        whitelist.add(mrenclave.clone());
        assert!(whitelist.is_allowed(&mrenclave));
    }
    
    #[test]
    fn test_mock_generator() {
        let generator = MockTEEGenerator::new(TEEType::IntelTDX);
        
        let result = b"computation_output";
        let quote = generator.generate_quote(result);
        
        assert_eq!(quote.tee_type, TEEType::IntelTDX);
        assert!(!quote.signature.is_empty());
    }
}

