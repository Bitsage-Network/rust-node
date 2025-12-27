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
pub struct MockTEEGenerator {
    tee_type: TEEType,
    mrenclave: Vec<u8>,
}

impl MockTEEGenerator {
    pub fn new(tee_type: TEEType) -> Self {
        Self {
            tee_type,
            mrenclave: vec![0u8; 32], // Mock MRENCLAVE
        }
    }
    
    /// Generate a mock quote for testing
    pub fn generate_quote(&self, computation_result: &[u8]) -> TEEQuote {
        use sha2::{Sha256, Digest};
        
        // Hash the result to create report_data
        let mut hasher = Sha256::new();
        hasher.update(computation_result);
        let result_hash = hasher.finalize();
        
        let mut report_data = vec![0u8; 64];
        report_data[..32].copy_from_slice(&result_hash);
        
        let mut quote = TEEQuote::new(
            self.tee_type,
            self.mrenclave.clone(),
            vec![1u8; 32], // Mock MRSIGNER
            report_data,
        );
        
        // Generate mock signature
        quote.signature = vec![0xde, 0xad, 0xbe, 0xef]; // Mock signature
        
        quote
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

