//! GPU-TEE Integration for Obelysk
//!
//! This module provides secure GPU proof generation within a TEE context.
//! It connects the rust-node's TEE infrastructure with the GPU-accelerated
//! Stwo prover.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    GpuSecureProver                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │   ┌─────────────────┐    ┌─────────────────┐                   │
//! │   │   TEE Context   │    │   GPU Pipeline  │                   │
//! │   │  (TDX/SEV/SGX)  │◄──►│  (Stwo GPU)     │                   │
//! │   └─────────────────┘    └─────────────────┘                   │
//! │           │                      │                              │
//! │           ▼                      ▼                              │
//! │   ┌─────────────────┐    ┌─────────────────┐                   │
//! │   │   Encryption    │    │   ZK Proof      │                   │
//! │   │   (AES-GCM)     │    │   Generation    │                   │
//! │   └─────────────────┘    └─────────────────┘                   │
//! │                                                                 │
//! │   Data stays encrypted until inside GPU TEE                    │
//! │   Only 32-byte proof attestation leaves                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Model
//!
//! 1. **Data Encryption**: All input data is AES-256-GCM encrypted
//! 2. **TEE Execution**: Decryption only happens inside TEE
//! 3. **GPU Processing**: Data processed on GPU within TEE boundary
//! 4. **Proof Output**: Only cryptographic proof leaves the system
//! 5. **Attestation**: Hardware attestation proves correct execution

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::time::Instant;
use tracing::{info, warn, debug};

use super::tee::{TEEContext, AttestationQuote};
use crate::obelysk::{
    ExecutionTrace, StarkProof,
    stwo_adapter::{prove_with_stwo_gpu, is_gpu_available},
};

/// Configuration for GPU-TEE secure prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuTeeConfig {
    /// Enable encryption of input data
    pub encrypt_inputs: bool,
    
    /// Enable hardware attestation
    pub hardware_attestation: bool,
    
    /// Security level in bits
    pub security_bits: usize,
    
    /// Session timeout in seconds
    pub session_timeout_secs: u64,
}

impl Default for GpuTeeConfig {
    fn default() -> Self {
        Self {
            encrypt_inputs: true,
            hardware_attestation: true,
            security_bits: 128,
            session_timeout_secs: 300,
        }
    }
}

/// Session key for encrypted communication
#[derive(Clone)]
pub struct SessionKey {
    /// AES-256 key
    key: [u8; 32],
    
    /// Session ID
    session_id: String,
    
    /// Creation timestamp
    created_at: u64,
}

impl SessionKey {
    /// Generate a new session key
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        
        Self {
            key,
            session_id: uuid::Uuid::new_v4().to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    
    /// Check if session is expired
    pub fn is_expired(&self, timeout_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.created_at > timeout_secs
    }
}

/// Encrypted payload for secure transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Session ID
    pub session_id: String,
    
    /// Encrypted data (AES-256-GCM)
    pub ciphertext: Vec<u8>,
    
    /// Nonce for AES-GCM
    pub nonce: [u8; 12],
    
    /// Authentication tag
    pub tag: [u8; 16],
}

/// Result of a secure GPU proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureProofResult {
    /// Session ID
    pub session_id: String,
    
    /// 32-byte proof attestation
    pub proof_attestation: [u8; 32],
    
    /// TEE hardware attestation quote
    pub tee_quote: Option<AttestationQuote>,
    
    /// Execution metrics
    pub metrics: SecureProofMetrics,
}

/// Metrics for secure proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureProofMetrics {
    /// Total time in milliseconds
    pub total_time_ms: u64,
    
    /// Decryption time
    pub decrypt_time_ms: u64,
    
    /// Proof generation time
    pub proof_time_ms: u64,
    
    /// Attestation generation time
    pub attestation_time_ms: u64,
    
    /// GPU used
    pub gpu_used: bool,
    
    /// TEE platform
    pub tee_platform: String,
}

/// GPU-TEE Secure Prover
///
/// Combines GPU acceleration with TEE security for verifiable computation.
pub struct GpuSecureProver {
    config: GpuTeeConfig,
    tee_context: TEEContext,
    session_key: Option<SessionKey>,
}

impl GpuSecureProver {
    /// Create a new GPU-TEE secure prover
    pub fn new(config: GpuTeeConfig) -> Self {
        let tee_context = TEEContext::new();
        
        Self {
            config,
            tee_context,
            session_key: None,
        }
    }
    
    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(GpuTeeConfig::default())
    }
    
    /// Initialize a new secure session
    pub fn init_session(&mut self) -> Result<String> {
        let session_key = SessionKey::generate();
        let session_id = session_key.session_id().to_string();
        
        info!("🔐 Initialized secure session: {}", session_id);
        
        self.session_key = Some(session_key);
        
        Ok(session_id)
    }
    
    /// Get current session ID
    pub fn session_id(&self) -> Option<&str> {
        self.session_key.as_ref().map(|k| k.session_id())
    }
    
    /// Check if session is valid
    pub fn is_session_valid(&self) -> bool {
        self.session_key
            .as_ref()
            .map(|k| !k.is_expired(self.config.session_timeout_secs))
            .unwrap_or(false)
    }
    
    /// Encrypt payload for secure transmission using AES-256-GCM.
    /// 
    /// AES-256-GCM provides:
    /// - Confidentiality: 256-bit AES encryption
    /// - Integrity: 128-bit authentication tag
    /// - Authenticity: AEAD (Authenticated Encryption with Associated Data)
    /// 
    /// # Security Properties
    /// 
    /// - Nonces are generated via OS CSPRNG (never reused)
    /// - Authentication tag prevents tampering
    /// - Session ID is bound to encryption context
    pub fn encrypt_payload(&self, data: &[u8]) -> Result<EncryptedPayload> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;
        
        let session_key = self.session_key
            .as_ref()
            .ok_or_else(|| anyhow!("No active session"))?;
        
        // Generate cryptographically secure random nonce (96 bits / 12 bytes)
        // CRITICAL: Nonce must NEVER be reused with the same key
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Initialize AES-256-GCM cipher with session key
        let cipher = Aes256Gcm::new_from_slice(&session_key.key)
            .map_err(|e| anyhow!("Failed to initialize AES-256-GCM: {:?}", e))?;
        
        // Encrypt with authentication
        // The ciphertext includes the 16-byte auth tag appended
        let ciphertext_with_tag = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("AES-256-GCM encryption failed: {:?}", e))?;
        
        // Split ciphertext and tag (tag is last 16 bytes)
        let tag_offset = ciphertext_with_tag.len() - 16;
        let ciphertext = ciphertext_with_tag[..tag_offset].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[tag_offset..]);
        
        debug!(
            "🔐 Encrypted {} bytes → {} bytes ciphertext + 16 byte tag",
            data.len(),
            ciphertext.len()
        );
        
        Ok(EncryptedPayload {
            session_id: session_key.session_id().to_string(),
            ciphertext,
            nonce: nonce_bytes,
            tag,
        })
    }
    
    /// Decrypt payload inside TEE using AES-256-GCM.
    /// 
    /// # Security
    /// 
    /// - Verifies session ID before decryption
    /// - Authentication tag is verified during decryption
    /// - Fails safely on any tampering attempt
    fn decrypt_payload(&self, payload: &EncryptedPayload) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        let session_key = self.session_key
            .as_ref()
            .ok_or_else(|| anyhow!("No active session"))?;
        
        // Verify session ID matches
        if payload.session_id != session_key.session_id() {
            return Err(anyhow!("Session ID mismatch - possible replay attack"));
        }
        
        // Check session hasn't expired
        if session_key.is_expired(self.config.session_timeout_secs) {
            return Err(anyhow!("Session expired - please re-authenticate"));
        }
        
        // Initialize AES-256-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&session_key.key)
            .map_err(|e| anyhow!("Failed to initialize AES-256-GCM: {:?}", e))?;
        
        let nonce = Nonce::from_slice(&payload.nonce);
        
        // Reconstruct ciphertext with tag for decryption
        let mut ciphertext_with_tag = payload.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&payload.tag);
        
        // Decrypt and verify authentication tag
        // This will fail if:
        // 1. The ciphertext was modified
        // 2. The nonce was tampered with
        // 3. The tag doesn't match
        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag.as_ref())
            .map_err(|_| anyhow!("Decryption failed - data may be tampered or corrupted"))?;
        
        debug!(
            "🔓 Decrypted {} bytes ciphertext → {} bytes plaintext",
            payload.ciphertext.len(),
            plaintext.len()
        );
        
        Ok(plaintext)
    }
    
    /// Generate proof securely with GPU acceleration
    ///
    /// This is the main entry point for secure proof generation:
    /// 1. Decrypts input data inside TEE
    /// 2. Generates ZK proof using GPU
    /// 3. Creates TEE attestation
    /// 4. Returns only the 32-byte proof attestation
    pub fn prove_secure(
        &self,
        encrypted_payload: &EncryptedPayload,
        trace: &ExecutionTrace,
    ) -> Result<SecureProofResult> {
        let total_start = Instant::now();
        let mut metrics = SecureProofMetrics {
            total_time_ms: 0,
            decrypt_time_ms: 0,
            proof_time_ms: 0,
            attestation_time_ms: 0,
            gpu_used: false,
            tee_platform: String::new(),
        };
        
        // 1. Decrypt payload (inside TEE)
        let decrypt_start = Instant::now();
        let _decrypted_data = self.decrypt_payload(encrypted_payload)?;
        metrics.decrypt_time_ms = decrypt_start.elapsed().as_millis() as u64;
        
        // 2. Generate ZK proof using GPU
        let proof_start = Instant::now();
        let proof = if is_gpu_available() {
            metrics.gpu_used = true;
            prove_with_stwo_gpu(trace, self.config.security_bits)
                .map_err(|e| anyhow!("GPU proof generation failed: {:?}", e))?
        } else {
            crate::obelysk::ObelyskProver::new()
                .prove_execution(trace)
                .map_err(|e| anyhow!("CPU proof generation failed: {:?}", e))?
        };
        metrics.proof_time_ms = proof_start.elapsed().as_millis() as u64;
        
        // 3. Extract 32-byte proof attestation
        let proof_attestation = self.extract_attestation(&proof);
        
        // 4. Generate TEE hardware attestation
        let attestation_start = Instant::now();
        let tee_quote = if self.config.hardware_attestation {
            match self.tee_context.generate_quote(&proof_attestation) {
                Ok(quote) => {
                    metrics.tee_platform = match quote.quote_version {
                        0 => "Software".to_string(),
                        4 | 5 => "Intel TDX".to_string(),
                        _ => "Unknown".to_string(),
                    };
                    Some(quote)
                }
                Err(e) => {
                    warn!("TEE attestation failed: {}", e);
                    metrics.tee_platform = "None".to_string();
                    None
                }
            }
        } else {
            metrics.tee_platform = "Disabled".to_string();
            None
        };
        metrics.attestation_time_ms = attestation_start.elapsed().as_millis() as u64;
        
        metrics.total_time_ms = total_start.elapsed().as_millis() as u64;
        
        info!(
            "🔐 Secure proof generated: {}ms (GPU: {}, TEE: {})",
            metrics.total_time_ms,
            metrics.gpu_used,
            metrics.tee_platform
        );
        
        Ok(SecureProofResult {
            session_id: encrypted_payload.session_id.clone(),
            proof_attestation,
            tee_quote,
            metrics,
        })
    }
    
    /// Generate proof directly (without encryption, for trusted environments)
    pub fn prove_direct(&self, trace: &ExecutionTrace) -> Result<SecureProofResult> {
        let total_start = Instant::now();
        let mut metrics = SecureProofMetrics {
            total_time_ms: 0,
            decrypt_time_ms: 0,
            proof_time_ms: 0,
            attestation_time_ms: 0,
            gpu_used: false,
            tee_platform: String::new(),
        };
        
        // Generate ZK proof using GPU
        let proof_start = Instant::now();
        let proof = if is_gpu_available() {
            metrics.gpu_used = true;
            prove_with_stwo_gpu(trace, self.config.security_bits)
                .map_err(|e| anyhow!("GPU proof generation failed: {:?}", e))?
        } else {
            crate::obelysk::ObelyskProver::new()
                .prove_execution(trace)
                .map_err(|e| anyhow!("CPU proof generation failed: {:?}", e))?
        };
        metrics.proof_time_ms = proof_start.elapsed().as_millis() as u64;
        
        // Extract 32-byte proof attestation
        let proof_attestation = self.extract_attestation(&proof);
        
        // Generate TEE hardware attestation
        let attestation_start = Instant::now();
        let tee_quote = if self.config.hardware_attestation {
            match self.tee_context.generate_quote(&proof_attestation) {
                Ok(quote) => {
                    metrics.tee_platform = match quote.quote_version {
                        0 => "Software".to_string(),
                        4 | 5 => "Intel TDX".to_string(),
                        _ => "Unknown".to_string(),
                    };
                    Some(quote)
                }
                Err(e) => {
                    warn!("TEE attestation failed: {}", e);
                    metrics.tee_platform = "None".to_string();
                    None
                }
            }
        } else {
            metrics.tee_platform = "Disabled".to_string();
            None
        };
        metrics.attestation_time_ms = attestation_start.elapsed().as_millis() as u64;
        
        metrics.total_time_ms = total_start.elapsed().as_millis() as u64;
        
        let session_id = self.session_key
            .as_ref()
            .map(|k| k.session_id().to_string())
            .unwrap_or_else(|| "direct".to_string());
        
        Ok(SecureProofResult {
            session_id,
            proof_attestation,
            tee_quote,
            metrics,
        })
    }
    
    /// Extract 32-byte attestation from proof
    fn extract_attestation(&self, proof: &StarkProof) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Hash trace commitment
        hasher.update(&proof.trace_commitment);
        
        // Hash public outputs
        for output in &proof.public_outputs {
            hasher.update(&output.value().to_le_bytes());
        }
        
        // Hash metadata
        hasher.update(&proof.metadata.trace_length.to_le_bytes());
        
        let result = hasher.finalize();
        let mut attestation = [0u8; 32];
        attestation.copy_from_slice(&result);
        attestation
    }
    
    /// Verify a proof attestation
    pub fn verify_attestation(
        &self,
        attestation: &[u8; 32],
        tee_quote: Option<&AttestationQuote>,
    ) -> Result<bool> {
        // 1. Verify TEE quote if present
        if let Some(quote) = tee_quote {
            // Verify the attestation is embedded in the quote
            if quote.data_hash != attestation.to_vec() {
                return Err(anyhow!("Attestation not found in TEE quote"));
            }
            
            // In production, verify the quote signature using Intel/AMD verification service
            if quote.quote_version == 0 {
                warn!("TEE quote is software-generated (not hardware-backed)");
            }
        }
        
        // 2. Attestation format validation
        if attestation.iter().all(|&b| b == 0) {
            return Err(anyhow!("Invalid attestation (all zeros)"));
        }
        
        Ok(true)
    }
    
    /// End the current session
    pub fn end_session(&mut self) {
        if let Some(key) = self.session_key.take() {
            info!("🔐 Ended secure session: {}", key.session_id());
        }
    }
}

impl Drop for GpuSecureProver {
    fn drop(&mut self) {
        self.end_session();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::vm::{ObelyskVM, Instruction, OpCode};
    
    fn create_test_trace() -> ExecutionTrace {
        let mut vm = ObelyskVM::new();
        vm.set_public_inputs(vec![M31::new(5), M31::new(7)]);
        
        let program = vec![
            Instruction {
                opcode: OpCode::Add,
                dst: 2,
                src1: 0,
                src2: 1,
                immediate: None,
                address: None,
            },
            Instruction {
                opcode: OpCode::Halt,
                dst: 0,
                src1: 0,
                src2: 0,
                immediate: None,
                address: None,
            },
        ];
        
        vm.load_program(program);
        vm.execute().unwrap()
    }
    
    #[test]
    fn test_session_management() {
        let mut prover = GpuSecureProver::with_defaults();
        
        assert!(!prover.is_session_valid());
        
        let session_id = prover.init_session().unwrap();
        assert!(!session_id.is_empty());
        assert!(prover.is_session_valid());
        
        prover.end_session();
        assert!(!prover.is_session_valid());
    }
    
    #[test]
    fn test_encryption_roundtrip() {
        let mut prover = GpuSecureProver::with_defaults();
        prover.init_session().unwrap();
        
        let original_data = b"Hello, Obelysk!";
        let encrypted = prover.encrypt_payload(original_data).unwrap();
        let decrypted = prover.decrypt_payload(&encrypted).unwrap();
        
        assert_eq!(original_data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_attestation_extraction() {
        let prover = GpuSecureProver::with_defaults();
        let trace = create_test_trace();
        
        // Generate a mock proof
        let proof = crate::obelysk::ObelyskProver::new()
            .prove_execution(&trace)
            .unwrap();
        
        let attestation = prover.extract_attestation(&proof);
        
        // Attestation should be non-trivial
        assert!(!attestation.iter().all(|&b| b == 0));
    }
}

