//! Privacy State Machine - Tracking encryption lifecycle of data
//!
//! This module implements a formal state machine for tracking the privacy state
//! of data throughout its lifecycle in BitSage/Obelysk. Every piece of sensitive
//! data has a privacy state that ensures:
//!
//! 1. Plaintext only exists on user devices
//! 2. All transitions are cryptographically enforced
//! 3. Audit trail is maintained (encrypted)
//! 4. IO commitments bind proofs to data
//!
//! # State Diagram
//!
//! ```text
//! PLAINTEXT → USER_ENCRYPTED → FHE_ENCRYPTED → FHE_RESULT → PROVEN → COMMITTED
//!                    ↓                                            ↓
//!              AUDITOR_ENCRYPTED                             NULLIFIED
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

/// Privacy states for data lifecycle tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyState {
    /// Raw plaintext - only exists on user device, never transmitted
    Plaintext,

    /// Encrypted with user's key (AES-GCM or similar)
    UserEncrypted,

    /// Re-encrypted for FHE computation (TFHE ciphertext)
    FheEncrypted,

    /// Result of FHE computation (still encrypted)
    FheResult,

    /// Has ZK proof attached - verifiable without decryption
    ProvenEncrypted,

    /// Re-encrypted for user retrieval
    UserResultEncrypted,

    /// Encrypted for threshold auditor access
    AuditorEncrypted,

    /// Committed on-chain (only commitment visible)
    Committed,

    /// Nullified - spent, cannot be reused
    Nullified,

    /// Destroyed - securely wiped from memory
    Destroyed,
}

impl PrivacyState {
    /// Check if transition to another state is valid
    pub fn can_transition_to(&self, next: PrivacyState) -> bool {
        use PrivacyState::*;

        match (self, next) {
            // User encrypts their plaintext data
            (Plaintext, UserEncrypted) => true,

            // TEE re-encrypts for FHE (inside enclave only)
            (UserEncrypted, FheEncrypted) => true,

            // FHE computation produces result
            (FheEncrypted, FheResult) => true,

            // Proof attached to encrypted result
            (FheResult, ProvenEncrypted) => true,

            // Re-encrypt for user retrieval
            (ProvenEncrypted, UserResultEncrypted) => true,

            // User decrypts locally (final step)
            (UserResultEncrypted, Plaintext) => true,

            // Commit encrypted data to chain
            (UserEncrypted, Committed) => true,
            (FheResult, Committed) => true,
            (ProvenEncrypted, Committed) => true,

            // Nullify (spend committed data)
            (Committed, Nullified) => true,

            // Auditor access (threshold decryption)
            (UserEncrypted, AuditorEncrypted) => true,
            (Committed, AuditorEncrypted) => true,

            // Secure destruction from any state
            (_, Destroyed) => true,

            // No other transitions allowed
            _ => false,
        }
    }

    /// Check if this state contains encrypted data
    pub fn is_encrypted(&self) -> bool {
        use PrivacyState::*;
        matches!(
            self,
            UserEncrypted | FheEncrypted | FheResult | ProvenEncrypted |
            UserResultEncrypted | AuditorEncrypted
        )
    }

    /// Check if this state is safe to transmit over network
    pub fn is_network_safe(&self) -> bool {
        use PrivacyState::*;
        matches!(
            self,
            UserEncrypted | FheEncrypted | FheResult | ProvenEncrypted |
            UserResultEncrypted | AuditorEncrypted | Committed | Nullified
        )
    }

    /// Check if this state requires TEE for transition
    pub fn requires_tee_for_transition(&self) -> bool {
        use PrivacyState::*;
        matches!(self, UserEncrypted | FheResult | ProvenEncrypted)
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        use PrivacyState::*;
        match self {
            Plaintext => "Raw plaintext (user device only)",
            UserEncrypted => "Encrypted with user key",
            FheEncrypted => "FHE ciphertext (computable)",
            FheResult => "FHE computation result",
            ProvenEncrypted => "Encrypted with ZK proof",
            UserResultEncrypted => "Result encrypted for user",
            AuditorEncrypted => "Threshold-encrypted for auditors",
            Committed => "Committed on-chain",
            Nullified => "Spent/nullified",
            Destroyed => "Securely destroyed",
        }
    }
}

/// Transition between privacy states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyTransition {
    /// Source state
    pub from: PrivacyState,

    /// Destination state
    pub to: PrivacyState,

    /// Timestamp of transition
    pub timestamp: u64,

    /// Operation that caused transition
    pub operation: TransitionOperation,

    /// Evidence of valid transition (hash of proof/attestation)
    pub evidence_hash: [u8; 32],

    /// TEE attestation if required
    pub tee_attestation: Option<TeeAttestationRef>,
}

/// Operations that can cause privacy state transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionOperation {
    /// User encrypted plaintext
    Encrypt { algorithm: EncryptionAlgorithm },

    /// TEE re-encrypted for FHE
    FheConvert { tee_type: TeeType },

    /// FHE computation performed
    FheCompute { operation: FheOperationType },

    /// ZK proof generated
    ProofGenerate { proof_type: ProofType },

    /// Re-encrypted for user
    ResultEncrypt,

    /// Committed to blockchain
    ChainCommit { block_number: u64, tx_hash: [u8; 32] },

    /// Nullified/spent
    Nullify { nullifier: [u8; 32] },

    /// Threshold encrypted for auditors
    AuditorEncrypt { threshold: u8, total: u8 },

    /// Securely destroyed
    Destroy,
}

/// Encryption algorithms supported
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AesGcm256,
    ChaCha20Poly1305,
    FheTfhe,
    ElGamalStark,
}

/// TEE types for attestation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TeeType {
    IntelTdx,
    AmdSevSnp,
    NvidiaCc,
    ArmTrustZone,
    Software,
}

/// FHE operation types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FheOperationType {
    Add,
    Sub,
    Mul,
    Compare,
    Relu,
    MatMul,
    DotProduct,
    Custom(u32),
}

/// Proof types for verification
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProofType {
    StwoStark,
    Groth16,
    Plonk,
    Bulletproof,
    RangeProof,
}

/// Reference to TEE attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationRef {
    /// Hash of full attestation quote
    pub quote_hash: [u8; 32],

    /// TEE type
    pub tee_type: TeeType,

    /// MRENCLAVE/measurement (48 bytes for SGX, stored as Vec for serde)
    pub measurement: Vec<u8>,
}

/// Encrypted audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAuditEntry {
    /// Encrypted audit data (AES-GCM with auditor keys)
    pub encrypted_data: Vec<u8>,

    /// Nonce for decryption
    pub nonce: [u8; 12],

    /// Timestamp
    pub timestamp: u64,

    /// Entry type (visible for filtering)
    pub entry_type: AuditEntryType,
}

/// Types of audit entries
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuditEntryType {
    Encryption,
    FheConversion,
    FheComputation,
    ProofGeneration,
    ChainCommit,
    Nullification,
    AuditorAccess,
    RegulatoryRequest,
}

/// Privacy-wrapped data with state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateData<T> {
    /// Current privacy state
    state: PrivacyState,

    /// The data (encrypted in most states)
    data: PrivateDataInner,

    /// Pedersen commitment for verification
    commitment: Option<[u8; 32]>,

    /// IO commitment binding proof to I/O
    io_commitment: Option<[u8; 32]>,

    /// Attached proofs
    proofs: Vec<AttachedProof>,

    /// Transition history (encrypted)
    audit_trail: Vec<EncryptedAuditEntry>,

    /// Creation timestamp
    created_at: u64,

    /// Last modified timestamp
    modified_at: u64,

    /// Type marker
    #[serde(skip)]
    _marker: PhantomData<T>,
}

/// Inner data representation based on state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivateDataInner {
    /// Plaintext bytes (only in Plaintext state)
    Plain(Vec<u8>),

    /// AES-GCM encrypted
    AesGcm {
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        tag: [u8; 16],
    },

    /// FHE ciphertext (serialized TFHE)
    Fhe(Vec<u8>),

    /// ElGamal ciphertext (for payments)
    ElGamal {
        c1_x: [u8; 32],
        c1_y: [u8; 32],
        c2_x: [u8; 32],
        c2_y: [u8; 32],
    },

    /// On-chain commitment only
    Commitment([u8; 32]),

    /// Nullified (only nullifier hash remains)
    Nullified([u8; 32]),

    /// Destroyed (no data)
    Destroyed,
}

/// Attached cryptographic proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttachedProof {
    /// STWO STARK proof
    Stark {
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
    },

    /// TEE attestation
    TeeAttestation(TeeAttestationRef),

    /// Range proof
    RangeProof {
        commitment: [u8; 32],
        proof_data: Vec<u8>,
        bit_length: u8,
    },

    /// Same-encryption proof
    SameEncryptionProof {
        proof_data: Vec<u8>,
    },

    /// Encryption correctness proof
    EncryptionProof {
        algorithm: EncryptionAlgorithm,
        proof_data: Vec<u8>,
    },
}

/// Errors during privacy operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum PrivacyError {
    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition { from: PrivacyState, to: PrivacyState },

    #[error("TEE required for this operation")]
    TeeRequired,

    #[error("Not inside TEE boundary")]
    NotInTee,

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Commitment mismatch")]
    CommitmentMismatch,

    #[error("Data already nullified")]
    AlreadyNullified,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
}

impl<T: Serialize + for<'de> Deserialize<'de>> PrivateData<T> {
    /// Create new private data from plaintext (user-side only)
    pub fn from_plaintext(value: T) -> Result<Self, PrivacyError> {
        let serialized = bincode::serialize(&value)
            .map_err(|e| PrivacyError::SerializationFailed(e.to_string()))?;

        let commitment = compute_commitment(&serialized);
        let timestamp = current_timestamp();

        Ok(Self {
            state: PrivacyState::Plaintext,
            data: PrivateDataInner::Plain(serialized),
            commitment: Some(commitment),
            io_commitment: None,
            proofs: vec![],
            audit_trail: vec![],
            created_at: timestamp,
            modified_at: timestamp,
            _marker: PhantomData,
        })
    }

    /// Get current privacy state
    pub fn state(&self) -> PrivacyState {
        self.state
    }

    /// Get commitment if available
    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.commitment
    }

    /// Get IO commitment if available
    pub fn io_commitment(&self) -> Option<[u8; 32]> {
        self.io_commitment
    }

    /// Check if data is in encrypted state
    pub fn is_encrypted(&self) -> bool {
        self.state.is_encrypted()
    }

    /// Check if data is safe to transmit
    pub fn is_network_safe(&self) -> bool {
        self.state.is_network_safe()
    }

    /// Encrypt plaintext with user key
    pub fn encrypt_user(
        self,
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Self, PrivacyError> {
        if !self.state.can_transition_to(PrivacyState::UserEncrypted) {
            return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::UserEncrypted,
            });
        }

        let plaintext = match &self.data {
            PrivateDataInner::Plain(data) => data.clone(),
            _ => return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::UserEncrypted,
            }),
        };

        // AES-GCM encryption
        let (ciphertext, tag) = aes_gcm_encrypt(&plaintext, key, nonce)?;

        let timestamp = current_timestamp();
        let mut audit_trail = self.audit_trail;
        audit_trail.push(create_audit_entry(
            AuditEntryType::Encryption,
            timestamp,
        ));

        Ok(Self {
            state: PrivacyState::UserEncrypted,
            data: PrivateDataInner::AesGcm {
                ciphertext,
                nonce: *nonce,
                tag,
            },
            commitment: self.commitment,
            io_commitment: self.io_commitment,
            proofs: vec![],
            audit_trail,
            created_at: self.created_at,
            modified_at: timestamp,
            _marker: PhantomData,
        })
    }

    /// Convert to FHE encryption (must be inside TEE)
    #[cfg(feature = "tee")]
    pub fn convert_to_fhe(
        self,
        user_key: &[u8; 32],
        fhe_pk: &crate::obelysk::fhe::FhePublicKey,
        tee_attestation: TeeAttestationRef,
    ) -> Result<Self, PrivacyError> {
        // Verify we're inside TEE
        if !is_inside_tee() {
            return Err(PrivacyError::NotInTee);
        }

        if !self.state.can_transition_to(PrivacyState::FheEncrypted) {
            return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::FheEncrypted,
            });
        }

        // Decrypt with user key (inside TEE only)
        let plaintext = match &self.data {
            PrivateDataInner::AesGcm { ciphertext, nonce, tag } => {
                aes_gcm_decrypt(ciphertext, user_key, nonce, tag)?
            }
            _ => return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::FheEncrypted,
            }),
        };

        // Re-encrypt with FHE
        let fhe_ciphertext = fhe_encrypt(&plaintext, fhe_pk)?;

        // Securely wipe plaintext
        // (In real implementation, use secure_zero)

        let timestamp = current_timestamp();
        let mut audit_trail = self.audit_trail;
        audit_trail.push(create_audit_entry(
            AuditEntryType::FheConversion,
            timestamp,
        ));

        let mut proofs = self.proofs;
        proofs.push(AttachedProof::TeeAttestation(tee_attestation));

        Ok(Self {
            state: PrivacyState::FheEncrypted,
            data: PrivateDataInner::Fhe(fhe_ciphertext),
            commitment: self.commitment,
            io_commitment: None,
            proofs,
            audit_trail,
            created_at: self.created_at,
            modified_at: timestamp,
            _marker: PhantomData,
        })
    }

    /// Mark computation result with IO commitment
    pub fn mark_fhe_result(
        mut self,
        io_commitment: [u8; 32],
    ) -> Result<Self, PrivacyError> {
        if self.state != PrivacyState::FheEncrypted {
            return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::FheResult,
            });
        }

        self.state = PrivacyState::FheResult;
        self.io_commitment = Some(io_commitment);
        self.modified_at = current_timestamp();

        let mut audit_trail = self.audit_trail;
        audit_trail.push(create_audit_entry(
            AuditEntryType::FheComputation,
            self.modified_at,
        ));
        self.audit_trail = audit_trail;

        Ok(self)
    }

    /// Attach ZK proof to encrypted result
    pub fn attach_stark_proof(
        mut self,
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Result<Self, PrivacyError> {
        if !self.state.can_transition_to(PrivacyState::ProvenEncrypted) {
            return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::ProvenEncrypted,
            });
        }

        self.state = PrivacyState::ProvenEncrypted;
        self.proofs.push(AttachedProof::Stark { proof_data, public_inputs });
        self.modified_at = current_timestamp();

        let mut audit_trail = self.audit_trail;
        audit_trail.push(create_audit_entry(
            AuditEntryType::ProofGeneration,
            self.modified_at,
        ));
        self.audit_trail = audit_trail;

        Ok(self)
    }

    /// Commit to blockchain
    pub fn commit_to_chain(
        mut self,
        _block_number: u64,
        _tx_hash: [u8; 32],
    ) -> Result<Self, PrivacyError> {
        if !self.state.can_transition_to(PrivacyState::Committed) {
            return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::Committed,
            });
        }

        let commitment = self.commitment.ok_or(PrivacyError::CommitmentMismatch)?;

        self.state = PrivacyState::Committed;
        self.data = PrivateDataInner::Commitment(commitment);
        self.modified_at = current_timestamp();

        let mut audit_trail = self.audit_trail;
        audit_trail.push(create_audit_entry(
            AuditEntryType::ChainCommit,
            self.modified_at,
        ));
        self.audit_trail = audit_trail;

        Ok(self)
    }

    /// Nullify (spend) committed data
    pub fn nullify(mut self, nullifier: [u8; 32]) -> Result<Self, PrivacyError> {
        if self.state != PrivacyState::Committed {
            return Err(PrivacyError::InvalidTransition {
                from: self.state,
                to: PrivacyState::Nullified,
            });
        }

        self.state = PrivacyState::Nullified;
        self.data = PrivateDataInner::Nullified(nullifier);
        self.modified_at = current_timestamp();

        let mut audit_trail = self.audit_trail;
        audit_trail.push(create_audit_entry(
            AuditEntryType::Nullification,
            self.modified_at,
        ));
        self.audit_trail = audit_trail;

        Ok(self)
    }

    /// Securely destroy all data
    pub fn destroy(mut self) -> Self {
        self.state = PrivacyState::Destroyed;
        self.data = PrivateDataInner::Destroyed;
        self.commitment = None;
        self.io_commitment = None;
        self.proofs.clear();
        // Note: audit_trail preserved for compliance
        self.modified_at = current_timestamp();
        self
    }

    /// Verify all attached proofs
    pub fn verify_proofs(&self) -> bool {
        for proof in &self.proofs {
            let valid = match proof {
                AttachedProof::Stark { proof_data, public_inputs } => {
                    verify_stark_proof(proof_data, public_inputs)
                }
                AttachedProof::TeeAttestation(att) => {
                    verify_tee_attestation(att)
                }
                AttachedProof::RangeProof { commitment, proof_data, bit_length } => {
                    verify_range_proof(commitment, proof_data, *bit_length)
                }
                AttachedProof::SameEncryptionProof { proof_data } => {
                    verify_same_encryption_proof(proof_data)
                }
                AttachedProof::EncryptionProof { algorithm, proof_data } => {
                    verify_encryption_proof(*algorithm, proof_data)
                }
            };

            if !valid {
                return false;
            }
        }

        // Verify IO commitment if present and state requires it
        if self.state == PrivacyState::ProvenEncrypted || self.state == PrivacyState::Committed {
            if let Some(io_commitment) = self.io_commitment {
                // Verify IO commitment is embedded in STARK proof
                for proof in &self.proofs {
                    if let AttachedProof::Stark { public_inputs, .. } = proof {
                        if !verify_io_commitment_in_proof(public_inputs, &io_commitment) {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn compute_commitment(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"OBELYSK_COMMITMENT_V1");
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    let result = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&result);
    commitment
}

fn create_audit_entry(entry_type: AuditEntryType, timestamp: u64) -> EncryptedAuditEntry {
    // In production, this would encrypt the entry with auditor keys
    EncryptedAuditEntry {
        encrypted_data: vec![],
        nonce: [0u8; 12],
        timestamp,
        entry_type,
    }
}

fn aes_gcm_encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<(Vec<u8>, [u8; 16]), PrivacyError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PrivacyError::EncryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| PrivacyError::EncryptionFailed(e.to_string()))?;

    // Split off tag (last 16 bytes)
    let tag_start = ciphertext.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[tag_start..]);
    let ct = ciphertext[..tag_start].to_vec();

    Ok((ct, tag))
}

#[allow(dead_code)]
fn aes_gcm_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    tag: &[u8; 16],
) -> Result<Vec<u8>, PrivacyError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PrivacyError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    // Reconstruct ciphertext with tag
    let mut ct_with_tag = ciphertext.to_vec();
    ct_with_tag.extend_from_slice(tag);

    cipher.decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|e| PrivacyError::DecryptionFailed(e.to_string()))
}

#[cfg(feature = "fhe")]
#[allow(dead_code)]
fn fhe_encrypt(
    plaintext: &[u8],
    _fhe_pk: &crate::obelysk::fhe::FhePublicKey,
) -> Result<Vec<u8>, PrivacyError> {
    // In production, use actual FHE encryption
    Ok(plaintext.to_vec())
}

#[cfg(not(feature = "fhe"))]
#[allow(dead_code)]
fn fhe_encrypt(
    plaintext: &[u8],
    _fhe_pk: &(),
) -> Result<Vec<u8>, PrivacyError> {
    Ok(plaintext.to_vec())
}

#[cfg(feature = "tee")]
#[allow(dead_code)]
fn is_inside_tee() -> bool {
    // Check for TEE environment
    std::path::Path::new("/dev/sgx_enclave").exists() ||
    std::path::Path::new("/sys/kernel/config/tsm/report").exists() ||
    std::path::Path::new("/dev/nvidia-cc").exists()
}

#[cfg(not(feature = "tee"))]
#[allow(dead_code)]
fn is_inside_tee() -> bool {
    false
}

fn verify_stark_proof(_proof_data: &[u8], _public_inputs: &[u8]) -> bool {
    // In production, call STWO verifier
    true
}

fn verify_tee_attestation(_att: &TeeAttestationRef) -> bool {
    // In production, verify TEE quote
    true
}

fn verify_range_proof(_commitment: &[u8; 32], _proof_data: &[u8], _bit_length: u8) -> bool {
    // In production, verify Bulletproof
    true
}

fn verify_same_encryption_proof(_proof_data: &[u8]) -> bool {
    // In production, verify DLEQ proof
    true
}

fn verify_encryption_proof(_algorithm: EncryptionAlgorithm, _proof_data: &[u8]) -> bool {
    // In production, verify encryption correctness
    true
}

fn verify_io_commitment_in_proof(_public_inputs: &[u8], _io_commitment: &[u8; 32]) -> bool {
    // In production, check IO commitment is in public inputs
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_state_transitions() {
        use PrivacyState::*;

        // Valid transitions
        assert!(Plaintext.can_transition_to(UserEncrypted));
        assert!(UserEncrypted.can_transition_to(FheEncrypted));
        assert!(FheEncrypted.can_transition_to(FheResult));
        assert!(FheResult.can_transition_to(ProvenEncrypted));
        assert!(ProvenEncrypted.can_transition_to(Committed));
        assert!(Committed.can_transition_to(Nullified));

        // Invalid transitions
        assert!(!Plaintext.can_transition_to(FheResult));
        assert!(!FheResult.can_transition_to(Plaintext));
        assert!(!Nullified.can_transition_to(Plaintext));
        assert!(!Committed.can_transition_to(Plaintext));
    }

    #[test]
    fn test_privacy_state_properties() {
        use PrivacyState::*;

        assert!(!Plaintext.is_encrypted());
        assert!(UserEncrypted.is_encrypted());
        assert!(FheEncrypted.is_encrypted());

        assert!(!Plaintext.is_network_safe());
        assert!(UserEncrypted.is_network_safe());
        assert!(Committed.is_network_safe());
    }

    #[test]
    fn test_private_data_creation() {
        let data: u64 = 42;
        let private = PrivateData::from_plaintext(data).unwrap();

        assert_eq!(private.state(), PrivacyState::Plaintext);
        assert!(private.commitment().is_some());
        assert!(!private.is_encrypted());
    }

    #[test]
    fn test_private_data_encryption() {
        let data: u64 = 42;
        let private = PrivateData::from_plaintext(data).unwrap();

        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let encrypted = private.encrypt_user(&key, &nonce).unwrap();

        assert_eq!(encrypted.state(), PrivacyState::UserEncrypted);
        assert!(encrypted.is_encrypted());
        assert!(encrypted.is_network_safe());
    }

    #[test]
    fn test_commitment_preservation() {
        let data: u64 = 42;
        let private = PrivateData::from_plaintext(data).unwrap();
        let original_commitment = private.commitment();

        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let encrypted = private.encrypt_user(&key, &nonce).unwrap();

        // Commitment should be preserved through encryption
        assert_eq!(encrypted.commitment(), original_commitment);
    }
}
