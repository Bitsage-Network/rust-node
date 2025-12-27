// Worker Key Management for Obelysk Privacy Layer
//
// Manages ElGamal keypairs for GPU workers, handling:
// - Secure key generation and storage
// - Key derivation from worker ID
// - Encryption/decryption for privacy payments
// - Integration with TEE for secure key storage
//
// # Security Model
// - Keys derived deterministically from worker secret + salt
// - Private keys never leave TEE in production
// - Public keys registered on-chain for payment routing

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use std::fs;
use sha3::{Digest, Keccak256};
use tracing::{info, debug};

use super::elgamal::{
    Felt252, ECPoint, KeyPair, ElGamalCiphertext,
    decrypt_point, hash_felts,
};

// =============================================================================
// Worker Key Manager
// =============================================================================

/// Manages privacy keys for a worker node
pub struct WorkerKeyManager {
    /// The worker's ElGamal keypair
    keypair: KeyPair,
    /// Worker identifier
    worker_id: String,
    /// Path to key storage (if file-based)
    storage_path: Option<PathBuf>,
    /// Whether running in TEE mode
    tee_mode: bool,
}

impl WorkerKeyManager {
    /// Generate a new keypair from worker secret
    /// This should be called once during worker setup
    pub fn new_from_secret(
        worker_id: &str,
        secret: &[u8],
        storage_path: Option<PathBuf>,
    ) -> Result<Self> {
        // Derive privacy key from worker secret with domain separation
        let privacy_secret = derive_privacy_secret(worker_id, secret);
        let keypair = KeyPair::from_secret(privacy_secret);

        info!("Generated privacy keypair for worker {}", worker_id);
        debug!("Public key: ({}, {})",
               keypair.public_key.x.to_hex(),
               keypair.public_key.y.to_hex());

        let manager = Self {
            keypair,
            worker_id: worker_id.to_string(),
            storage_path,
            tee_mode: false,
        };

        // Optionally persist the key
        if let Some(ref path) = manager.storage_path {
            manager.save_to_file(path)?;
        }

        Ok(manager)
    }

    /// Load keypair from encrypted file
    pub fn load_from_file(path: &PathBuf, encryption_key: &[u8]) -> Result<Self> {
        let encrypted_data = fs::read(path)
            .map_err(|e| anyhow!("Failed to read key file: {}", e))?;

        let decrypted = decrypt_key_file(&encrypted_data, encryption_key)?;
        let stored: StoredKeyPair = serde_json::from_slice(&decrypted)
            .map_err(|e| anyhow!("Failed to parse key file: {}", e))?;

        let secret = Felt252::from_hex(&stored.secret_key_hex)
            .ok_or_else(|| anyhow!("Invalid secret key format"))?;

        let keypair = KeyPair::from_secret(secret);

        // Verify public key matches
        if keypair.public_key.x.to_hex() != stored.public_key_x_hex ||
           keypair.public_key.y.to_hex() != stored.public_key_y_hex {
            return Err(anyhow!("Public key mismatch in stored key file"));
        }

        info!("Loaded privacy keypair for worker {}", stored.worker_id);

        Ok(Self {
            keypair,
            worker_id: stored.worker_id,
            storage_path: Some(path.clone()),
            tee_mode: false,
        })
    }

    /// Generate from TEE-protected seed
    /// In TEE mode, the private key never leaves the enclave
    #[cfg(feature = "tee")]
    pub fn new_from_tee(worker_id: &str, tee_context: &TeeContext) -> Result<Self> {
        // Get sealed random from TEE
        let sealed_random = tee_context.get_sealed_random(32)?;
        let privacy_secret = derive_privacy_secret(worker_id, &sealed_random);
        let keypair = KeyPair::from_secret(privacy_secret);

        info!("Generated TEE-protected privacy keypair for worker {}", worker_id);

        Ok(Self {
            keypair,
            worker_id: worker_id.to_string(),
            storage_path: None,
            tee_mode: true,
        })
    }

    /// Get the worker's public key (safe to share)
    pub fn public_key(&self) -> ECPoint {
        self.keypair.public_key
    }

    /// Get worker ID
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Decrypt an encrypted payment amount
    /// Returns the decoded point (amount * H)
    pub fn decrypt_payment(&self, ciphertext: &ElGamalCiphertext) -> ECPoint {
        decrypt_point(ciphertext, &self.keypair.secret_key)
    }

    /// Create a decryption proof for claiming a payment
    pub fn create_claim_proof(
        &self,
        ciphertext: &ElGamalCiphertext,
        job_id: u128,
    ) -> super::elgamal::EncryptionProof {
        // Generate nonce from job_id for determinism
        let nonce = hash_felts(&[
            self.keypair.secret_key,
            Felt252::from_u128(job_id),
        ]);

        super::elgamal::create_decryption_proof(&self.keypair, ciphertext, &nonce)
    }

    /// Sign a registration message (proves ownership of public key)
    pub fn sign_registration(&self, timestamp: u64) -> RegistrationSignature {
        let message = hash_felts(&[
            self.keypair.public_key.x,
            self.keypair.public_key.y,
            Felt252::from_u64(timestamp),
        ]);

        // Create Schnorr signature
        let nonce = hash_felts(&[self.keypair.secret_key, message]);
        let proof = super::elgamal::create_schnorr_proof(
            &self.keypair.secret_key,
            &self.keypair.public_key,
            &nonce,
            &[message],
        );

        RegistrationSignature {
            public_key: self.keypair.public_key,
            timestamp,
            proof,
        }
    }

    /// Save keypair to encrypted file
    fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let stored = StoredKeyPair {
            worker_id: self.worker_id.clone(),
            secret_key_hex: self.keypair.secret_key.to_hex(),
            public_key_x_hex: self.keypair.public_key.x.to_hex(),
            public_key_y_hex: self.keypair.public_key.y.to_hex(),
            created_at: chrono::Utc::now().timestamp() as u64,
        };

        let json = serde_json::to_vec_pretty(&stored)
            .map_err(|e| anyhow!("Failed to serialize keypair: {}", e))?;

        // Encrypt with worker-derived key
        let encryption_key = derive_file_encryption_key(&self.worker_id, &stored.secret_key_hex);
        let encrypted = encrypt_key_file(&json, &encryption_key)?;

        fs::write(path, &encrypted)
            .map_err(|e| anyhow!("Failed to write key file: {}", e))?;

        info!("Saved encrypted keypair to {:?}", path);
        Ok(())
    }

    /// Export public key for on-chain registration
    pub fn export_public_key(&self) -> PublicKeyExport {
        PublicKeyExport {
            worker_id: self.worker_id.clone(),
            public_key_x: self.keypair.public_key.x.to_hex(),
            public_key_y: self.keypair.public_key.y.to_hex(),
        }
    }

    /// Get keypair reference (for advanced usage)
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }
}

// =============================================================================
// Storage Types
// =============================================================================

/// Stored keypair format
#[derive(Serialize, Deserialize)]
struct StoredKeyPair {
    worker_id: String,
    secret_key_hex: String,
    public_key_x_hex: String,
    public_key_y_hex: String,
    created_at: u64,
}

/// Public key export for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyExport {
    pub worker_id: String,
    pub public_key_x: String,
    pub public_key_y: String,
}

/// Registration signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationSignature {
    pub public_key: ECPoint,
    pub timestamp: u64,
    pub proof: super::elgamal::EncryptionProof,
}

// =============================================================================
// Key Derivation
// =============================================================================

/// Derive privacy secret from worker secret with domain separation
fn derive_privacy_secret(worker_id: &str, secret: &[u8]) -> Felt252 {
    let mut hasher = Keccak256::new();

    // Domain separator
    hasher.update(b"BITSAGE_PRIVACY_KEY_V1");
    hasher.update(worker_id.as_bytes());
    hasher.update(secret);

    let hash = hasher.finalize();

    // Take 31 bytes to ensure < STARK_PRIME
    let mut bytes = [0u8; 32];
    bytes[1..32].copy_from_slice(&hash[0..31]);

    Felt252::from_be_bytes(&bytes)
}

/// Derive file encryption key
fn derive_file_encryption_key(worker_id: &str, secret_hex: &str) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"BITSAGE_FILE_KEY_V1");
    hasher.update(worker_id.as_bytes());
    hasher.update(secret_hex.as_bytes());
    hasher.finalize().into()
}

// =============================================================================
// File Encryption (simple XOR for demo, use AES-GCM in production)
// =============================================================================

fn encrypt_key_file(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // In production, use AES-GCM from aes-gcm crate
    // This is a simple XOR for demonstration
    let mut encrypted = vec![0u8; data.len() + 32]; // Include salt

    // Generate random salt
    let salt: [u8; 32] = rand::random();
    encrypted[0..32].copy_from_slice(&salt);

    // Derive encryption stream from key + salt
    let mut hasher = Keccak256::new();
    hasher.update(key);
    hasher.update(&salt);
    let stream: [u8; 32] = hasher.finalize().into();

    // XOR encrypt (repeat stream as needed)
    for (i, byte) in data.iter().enumerate() {
        encrypted[32 + i] = byte ^ stream[i % 32];
    }

    Ok(encrypted)
}

fn decrypt_key_file(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 32 {
        return Err(anyhow!("Invalid encrypted file"));
    }

    // Extract salt
    let salt = &encrypted[0..32];
    let ciphertext = &encrypted[32..];

    // Derive decryption stream
    let mut hasher = Keccak256::new();
    hasher.update(key);
    hasher.update(salt);
    let stream: [u8; 32] = hasher.finalize().into();

    // XOR decrypt
    let mut decrypted = Vec::with_capacity(ciphertext.len());
    for (i, byte) in ciphertext.iter().enumerate() {
        decrypted.push(byte ^ stream[i % 32]);
    }

    Ok(decrypted)
}

// =============================================================================
// Batch Key Operations
// =============================================================================

/// Generate multiple worker keys for a coordinator
pub fn generate_worker_keys(
    coordinator_secret: &[u8],
    worker_ids: &[&str],
) -> Vec<(String, PublicKeyExport)> {
    worker_ids.iter().map(|id| {
        let manager = WorkerKeyManager::new_from_secret(id, coordinator_secret, None)
            .expect("Key generation should not fail");
        (id.to_string(), manager.export_public_key())
    }).collect()
}

/// Verify a worker's registration signature
pub fn verify_registration_signature(
    signature: &RegistrationSignature,
    expected_worker_id: &str,
) -> bool {
    // Recompute message
    let message = hash_felts(&[
        signature.public_key.x,
        signature.public_key.y,
        Felt252::from_u64(signature.timestamp),
    ]);

    // Verify Schnorr proof
    super::elgamal::verify_schnorr_proof(
        &signature.public_key,
        &signature.proof,
        &[message],
    )
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_key_generation() {
        let secret = b"test_worker_secret_12345";
        let manager = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();

        assert!(!manager.public_key().is_infinity());
        assert!(manager.public_key().is_on_curve());
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_deterministic_key_derivation() {
        let secret = b"test_secret";

        let manager1 = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();
        let manager2 = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();

        assert_eq!(manager1.public_key(), manager2.public_key());
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_different_workers_different_keys() {
        let secret = b"shared_secret";

        let manager1 = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();
        let manager2 = WorkerKeyManager::new_from_secret("worker_2", secret, None).unwrap();

        assert_ne!(manager1.public_key(), manager2.public_key());
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_decrypt_payment() {
        let secret = b"worker_secret";
        let manager = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();

        // Encrypt an amount to this worker
        let amount = 1000u64;
        let randomness = Felt252::from_u64(12345);
        let ciphertext = super::super::elgamal::encrypt(amount, &manager.public_key(), &randomness);

        // Decrypt
        let decrypted_point = manager.decrypt_payment(&ciphertext);

        // Should equal amount * H
        let h = ECPoint::generator_h();
        let expected = h.scalar_mul(&Felt252::from_u64(amount));

        assert_eq!(decrypted_point, expected);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_registration_signature() {
        let secret = b"worker_secret";
        let manager = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();

        let timestamp = 1234567890u64;
        let signature = manager.sign_registration(timestamp);

        // Verify
        assert!(verify_registration_signature(&signature, "worker_1"));
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_public_key_export() {
        let secret = b"worker_secret";
        let manager = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();

        let export = manager.export_public_key();

        assert_eq!(export.worker_id, "worker_1");
        assert!(export.public_key_x.starts_with("0x"));
        assert!(export.public_key_y.starts_with("0x"));
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_batch_key_generation() {
        let secret = b"coordinator_secret";
        let workers = vec!["worker_1", "worker_2", "worker_3"];

        let keys = generate_worker_keys(secret, &workers);

        assert_eq!(keys.len(), 3);

        // All keys should be unique
        let mut public_keys: Vec<_> = keys.iter()
            .map(|(_, export)| (export.public_key_x.clone(), export.public_key_y.clone()))
            .collect();
        public_keys.sort();
        public_keys.dedup();
        assert_eq!(public_keys.len(), 3);
    }

    #[test]
    fn test_file_encryption_roundtrip() {
        let data = b"secret key data here";
        let key = [0u8; 32];

        let encrypted = encrypt_key_file(data, &key).unwrap();
        let decrypted = decrypt_key_file(&encrypted, &key).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_claim_proof_creation() {
        let secret = b"worker_secret";
        let manager = WorkerKeyManager::new_from_secret("worker_1", secret, None).unwrap();

        // Create a test ciphertext
        let randomness = Felt252::from_u64(999);
        let ciphertext = super::super::elgamal::encrypt(500, &manager.public_key(), &randomness);

        // Create claim proof
        let job_id = 12345u128;
        let proof = manager.create_claim_proof(&ciphertext, job_id);

        // Verify proof
        assert!(super::super::elgamal::verify_decryption_proof(
            &manager.public_key(),
            &ciphertext,
            &proof,
        ));
    }
}
