// Obelysk FHE Module - Fully Homomorphic Encryption for Confidential Compute
//
// This module provides FHE capabilities for BitSage Network:
// - Encrypted AI inference without decryption
// - Privacy-preserving computation on user data
// - End-to-end encrypted data pipelines
//
// Architecture:
// - Uses Zama's tfhe-rs library (TFHE scheme)
// - Client-side encryption with user keys
// - Server-side homomorphic computation
// - On-chain verification of computation integrity
//
// Integration with Obelysk:
// - TEE provides hardware isolation for key operations
// - STWO generates proofs of correct FHE computation
// - Cairo verifies proofs on-chain

pub mod keys;
pub mod encryption;
pub mod compute;
pub mod types;

// Re-exports for convenience
pub use keys::{
    FheKeyManager, FheClientKey, FheServerKey, FhePublicKey,
    KeyConfig, KeyGenerationError,
};
pub use encryption::{
    FheEncryptor, EncryptedValue, EncryptedVector,
    encrypt_u8, encrypt_u16, encrypt_u32, encrypt_u64,
    decrypt_u8, decrypt_u16, decrypt_u32, decrypt_u64,
};
pub use compute::{
    FheCompute, ComputeResult, HomomorphicOperation,
    homomorphic_add, homomorphic_sub, homomorphic_mul,
    homomorphic_compare, homomorphic_max, homomorphic_min,
};
pub use types::{
    FheError, FheConfig, SerializedKey, SerializedCiphertext,
    ComputeRequest, ComputeResponse,
};

/// FHE configuration for BitSage Network
#[derive(Debug, Clone)]
pub struct ObelyskFheConfig {
    /// Enable GPU acceleration for FHE operations
    pub gpu_acceleration: bool,
    /// Maximum number of concurrent FHE operations
    pub max_concurrent_ops: usize,
    /// Key caching duration in seconds
    pub key_cache_ttl: u64,
    /// Enable STWO proof generation for FHE computations
    pub generate_proofs: bool,
}

impl Default for ObelyskFheConfig {
    fn default() -> Self {
        Self {
            gpu_acceleration: false,
            max_concurrent_ops: 4,
            key_cache_ttl: 3600, // 1 hour
            generate_proofs: true,
        }
    }
}

/// Main entry point for FHE operations in BitSage
pub struct ObelyskFhe {
    config: ObelyskFheConfig,
    key_manager: FheKeyManager,
}

impl ObelyskFhe {
    /// Create a new FHE instance with the given configuration
    pub fn new(config: ObelyskFheConfig) -> Result<Self, FheError> {
        let key_config = KeyConfig::default();
        let key_manager = FheKeyManager::new(key_config)?;

        Ok(Self {
            config,
            key_manager,
        })
    }

    /// Generate new FHE keys for a client
    pub fn generate_client_keys(&self) -> Result<(FheClientKey, FheServerKey, FhePublicKey), FheError> {
        self.key_manager.generate_keys()
    }

    /// Encrypt a value using the public key
    pub fn encrypt<T: Into<u64>>(&self, value: T, public_key: &FhePublicKey) -> Result<EncryptedValue, FheError> {
        FheEncryptor::encrypt_with_public_key(value.into(), public_key)
    }

    /// Decrypt a value using the client key
    pub fn decrypt(&self, ciphertext: &EncryptedValue, client_key: &FheClientKey) -> Result<u64, FheError> {
        FheEncryptor::decrypt(ciphertext, client_key)
    }

    /// Perform homomorphic addition
    pub fn add(&self, a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> Result<EncryptedValue, FheError> {
        FheCompute::add(a, b, server_key)
    }

    /// Perform homomorphic multiplication
    pub fn mul(&self, a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> Result<EncryptedValue, FheError> {
        FheCompute::mul(a, b, server_key)
    }

    /// Check if FHE feature is enabled
    pub fn is_available() -> bool {
        cfg!(feature = "fhe")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "fhe")]
    fn test_fhe_basic_operations() {
        let config = ObelyskFheConfig::default();
        let fhe = ObelyskFhe::new(config).expect("Failed to create FHE instance");

        let (client_key, server_key, public_key) = fhe.generate_client_keys()
            .expect("Failed to generate keys");

        // Encrypt two values
        let a = fhe.encrypt(5u64, &public_key).expect("Failed to encrypt a");
        let b = fhe.encrypt(3u64, &public_key).expect("Failed to encrypt b");

        // Add them homomorphically
        let sum = fhe.add(&a, &b, &server_key).expect("Failed to add");

        // Decrypt the result
        let result = fhe.decrypt(&sum, &client_key).expect("Failed to decrypt");
        assert_eq!(result, 8);
    }
}
