// FHE Types - Error types and common structures for FHE operations
//
// This module defines the core types used across the FHE implementation

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during FHE operations
#[derive(Error, Debug)]
pub enum FheError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Homomorphic operation failed: {0}")]
    HomomorphicOp(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("FHE feature not enabled")]
    FeatureNotEnabled,

    #[error("Overflow in homomorphic operation")]
    Overflow,

    #[error("GPU acceleration error: {0}")]
    GpuError(String),
}

/// Configuration for FHE operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheConfig {
    /// Security parameter (bits of security)
    pub security_bits: u32,
    /// Maximum value that can be encrypted (determines ciphertext size)
    pub max_value_bits: u32,
    /// Enable bootstrapping for unlimited computation depth
    pub enable_bootstrapping: bool,
    /// Number of threads for parallel operations
    pub num_threads: usize,
}

impl Default for FheConfig {
    fn default() -> Self {
        Self {
            security_bits: 128,
            max_value_bits: 64,
            enable_bootstrapping: false,
            num_threads: 4,
        }
    }
}

/// Serialized FHE key for storage/transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedKey {
    /// Key type identifier
    pub key_type: KeyType,
    /// Serialized key data (compressed)
    pub data: Vec<u8>,
    /// Key version for compatibility
    pub version: u32,
    /// SHA-256 hash of the key for integrity
    pub checksum: [u8; 32],
}

/// Type of FHE key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Client key for encryption/decryption
    Client,
    /// Server key for homomorphic operations
    Server,
    /// Public key for encryption only
    Public,
}

/// Serialized ciphertext for storage/transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedCiphertext {
    /// Ciphertext data (compressed)
    pub data: Vec<u8>,
    /// Type of encrypted value
    pub value_type: ValueType,
    /// Version for compatibility
    pub version: u32,
}

/// Type of encrypted value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Bool,
    Vector(usize), // Vector of values with length
}

/// Request for FHE computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeRequest {
    /// Unique request ID
    pub request_id: String,
    /// Operation to perform
    pub operation: ComputeOperation,
    /// Input ciphertexts (serialized)
    pub inputs: Vec<SerializedCiphertext>,
    /// Server key for computation (serialized)
    pub server_key: SerializedKey,
    /// Whether to generate a STWO proof of computation
    pub generate_proof: bool,
}

/// Response from FHE computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeResponse {
    /// Request ID this responds to
    pub request_id: String,
    /// Result ciphertext (serialized)
    pub result: SerializedCiphertext,
    /// STWO proof of correct computation (if requested)
    pub proof: Option<Vec<u8>>,
    /// Computation statistics
    pub stats: ComputeStats,
}

/// Statistics about an FHE computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeStats {
    /// Time taken for computation in milliseconds
    pub compute_time_ms: u64,
    /// Time taken for proof generation in milliseconds (if applicable)
    pub proof_time_ms: Option<u64>,
    /// Number of homomorphic operations performed
    pub operations_count: u64,
    /// Whether GPU was used
    pub gpu_used: bool,
}

/// Type of computation operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComputeOperation {
    /// Add two ciphertexts
    Add,
    /// Subtract two ciphertexts
    Sub,
    /// Multiply two ciphertexts
    Mul,
    /// Compare two ciphertexts (returns encrypted boolean)
    Compare(CompareOp),
    /// Maximum of two ciphertexts
    Max,
    /// Minimum of two ciphertexts
    Min,
    /// Bitwise AND
    BitwiseAnd,
    /// Bitwise OR
    BitwiseOr,
    /// Bitwise XOR
    BitwiseXor,
    /// Bitwise NOT (unary)
    BitwiseNot,
    /// Left shift by constant
    LeftShift(u32),
    /// Right shift by constant
    RightShift(u32),
    /// Neural network layer (matrix multiplication + activation)
    NeuralNetworkLayer {
        weights: Vec<SerializedCiphertext>,
        activation: ActivationFunction,
    },
    /// Custom operation (for extensibility)
    Custom(String),
}

/// Comparison operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompareOp {
    Equal,
    NotEqual,
    LessThan,
    LessOrEqual,
    GreaterThan,
    GreaterOrEqual,
}

/// Activation functions for neural network operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ActivationFunction {
    /// No activation
    None,
    /// ReLU: max(0, x)
    ReLU,
    /// Sign function
    Sign,
    /// Step function (x > 0 ? 1 : 0)
    Step,
}

/// Result of a computation including optional proof
#[derive(Debug)]
pub struct ComputeResultWithProof<T> {
    /// The computed result
    pub result: T,
    /// STWO proof of correct computation
    pub proof: Option<Vec<u8>>,
    /// Proof commitment for on-chain verification
    pub proof_commitment: Option<[u8; 32]>,
}

impl<T> ComputeResultWithProof<T> {
    pub fn new(result: T) -> Self {
        Self {
            result,
            proof: None,
            proof_commitment: None,
        }
    }

    pub fn with_proof(mut self, proof: Vec<u8>, commitment: [u8; 32]) -> Self {
        self.proof = Some(proof);
        self.proof_commitment = Some(commitment);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_config_default() {
        let config = FheConfig::default();
        assert_eq!(config.security_bits, 128);
        assert_eq!(config.max_value_bits, 64);
    }

    #[test]
    fn test_serialized_key_type() {
        assert_eq!(KeyType::Client, KeyType::Client);
        assert_ne!(KeyType::Client, KeyType::Server);
    }
}
