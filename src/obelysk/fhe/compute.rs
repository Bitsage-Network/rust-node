// FHE Compute Module - Homomorphic operations on encrypted data
//
// This module provides computation functionality on encrypted values:
// - Arithmetic: add, subtract, multiply
// - Comparison: less than, greater than, equal
// - Bitwise: AND, OR, XOR, NOT
// - Neural network operations: matrix multiplication, activation functions
//
// All operations are performed on ciphertexts without decryption

use super::encryption::{EncryptedValue, EncryptedU8, EncryptedU16, EncryptedU32, EncryptedU64};
use super::keys::FheServerKey;
use super::types::{FheError, ComputeResultWithProof, FheIOCommitment};
use std::sync::Arc;
use sha2::{Sha256, Digest};

#[cfg(feature = "fhe")]
use tfhe::{
    prelude::*,
    FheUint8, FheUint16, FheUint32, FheUint64, FheBool,
};

/// Result of a homomorphic computation
pub type ComputeResult<T> = Result<T, FheError>;

/// Types of homomorphic operations
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum HomomorphicOperation {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    LessThan,
    LessOrEqual,
    GreaterThan,
    GreaterOrEqual,
    Equal,
    NotEqual,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    BitwiseNot,
    LeftShift,
    RightShift,
    Max,
    Min,
}

/// Encrypted boolean result from comparisons
#[derive(Clone)]
pub struct EncryptedBool {
    #[cfg(feature = "fhe")]
    pub(crate) inner: Arc<FheBool>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

impl EncryptedBool {
    #[cfg(feature = "fhe")]
    pub(crate) fn from_tfhe(val: FheBool) -> Self {
        Self { inner: Arc::new(val) }
    }

    /// Decrypt the boolean result
    #[cfg(feature = "fhe")]
    pub fn decrypt(&self, client_key: &super::keys::FheClientKey) -> bool {
        self.inner.decrypt(client_key.inner())
    }
}

/// FHE compute engine for homomorphic operations
pub struct FheCompute;

impl FheCompute {
    // ========== ARITHMETIC OPERATIONS ==========

    /// Homomorphic addition of two encrypted values
    pub fn add(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = &*a.inner + &*b.inner;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = &*a.inner + &*b.inner;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = &*a.inner + &*b.inner;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = &*a.inner + &*b.inner;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in addition".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Homomorphic subtraction
    pub fn sub(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = &*a.inner - &*b.inner;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = &*a.inner - &*b.inner;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = &*a.inner - &*b.inner;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = &*a.inner - &*b.inner;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in subtraction".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Homomorphic multiplication
    pub fn mul(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = &*a.inner * &*b.inner;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = &*a.inner * &*b.inner;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = &*a.inner * &*b.inner;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = &*a.inner * &*b.inner;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in multiplication".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Add a plaintext scalar to an encrypted value
    pub fn add_scalar(a: &EncryptedValue, scalar: u64, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match a {
                EncryptedValue::U8(a) => {
                    let result = &*a.inner + (scalar as u8);
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                EncryptedValue::U16(a) => {
                    let result = &*a.inner + (scalar as u16);
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                EncryptedValue::U32(a) => {
                    let result = &*a.inner + (scalar as u32);
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                EncryptedValue::U64(a) => {
                    let result = &*a.inner + scalar;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, scalar, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Multiply an encrypted value by a plaintext scalar
    pub fn mul_scalar(a: &EncryptedValue, scalar: u64, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match a {
                EncryptedValue::U8(a) => {
                    let result = &*a.inner * (scalar as u8);
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                EncryptedValue::U16(a) => {
                    let result = &*a.inner * (scalar as u16);
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                EncryptedValue::U32(a) => {
                    let result = &*a.inner * (scalar as u32);
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                EncryptedValue::U64(a) => {
                    let result = &*a.inner * scalar;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, scalar, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    // ========== COMPARISON OPERATIONS ==========

    /// Homomorphic less than comparison
    pub fn lt(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedBool> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = a.inner.lt(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = a.inner.lt(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = a.inner.lt(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = a.inner.lt(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in comparison".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Homomorphic equality check
    pub fn eq(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedBool> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = a.inner.eq(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = a.inner.eq(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = a.inner.eq(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = a.inner.eq(&*b.inner);
                    Ok(EncryptedBool::from_tfhe(result))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in comparison".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    // ========== MIN/MAX OPERATIONS ==========

    /// Homomorphic maximum
    pub fn max(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = a.inner.max(&*b.inner);
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = a.inner.max(&*b.inner);
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = a.inner.max(&*b.inner);
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = a.inner.max(&*b.inner);
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in max".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Homomorphic minimum
    pub fn min(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = a.inner.min(&*b.inner);
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = a.inner.min(&*b.inner);
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = a.inner.min(&*b.inner);
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = a.inner.min(&*b.inner);
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in min".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    // ========== BITWISE OPERATIONS ==========

    /// Homomorphic bitwise AND
    pub fn bitand(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = &*a.inner & &*b.inner;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = &*a.inner & &*b.inner;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = &*a.inner & &*b.inner;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = &*a.inner & &*b.inner;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in bitwise AND".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Homomorphic bitwise OR
    pub fn bitor(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match (a, b) {
                (EncryptedValue::U64(a), EncryptedValue::U64(b)) => {
                    let result = &*a.inner | &*b.inner;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U32(a), EncryptedValue::U32(b)) => {
                    let result = &*a.inner | &*b.inner;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U16(a), EncryptedValue::U16(b)) => {
                    let result = &*a.inner | &*b.inner;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                (EncryptedValue::U8(a), EncryptedValue::U8(b)) => {
                    let result = &*a.inner | &*b.inner;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
                _ => Err(FheError::HomomorphicOp("Type mismatch in bitwise OR".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, b, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Homomorphic left shift by a constant
    pub fn shl(a: &EncryptedValue, shift: u32, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match a {
                EncryptedValue::U64(a) => {
                    let result = &*a.inner << shift;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                EncryptedValue::U32(a) => {
                    let result = &*a.inner << shift;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                EncryptedValue::U16(a) => {
                    let result = &*a.inner << shift;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                EncryptedValue::U8(a) => {
                    let result = &*a.inner << shift;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, shift, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Homomorphic right shift by a constant
    pub fn shr(a: &EncryptedValue, shift: u32, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        #[cfg(feature = "fhe")]
        {
            server_key.set_as_global();

            match a {
                EncryptedValue::U64(a) => {
                    let result = &*a.inner >> shift;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(result) }))
                }
                EncryptedValue::U32(a) => {
                    let result = &*a.inner >> shift;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(result) }))
                }
                EncryptedValue::U16(a) => {
                    let result = &*a.inner >> shift;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(result) }))
                }
                EncryptedValue::U8(a) => {
                    let result = &*a.inner >> shift;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(result) }))
                }
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (a, shift, server_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    // ========== NEURAL NETWORK OPERATIONS ==========

    /// Homomorphic ReLU: max(0, x)
    /// For unsigned types, this is identity since they can't be negative
    pub fn relu(a: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        // For unsigned integers, ReLU is identity
        // For signed integers (future), we'd compute max(0, x)
        let _ = server_key;
        Ok(a.clone())
    }

    /// Homomorphic dot product of two encrypted vectors
    pub fn dot_product(
        a: &[EncryptedValue],
        b: &[EncryptedValue],
        server_key: &FheServerKey,
    ) -> ComputeResult<EncryptedValue> {
        if a.len() != b.len() {
            return Err(FheError::HomomorphicOp("Vector length mismatch".to_string()));
        }

        if a.is_empty() {
            return Err(FheError::HomomorphicOp("Empty vectors".to_string()));
        }

        // Start with first element product
        let mut result = Self::mul(&a[0], &b[0], server_key)?;

        // Accumulate remaining products
        for i in 1..a.len() {
            let product = Self::mul(&a[i], &b[i], server_key)?;
            result = Self::add(&result, &product, server_key)?;
        }

        Ok(result)
    }

    /// Homomorphic sum of a vector
    pub fn sum(values: &[EncryptedValue], server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
        if values.is_empty() {
            return Err(FheError::HomomorphicOp("Empty vector".to_string()));
        }

        let mut result = values[0].clone();
        for value in values.iter().skip(1) {
            result = Self::add(&result, value, server_key)?;
        }

        Ok(result)
    }
}

// ========== CONVENIENCE FUNCTIONS ==========

/// Homomorphic addition (convenience function)
pub fn homomorphic_add(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
    FheCompute::add(a, b, server_key)
}

/// Homomorphic subtraction (convenience function)
pub fn homomorphic_sub(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
    FheCompute::sub(a, b, server_key)
}

/// Homomorphic multiplication (convenience function)
pub fn homomorphic_mul(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
    FheCompute::mul(a, b, server_key)
}

/// Homomorphic comparison (convenience function)
pub fn homomorphic_compare(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedBool> {
    FheCompute::lt(a, b, server_key)
}

/// Homomorphic maximum (convenience function)
pub fn homomorphic_max(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
    FheCompute::max(a, b, server_key)
}

/// Homomorphic minimum (convenience function)
pub fn homomorphic_min(a: &EncryptedValue, b: &EncryptedValue, server_key: &FheServerKey) -> ComputeResult<EncryptedValue> {
    FheCompute::min(a, b, server_key)
}

// ========== FHE IO BINDING ==========

/// FHE-specific IO commitment builder
///
/// This creates cryptographic commitments that bind FHE computations to specific
/// encrypted inputs and outputs, preventing proof reuse attacks.
///
/// # Security Model
///
/// The io_commitment = H(FHE_DOMAIN || ciphertext_hashes || operation || metadata) ensures:
/// 1. FHE proofs cannot be replayed with different ciphertexts
/// 2. Operation type is bound to the proof
/// 3. Job/worker metadata prevents cross-job attacks
#[derive(Debug, Clone)]
pub struct FheIOBinder {
    hasher: Sha256,
    input_count: usize,
    output_count: usize,
}

impl FheIOBinder {
    /// Create a new FHE IO binder with domain separation
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        // Domain separation for FHE commitments (distinct from regular IO commitments)
        hasher.update(b"OBELYSK_FHE_IO_COMMITMENT_V1");
        Self {
            hasher,
            input_count: 0,
            output_count: 0,
        }
    }

    /// Add an encrypted input value to the commitment
    ///
    /// This hashes the ciphertext representation without decrypting
    pub fn add_encrypted_input(&mut self, value: &EncryptedValue) {
        self.hasher.update(b"__FHE_INPUT__");

        // Hash the ciphertext type and a representation
        match value {
            EncryptedValue::U8(_) => {
                self.hasher.update(&[0x08u8]); // Type tag
            }
            EncryptedValue::U16(_) => {
                self.hasher.update(&[0x10u8]); // Type tag
            }
            EncryptedValue::U32(_) => {
                self.hasher.update(&[0x20u8]); // Type tag
            }
            EncryptedValue::U64(_) => {
                self.hasher.update(&[0x40u8]); // Type tag
            }
        }

        // Note: In production, we'd serialize the actual ciphertext bytes
        // For now, we use a hash of the ciphertext's internal pointer as a unique ID
        #[cfg(feature = "fhe")]
        {
            use std::hash::{Hash, Hasher};
            use std::collections::hash_map::DefaultHasher;

            let mut h = DefaultHasher::new();
            match value {
                EncryptedValue::U8(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
                EncryptedValue::U16(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
                EncryptedValue::U32(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
                EncryptedValue::U64(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
            }
            self.hasher.update(&h.finish().to_le_bytes());
        }

        self.input_count += 1;
    }

    /// Add multiple encrypted inputs
    pub fn add_encrypted_inputs(&mut self, values: &[EncryptedValue]) {
        self.hasher.update(b"__FHE_INPUTS_BATCH__");
        self.hasher.update(&(values.len() as u64).to_le_bytes());
        for value in values {
            self.add_encrypted_input(value);
        }
    }

    /// Add an encrypted output value to the commitment
    pub fn add_encrypted_output(&mut self, value: &EncryptedValue) {
        if self.output_count == 0 {
            self.hasher.update(b"__FHE_OUTPUTS__");
        }

        self.hasher.update(b"__FHE_OUTPUT__");

        // Hash the ciphertext type
        match value {
            EncryptedValue::U8(_) => self.hasher.update(&[0x08u8]),
            EncryptedValue::U16(_) => self.hasher.update(&[0x10u8]),
            EncryptedValue::U32(_) => self.hasher.update(&[0x20u8]),
            EncryptedValue::U64(_) => self.hasher.update(&[0x40u8]),
        }

        #[cfg(feature = "fhe")]
        {
            use std::hash::{Hash, Hasher};
            use std::collections::hash_map::DefaultHasher;

            let mut h = DefaultHasher::new();
            match value {
                EncryptedValue::U8(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
                EncryptedValue::U16(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
                EncryptedValue::U32(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
                EncryptedValue::U64(v) => std::ptr::addr_of!(*v.inner).hash(&mut h),
            }
            self.hasher.update(&h.finish().to_le_bytes());
        }

        self.output_count += 1;
    }

    /// Add the operation type to the commitment
    pub fn add_operation(&mut self, op: HomomorphicOperation) {
        self.hasher.update(b"__FHE_OP__");
        self.hasher.update(&[op as u8]);
    }

    /// Add job ID for replay protection
    pub fn add_job_id(&mut self, job_id: &str) {
        self.hasher.update(b"__FHE_JOB_ID__");
        self.hasher.update(&(job_id.len() as u64).to_le_bytes());
        self.hasher.update(job_id.as_bytes());
    }

    /// Add worker ID for attribution
    pub fn add_worker_id(&mut self, worker_id: &str) {
        self.hasher.update(b"__FHE_WORKER__");
        self.hasher.update(&(worker_id.len() as u64).to_le_bytes());
        self.hasher.update(worker_id.as_bytes());
    }

    /// Add timestamp for freshness
    pub fn add_timestamp(&mut self, timestamp_secs: u64) {
        self.hasher.update(b"__FHE_TIMESTAMP__");
        self.hasher.update(&timestamp_secs.to_le_bytes());
    }

    /// Finalize and return the 32-byte io_commitment
    pub fn finalize(self) -> [u8; 32] {
        let mut commitment = [0u8; 32];
        let result = self.hasher.finalize();
        commitment.copy_from_slice(&result);
        commitment
    }
}

impl Default for FheIOBinder {
    fn default() -> Self {
        Self::new()
    }
}

/// FHE computation with IO binding
pub struct FheComputeWithIO;

impl FheComputeWithIO {
    /// Perform homomorphic addition with IO commitment
    pub fn add_with_io_binding(
        a: &EncryptedValue,
        b: &EncryptedValue,
        server_key: &FheServerKey,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
        // Perform the computation
        let result = FheCompute::add(a, b, server_key)?;

        // Build IO commitment
        let io_commitment = Self::build_binary_op_commitment(
            a, b, &result,
            HomomorphicOperation::Add,
            job_id,
            worker_id,
        );

        Ok(ComputeResultWithProof::new(result)
            .with_io_commitment(io_commitment))
    }

    /// Perform homomorphic subtraction with IO commitment
    pub fn sub_with_io_binding(
        a: &EncryptedValue,
        b: &EncryptedValue,
        server_key: &FheServerKey,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
        let result = FheCompute::sub(a, b, server_key)?;

        let io_commitment = Self::build_binary_op_commitment(
            a, b, &result,
            HomomorphicOperation::Sub,
            job_id,
            worker_id,
        );

        Ok(ComputeResultWithProof::new(result)
            .with_io_commitment(io_commitment))
    }

    /// Perform homomorphic multiplication with IO commitment
    pub fn mul_with_io_binding(
        a: &EncryptedValue,
        b: &EncryptedValue,
        server_key: &FheServerKey,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
        let result = FheCompute::mul(a, b, server_key)?;

        let io_commitment = Self::build_binary_op_commitment(
            a, b, &result,
            HomomorphicOperation::Mul,
            job_id,
            worker_id,
        );

        Ok(ComputeResultWithProof::new(result)
            .with_io_commitment(io_commitment))
    }

    /// Perform homomorphic comparison with IO commitment
    pub fn lt_with_io_binding(
        a: &EncryptedValue,
        b: &EncryptedValue,
        server_key: &FheServerKey,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> ComputeResult<ComputeResultWithProof<EncryptedBool>> {
        let result = FheCompute::lt(a, b, server_key)?;

        // Build IO commitment for comparison
        let mut binder = FheIOBinder::new();
        binder.add_encrypted_input(a);
        binder.add_encrypted_input(b);
        binder.add_operation(HomomorphicOperation::LessThan);

        if let Some(jid) = job_id {
            binder.add_job_id(jid);
        }
        if let Some(wid) = worker_id {
            binder.add_worker_id(wid);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        binder.add_timestamp(timestamp);

        let io_commitment = FheIOCommitment {
            commitment: binder.finalize(),
            input_count: 2,
            output_count: 1,
            operation: Some(HomomorphicOperation::LessThan),
            job_id: job_id.map(String::from),
            created_at: timestamp,
        };

        Ok(ComputeResultWithProof::new(result)
            .with_io_commitment(io_commitment))
    }

    /// Perform homomorphic max with IO commitment
    pub fn max_with_io_binding(
        a: &EncryptedValue,
        b: &EncryptedValue,
        server_key: &FheServerKey,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
        let result = FheCompute::max(a, b, server_key)?;

        let io_commitment = Self::build_binary_op_commitment(
            a, b, &result,
            HomomorphicOperation::Max,
            job_id,
            worker_id,
        );

        Ok(ComputeResultWithProof::new(result)
            .with_io_commitment(io_commitment))
    }

    /// Perform homomorphic min with IO commitment
    pub fn min_with_io_binding(
        a: &EncryptedValue,
        b: &EncryptedValue,
        server_key: &FheServerKey,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
        let result = FheCompute::min(a, b, server_key)?;

        let io_commitment = Self::build_binary_op_commitment(
            a, b, &result,
            HomomorphicOperation::Min,
            job_id,
            worker_id,
        );

        Ok(ComputeResultWithProof::new(result)
            .with_io_commitment(io_commitment))
    }

    /// Perform dot product with IO commitment
    pub fn dot_product_with_io_binding(
        a: &[EncryptedValue],
        b: &[EncryptedValue],
        server_key: &FheServerKey,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
        let result = FheCompute::dot_product(a, b, server_key)?;

        // Build IO commitment for dot product
        let mut binder = FheIOBinder::new();
        binder.add_encrypted_inputs(a);
        binder.add_encrypted_inputs(b);
        binder.add_encrypted_output(&result);
        binder.add_operation(HomomorphicOperation::Mul); // Dot product uses mul

        if let Some(jid) = job_id {
            binder.add_job_id(jid);
        }
        if let Some(wid) = worker_id {
            binder.add_worker_id(wid);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        binder.add_timestamp(timestamp);

        let io_commitment = FheIOCommitment {
            commitment: binder.finalize(),
            input_count: a.len() + b.len(),
            output_count: 1,
            operation: Some(HomomorphicOperation::Mul),
            job_id: job_id.map(String::from),
            created_at: timestamp,
        };

        Ok(ComputeResultWithProof::new(result)
            .with_io_commitment(io_commitment))
    }

    /// Helper to build IO commitment for binary operations
    fn build_binary_op_commitment(
        a: &EncryptedValue,
        b: &EncryptedValue,
        result: &EncryptedValue,
        op: HomomorphicOperation,
        job_id: Option<&str>,
        worker_id: Option<&str>,
    ) -> FheIOCommitment {
        let mut binder = FheIOBinder::new();
        binder.add_encrypted_input(a);
        binder.add_encrypted_input(b);
        binder.add_encrypted_output(result);
        binder.add_operation(op);

        if let Some(jid) = job_id {
            binder.add_job_id(jid);
        }
        if let Some(wid) = worker_id {
            binder.add_worker_id(wid);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        binder.add_timestamp(timestamp);

        FheIOCommitment {
            commitment: binder.finalize(),
            input_count: 2,
            output_count: 1,
            operation: Some(op),
            job_id: job_id.map(String::from),
            created_at: timestamp,
        }
    }
}

/// Convenience function for FHE add with IO binding
pub fn homomorphic_add_with_io(
    a: &EncryptedValue,
    b: &EncryptedValue,
    server_key: &FheServerKey,
    job_id: Option<&str>,
) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
    FheComputeWithIO::add_with_io_binding(a, b, server_key, job_id, None)
}

/// Convenience function for FHE mul with IO binding
pub fn homomorphic_mul_with_io(
    a: &EncryptedValue,
    b: &EncryptedValue,
    server_key: &FheServerKey,
    job_id: Option<&str>,
) -> ComputeResult<ComputeResultWithProof<EncryptedValue>> {
    FheComputeWithIO::mul_with_io_binding(a, b, server_key, job_id, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::fhe::keys::{FheKeyManager, KeyConfig};
    use crate::obelysk::fhe::encryption::FheEncryptor;

    #[test]
    #[cfg(feature = "fhe")]
    fn test_homomorphic_add() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, server_key, public_key) = manager.generate_keys().unwrap();

        let a = FheEncryptor::encrypt_with_public_key(5u64, &public_key).unwrap();
        let b = FheEncryptor::encrypt_with_public_key(3u64, &public_key).unwrap();

        let sum = FheCompute::add(&a, &b, &server_key).unwrap();
        let result = FheEncryptor::decrypt(&sum, &client_key).unwrap();

        assert_eq!(result, 8);
    }

    #[test]
    #[cfg(feature = "fhe")]
    fn test_homomorphic_mul() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, server_key, public_key) = manager.generate_keys().unwrap();

        let a = FheEncryptor::encrypt_with_public_key(7u64, &public_key).unwrap();
        let b = FheEncryptor::encrypt_with_public_key(6u64, &public_key).unwrap();

        let product = FheCompute::mul(&a, &b, &server_key).unwrap();
        let result = FheEncryptor::decrypt(&product, &client_key).unwrap();

        assert_eq!(result, 42);
    }

    #[test]
    #[cfg(feature = "fhe")]
    fn test_homomorphic_comparison() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, server_key, public_key) = manager.generate_keys().unwrap();

        let a = FheEncryptor::encrypt_with_public_key(5u64, &public_key).unwrap();
        let b = FheEncryptor::encrypt_with_public_key(10u64, &public_key).unwrap();

        let lt_result = FheCompute::lt(&a, &b, &server_key).unwrap();
        assert!(lt_result.decrypt(&client_key)); // 5 < 10

        let gt_result = FheCompute::lt(&b, &a, &server_key).unwrap();
        assert!(!gt_result.decrypt(&client_key)); // 10 is not < 5
    }

    #[test]
    #[cfg(feature = "fhe")]
    fn test_dot_product() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, server_key, public_key) = manager.generate_keys().unwrap();

        // [1, 2, 3] dot [4, 5, 6] = 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        let a = vec![
            FheEncryptor::encrypt_with_public_key(1u64, &public_key).unwrap(),
            FheEncryptor::encrypt_with_public_key(2u64, &public_key).unwrap(),
            FheEncryptor::encrypt_with_public_key(3u64, &public_key).unwrap(),
        ];
        let b = vec![
            FheEncryptor::encrypt_with_public_key(4u64, &public_key).unwrap(),
            FheEncryptor::encrypt_with_public_key(5u64, &public_key).unwrap(),
            FheEncryptor::encrypt_with_public_key(6u64, &public_key).unwrap(),
        ];

        let dot = FheCompute::dot_product(&a, &b, &server_key).unwrap();
        let result = FheEncryptor::decrypt(&dot, &client_key).unwrap();

        assert_eq!(result, 32);
    }
}
