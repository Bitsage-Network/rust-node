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
use super::types::{FheError, ComputeResultWithProof};
use std::sync::Arc;

#[cfg(feature = "fhe")]
use tfhe::{
    prelude::*,
    FheUint8, FheUint16, FheUint32, FheUint64, FheBool,
};

/// Result of a homomorphic computation
pub type ComputeResult<T> = Result<T, FheError>;

/// Types of homomorphic operations
#[derive(Debug, Clone, Copy)]
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
