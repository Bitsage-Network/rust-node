// FHE Encryption Module - Encrypt and decrypt operations
//
// This module provides encryption and decryption functionality:
// - Encrypt plaintext values using client key or public key
// - Decrypt ciphertexts using client key
// - Support for various integer types (u8, u16, u32, u64)
// - Vector encryption for batch processing

use super::keys::{FheClientKey, FhePublicKey};
use super::types::{FheError, SerializedCiphertext, ValueType};

#[cfg(feature = "fhe")]
use tfhe::{
    prelude::*,
    FheUint8, FheUint16, FheUint32, FheUint64,
};

/// Encrypted value wrapper that can hold different integer types
#[derive(Clone)]
pub enum EncryptedValue {
    U8(EncryptedU8),
    U16(EncryptedU16),
    U32(EncryptedU32),
    U64(EncryptedU64),
}

/// Encrypted u8 value
#[derive(Clone)]
pub struct EncryptedU8 {
    #[cfg(feature = "fhe")]
    pub(crate) inner: Arc<FheUint8>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

/// Encrypted u16 value
#[derive(Clone)]
pub struct EncryptedU16 {
    #[cfg(feature = "fhe")]
    pub(crate) inner: Arc<FheUint16>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

/// Encrypted u32 value
#[derive(Clone)]
pub struct EncryptedU32 {
    #[cfg(feature = "fhe")]
    pub(crate) inner: Arc<FheUint32>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

/// Encrypted u64 value
#[derive(Clone)]
pub struct EncryptedU64 {
    #[cfg(feature = "fhe")]
    pub(crate) inner: Arc<FheUint64>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

impl EncryptedValue {
    /// Get the value type of this encrypted value
    pub fn value_type(&self) -> ValueType {
        match self {
            EncryptedValue::U8(_) => ValueType::U8,
            EncryptedValue::U16(_) => ValueType::U16,
            EncryptedValue::U32(_) => ValueType::U32,
            EncryptedValue::U64(_) => ValueType::U64,
        }
    }

    /// Serialize the encrypted value for storage/transmission
    pub fn serialize(&self) -> Result<SerializedCiphertext, FheError> {
        #[cfg(feature = "fhe")]
        {
            let (data, value_type) = match self {
                EncryptedValue::U8(v) => {
                    let data = bincode::serialize(&*v.inner)
                        .map_err(|e| FheError::Serialization(e.to_string()))?;
                    (data, ValueType::U8)
                }
                EncryptedValue::U16(v) => {
                    let data = bincode::serialize(&*v.inner)
                        .map_err(|e| FheError::Serialization(e.to_string()))?;
                    (data, ValueType::U16)
                }
                EncryptedValue::U32(v) => {
                    let data = bincode::serialize(&*v.inner)
                        .map_err(|e| FheError::Serialization(e.to_string()))?;
                    (data, ValueType::U32)
                }
                EncryptedValue::U64(v) => {
                    let data = bincode::serialize(&*v.inner)
                        .map_err(|e| FheError::Serialization(e.to_string()))?;
                    (data, ValueType::U64)
                }
            };

            Ok(SerializedCiphertext {
                data,
                value_type,
                version: 1,
            })
        }
        #[cfg(not(feature = "fhe"))]
        {
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Deserialize an encrypted value from storage
    pub fn deserialize(serialized: &SerializedCiphertext) -> Result<Self, FheError> {
        #[cfg(feature = "fhe")]
        {
            match serialized.value_type {
                ValueType::U8 => {
                    let inner: FheUint8 = bincode::deserialize(&serialized.data)
                        .map_err(|e| FheError::Deserialization(e.to_string()))?;
                    Ok(EncryptedValue::U8(EncryptedU8 { inner: Arc::new(inner) }))
                }
                ValueType::U16 => {
                    let inner: FheUint16 = bincode::deserialize(&serialized.data)
                        .map_err(|e| FheError::Deserialization(e.to_string()))?;
                    Ok(EncryptedValue::U16(EncryptedU16 { inner: Arc::new(inner) }))
                }
                ValueType::U32 => {
                    let inner: FheUint32 = bincode::deserialize(&serialized.data)
                        .map_err(|e| FheError::Deserialization(e.to_string()))?;
                    Ok(EncryptedValue::U32(EncryptedU32 { inner: Arc::new(inner) }))
                }
                ValueType::U64 => {
                    let inner: FheUint64 = bincode::deserialize(&serialized.data)
                        .map_err(|e| FheError::Deserialization(e.to_string()))?;
                    Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(inner) }))
                }
                _ => Err(FheError::Deserialization("Unsupported value type".to_string())),
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = serialized;
            Err(FheError::FeatureNotEnabled)
        }
    }
}

/// Vector of encrypted values for batch operations
#[derive(Clone)]
pub struct EncryptedVector {
    pub values: Vec<EncryptedValue>,
}

impl EncryptedVector {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { values: Vec::with_capacity(capacity) }
    }

    pub fn push(&mut self, value: EncryptedValue) {
        self.values.push(value);
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl Default for EncryptedVector {
    fn default() -> Self {
        Self::new()
    }
}

/// FHE encryptor for encrypt/decrypt operations
pub struct FheEncryptor;

impl FheEncryptor {
    /// Encrypt a u64 value using the public key
    pub fn encrypt_with_public_key(value: u64, public_key: &FhePublicKey) -> Result<EncryptedValue, FheError> {
        #[cfg(feature = "fhe")]
        {
            // Use CompactPublicKey for encryption
            let encrypted = FheUint64::try_encrypt(value, public_key.inner())
                .map_err(|e| FheError::Encryption(format!("Public key encryption failed: {:?}", e)))?;
            Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(encrypted) }))
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (value, public_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Encrypt a u64 value using the client key (faster than public key)
    pub fn encrypt_with_client_key(value: u64, client_key: &FheClientKey) -> Result<EncryptedValue, FheError> {
        #[cfg(feature = "fhe")]
        {
            let encrypted = FheUint64::encrypt(value, client_key.inner());
            Ok(EncryptedValue::U64(EncryptedU64 { inner: Arc::new(encrypted) }))
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (value, client_key);
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Decrypt an encrypted value using the client key
    pub fn decrypt(ciphertext: &EncryptedValue, client_key: &FheClientKey) -> Result<u64, FheError> {
        #[cfg(feature = "fhe")]
        {
            match ciphertext {
                EncryptedValue::U8(v) => {
                    let decrypted: u8 = v.inner.decrypt(client_key.inner());
                    Ok(decrypted as u64)
                }
                EncryptedValue::U16(v) => {
                    let decrypted: u16 = v.inner.decrypt(client_key.inner());
                    Ok(decrypted as u64)
                }
                EncryptedValue::U32(v) => {
                    let decrypted: u32 = v.inner.decrypt(client_key.inner());
                    Ok(decrypted as u64)
                }
                EncryptedValue::U64(v) => {
                    let decrypted: u64 = v.inner.decrypt(client_key.inner());
                    Ok(decrypted)
                }
            }
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = (ciphertext, client_key);
            Err(FheError::FeatureNotEnabled)
        }
    }
}

// Convenience functions for specific types

/// Encrypt a u8 value
pub fn encrypt_u8(value: u8, client_key: &FheClientKey) -> Result<EncryptedU8, FheError> {
    #[cfg(feature = "fhe")]
    {
        let encrypted = FheUint8::encrypt(value, client_key.inner());
        Ok(EncryptedU8 { inner: Arc::new(encrypted) })
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (value, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Encrypt a u16 value
pub fn encrypt_u16(value: u16, client_key: &FheClientKey) -> Result<EncryptedU16, FheError> {
    #[cfg(feature = "fhe")]
    {
        let encrypted = FheUint16::encrypt(value, client_key.inner());
        Ok(EncryptedU16 { inner: Arc::new(encrypted) })
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (value, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Encrypt a u32 value
pub fn encrypt_u32(value: u32, client_key: &FheClientKey) -> Result<EncryptedU32, FheError> {
    #[cfg(feature = "fhe")]
    {
        let encrypted = FheUint32::encrypt(value, client_key.inner());
        Ok(EncryptedU32 { inner: Arc::new(encrypted) })
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (value, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Encrypt a u64 value
pub fn encrypt_u64(value: u64, client_key: &FheClientKey) -> Result<EncryptedU64, FheError> {
    #[cfg(feature = "fhe")]
    {
        let encrypted = FheUint64::encrypt(value, client_key.inner());
        Ok(EncryptedU64 { inner: Arc::new(encrypted) })
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (value, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Decrypt a u8 value
pub fn decrypt_u8(ciphertext: &EncryptedU8, client_key: &FheClientKey) -> Result<u8, FheError> {
    #[cfg(feature = "fhe")]
    {
        Ok(ciphertext.inner.decrypt(client_key.inner()))
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (ciphertext, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Decrypt a u16 value
pub fn decrypt_u16(ciphertext: &EncryptedU16, client_key: &FheClientKey) -> Result<u16, FheError> {
    #[cfg(feature = "fhe")]
    {
        Ok(ciphertext.inner.decrypt(client_key.inner()))
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (ciphertext, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Decrypt a u32 value
pub fn decrypt_u32(ciphertext: &EncryptedU32, client_key: &FheClientKey) -> Result<u32, FheError> {
    #[cfg(feature = "fhe")]
    {
        Ok(ciphertext.inner.decrypt(client_key.inner()))
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (ciphertext, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Decrypt a u64 value
pub fn decrypt_u64(ciphertext: &EncryptedU64, client_key: &FheClientKey) -> Result<u64, FheError> {
    #[cfg(feature = "fhe")]
    {
        Ok(ciphertext.inner.decrypt(client_key.inner()))
    }
    #[cfg(not(feature = "fhe"))]
    {
        let _ = (ciphertext, client_key);
        Err(FheError::FeatureNotEnabled)
    }
}

/// Encrypt a vector of u64 values
pub fn encrypt_vector(values: &[u64], public_key: &FhePublicKey) -> Result<EncryptedVector, FheError> {
    let mut result = EncryptedVector::with_capacity(values.len());
    for &value in values {
        let encrypted = FheEncryptor::encrypt_with_public_key(value, public_key)?;
        result.push(encrypted);
    }
    Ok(result)
}

/// Decrypt a vector of encrypted values
pub fn decrypt_vector(ciphertexts: &EncryptedVector, client_key: &FheClientKey) -> Result<Vec<u64>, FheError> {
    let mut result = Vec::with_capacity(ciphertexts.len());
    for ct in &ciphertexts.values {
        let decrypted = FheEncryptor::decrypt(ct, client_key)?;
        result.push(decrypted);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::fhe::keys::{FheKeyManager, KeyConfig};

    #[test]
    #[cfg(feature = "fhe")]
    fn test_encrypt_decrypt_u64() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, _server_key, public_key) = manager.generate_keys().unwrap();

        let original = 42u64;
        let encrypted = FheEncryptor::encrypt_with_public_key(original, &public_key).unwrap();
        let decrypted = FheEncryptor::decrypt(&encrypted, &client_key).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    #[cfg(feature = "fhe")]
    fn test_encrypt_decrypt_specific_types() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, _, _) = manager.generate_keys().unwrap();

        // Test u8
        let val_u8 = 255u8;
        let enc_u8 = encrypt_u8(val_u8, &client_key).unwrap();
        let dec_u8 = decrypt_u8(&enc_u8, &client_key).unwrap();
        assert_eq!(val_u8, dec_u8);

        // Test u32
        let val_u32 = 1_000_000u32;
        let enc_u32 = encrypt_u32(val_u32, &client_key).unwrap();
        let dec_u32 = decrypt_u32(&enc_u32, &client_key).unwrap();
        assert_eq!(val_u32, dec_u32);
    }

    #[test]
    #[cfg(feature = "fhe")]
    fn test_vector_encryption() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, _, public_key) = manager.generate_keys().unwrap();

        let values = vec![1u64, 2u64, 3u64, 4u64, 5u64];
        let encrypted = encrypt_vector(&values, &public_key).unwrap();
        let decrypted = decrypt_vector(&encrypted, &client_key).unwrap();

        assert_eq!(values, decrypted);
    }
}
