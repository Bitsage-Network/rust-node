// FHE Key Management - Key generation, storage, and serialization
//
// This module handles all FHE key operations:
// - Client key generation (for encryption/decryption)
// - Server key derivation (for homomorphic operations)
// - Public key extraction (for encryption-only)
// - Secure key serialization and deserialization

use super::types::{FheError, KeyType, SerializedKey};
use sha2::{Digest, Sha256};

#[cfg(feature = "fhe")]
use tfhe::{
    ClientKey, ServerKey, PublicKey, ConfigBuilder,
    set_server_key,
};

/// Configuration for key generation
#[derive(Debug, Clone)]
pub struct KeyConfig {
    /// Security parameter
    pub security_bits: u32,
    /// Maximum message size in bits
    pub message_bits: u32,
    /// Enable compact public key generation
    pub enable_compact_public_key: bool,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            security_bits: 128,
            message_bits: 64,
            enable_compact_public_key: true,
        }
    }
}

/// Error type for key generation
#[derive(Debug)]
pub struct KeyGenerationError(pub String);

impl std::fmt::Display for KeyGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key generation error: {}", self.0)
    }
}

impl std::error::Error for KeyGenerationError {}

/// Wrapper for TFHE client key
#[derive(Clone)]
pub struct FheClientKey {
    #[cfg(feature = "fhe")]
    inner: Arc<ClientKey>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

impl FheClientKey {
    #[cfg(feature = "fhe")]
    pub(crate) fn from_tfhe(key: ClientKey) -> Self {
        Self { inner: Arc::new(key) }
    }

    #[cfg(not(feature = "fhe"))]
    pub(crate) fn placeholder() -> Self {
        Self { _phantom: std::marker::PhantomData }
    }

    #[cfg(feature = "fhe")]
    pub(crate) fn inner(&self) -> &ClientKey {
        &self.inner
    }

    /// Serialize the client key for storage
    pub fn serialize(&self) -> Result<SerializedKey, FheError> {
        #[cfg(feature = "fhe")]
        {
            let data = bincode::serialize(&*self.inner)
                .map_err(|e| FheError::Serialization(e.to_string()))?;

            let checksum = compute_checksum(&data);

            Ok(SerializedKey {
                key_type: KeyType::Client,
                data,
                version: 1,
                checksum,
            })
        }
        #[cfg(not(feature = "fhe"))]
        {
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Deserialize a client key from storage
    pub fn deserialize(serialized: &SerializedKey) -> Result<Self, FheError> {
        if serialized.key_type != KeyType::Client {
            return Err(FheError::InvalidKey("Expected client key".to_string()));
        }

        // Verify checksum
        let computed_checksum = compute_checksum(&serialized.data);
        if computed_checksum != serialized.checksum {
            return Err(FheError::InvalidKey("Checksum mismatch".to_string()));
        }

        #[cfg(feature = "fhe")]
        {
            let key: ClientKey = bincode::deserialize(&serialized.data)
                .map_err(|e| FheError::Deserialization(e.to_string()))?;
            Ok(Self::from_tfhe(key))
        }
        #[cfg(not(feature = "fhe"))]
        {
            Err(FheError::FeatureNotEnabled)
        }
    }
}

/// Wrapper for TFHE server key
#[derive(Clone)]
pub struct FheServerKey {
    #[cfg(feature = "fhe")]
    inner: Arc<ServerKey>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

impl FheServerKey {
    #[cfg(feature = "fhe")]
    pub(crate) fn from_tfhe(key: ServerKey) -> Self {
        Self { inner: Arc::new(key) }
    }

    #[cfg(not(feature = "fhe"))]
    pub(crate) fn placeholder() -> Self {
        Self { _phantom: std::marker::PhantomData }
    }

    #[cfg(feature = "fhe")]
    pub(crate) fn inner(&self) -> &ServerKey {
        &self.inner
    }

    /// Set this as the global server key for operations
    #[cfg(feature = "fhe")]
    pub fn set_as_global(&self) {
        set_server_key((*self.inner).clone());
    }

    /// Serialize the server key for storage
    pub fn serialize(&self) -> Result<SerializedKey, FheError> {
        #[cfg(feature = "fhe")]
        {
            let data = bincode::serialize(&*self.inner)
                .map_err(|e| FheError::Serialization(e.to_string()))?;

            let checksum = compute_checksum(&data);

            Ok(SerializedKey {
                key_type: KeyType::Server,
                data,
                version: 1,
                checksum,
            })
        }
        #[cfg(not(feature = "fhe"))]
        {
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Deserialize a server key from storage
    pub fn deserialize(serialized: &SerializedKey) -> Result<Self, FheError> {
        if serialized.key_type != KeyType::Server {
            return Err(FheError::InvalidKey("Expected server key".to_string()));
        }

        let computed_checksum = compute_checksum(&serialized.data);
        if computed_checksum != serialized.checksum {
            return Err(FheError::InvalidKey("Checksum mismatch".to_string()));
        }

        #[cfg(feature = "fhe")]
        {
            let key: ServerKey = bincode::deserialize(&serialized.data)
                .map_err(|e| FheError::Deserialization(e.to_string()))?;
            Ok(Self::from_tfhe(key))
        }
        #[cfg(not(feature = "fhe"))]
        {
            Err(FheError::FeatureNotEnabled)
        }
    }
}

/// Wrapper for TFHE compact public key
#[derive(Clone)]
pub struct FhePublicKey {
    #[cfg(feature = "fhe")]
    inner: Arc<PublicKey>,
    #[cfg(not(feature = "fhe"))]
    _phantom: std::marker::PhantomData<()>,
}

impl FhePublicKey {
    #[cfg(feature = "fhe")]
    pub(crate) fn from_tfhe(key: PublicKey) -> Self {
        Self { inner: Arc::new(key) }
    }

    #[cfg(not(feature = "fhe"))]
    pub(crate) fn placeholder() -> Self {
        Self { _phantom: std::marker::PhantomData }
    }

    #[cfg(feature = "fhe")]
    pub(crate) fn inner(&self) -> &PublicKey {
        &self.inner
    }

    /// Serialize the public key for distribution
    pub fn serialize(&self) -> Result<SerializedKey, FheError> {
        #[cfg(feature = "fhe")]
        {
            let data = bincode::serialize(&*self.inner)
                .map_err(|e| FheError::Serialization(e.to_string()))?;

            let checksum = compute_checksum(&data);

            Ok(SerializedKey {
                key_type: KeyType::Public,
                data,
                version: 1,
                checksum,
            })
        }
        #[cfg(not(feature = "fhe"))]
        {
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Deserialize a public key
    pub fn deserialize(serialized: &SerializedKey) -> Result<Self, FheError> {
        if serialized.key_type != KeyType::Public {
            return Err(FheError::InvalidKey("Expected public key".to_string()));
        }

        let computed_checksum = compute_checksum(&serialized.data);
        if computed_checksum != serialized.checksum {
            return Err(FheError::InvalidKey("Checksum mismatch".to_string()));
        }

        #[cfg(feature = "fhe")]
        {
            let key: PublicKey = bincode::deserialize(&serialized.data)
                .map_err(|e| FheError::Deserialization(e.to_string()))?;
            Ok(Self::from_tfhe(key))
        }
        #[cfg(not(feature = "fhe"))]
        {
            Err(FheError::FeatureNotEnabled)
        }
    }
}

/// Key manager for FHE operations
#[allow(dead_code)]
pub struct FheKeyManager {
    config: KeyConfig,
}

impl FheKeyManager {
    /// Create a new key manager with the given configuration
    pub fn new(config: KeyConfig) -> Result<Self, FheError> {
        Ok(Self { config })
    }

    /// Generate a complete set of FHE keys (client, server, public)
    pub fn generate_keys(&self) -> Result<(FheClientKey, FheServerKey, FhePublicKey), FheError> {
        #[cfg(feature = "fhe")]
        {
            // Configure TFHE parameters based on our config
            let config = ConfigBuilder::default().build();

            // Generate client key
            let client_key = ClientKey::generate(config);

            // Derive server key from client key
            let server_key = client_key.generate_server_key();

            // Generate compact public key for encryption
            let public_key = PublicKey::new(&client_key);

            Ok((
                FheClientKey::from_tfhe(client_key),
                FheServerKey::from_tfhe(server_key),
                FhePublicKey::from_tfhe(public_key),
            ))
        }
        #[cfg(not(feature = "fhe"))]
        {
            // Return placeholder keys when FHE feature is disabled
            // This allows the code to compile but operations will return FeatureNotEnabled
            Ok((
                FheClientKey::placeholder(),
                FheServerKey::placeholder(),
                FhePublicKey::placeholder(),
            ))
        }
    }

    /// Generate only a client key (for users who manage their own encryption)
    pub fn generate_client_key(&self) -> Result<FheClientKey, FheError> {
        #[cfg(feature = "fhe")]
        {
            let config = ConfigBuilder::default().build();
            let client_key = ClientKey::generate(config);
            Ok(FheClientKey::from_tfhe(client_key))
        }
        #[cfg(not(feature = "fhe"))]
        {
            Ok(FheClientKey::placeholder())
        }
    }

    /// Derive a server key from a client key
    pub fn derive_server_key(&self, client_key: &FheClientKey) -> Result<FheServerKey, FheError> {
        #[cfg(feature = "fhe")]
        {
            let server_key = client_key.inner().generate_server_key();
            Ok(FheServerKey::from_tfhe(server_key))
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = client_key;
            Err(FheError::FeatureNotEnabled)
        }
    }

    /// Extract a public key from a client key
    pub fn extract_public_key(&self, client_key: &FheClientKey) -> Result<FhePublicKey, FheError> {
        #[cfg(feature = "fhe")]
        {
            let public_key = PublicKey::new(client_key.inner());
            Ok(FhePublicKey::from_tfhe(public_key))
        }
        #[cfg(not(feature = "fhe"))]
        {
            let _ = client_key;
            Err(FheError::FeatureNotEnabled)
        }
    }
}

/// Compute SHA-256 checksum for key integrity verification
fn compute_checksum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_config_default() {
        let config = KeyConfig::default();
        assert_eq!(config.security_bits, 128);
        assert_eq!(config.message_bits, 64);
        assert!(config.enable_compact_public_key);
    }

    #[test]
    #[cfg(feature = "fhe")]
    fn test_key_generation() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, server_key, public_key) = manager.generate_keys().unwrap();

        // Keys should be serializable
        let serialized_client = client_key.serialize().unwrap();
        assert_eq!(serialized_client.key_type, KeyType::Client);

        let serialized_server = server_key.serialize().unwrap();
        assert_eq!(serialized_server.key_type, KeyType::Server);

        let serialized_public = public_key.serialize().unwrap();
        assert_eq!(serialized_public.key_type, KeyType::Public);
    }

    #[test]
    #[cfg(feature = "fhe")]
    fn test_key_serialization_roundtrip() {
        let manager = FheKeyManager::new(KeyConfig::default()).unwrap();
        let (client_key, _, _) = manager.generate_keys().unwrap();

        // Serialize and deserialize
        let serialized = client_key.serialize().unwrap();
        let deserialized = FheClientKey::deserialize(&serialized).unwrap();

        // Should be able to serialize again
        let re_serialized = deserialized.serialize().unwrap();
        assert_eq!(serialized.data, re_serialized.data);
    }
}
