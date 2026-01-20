//! Starknet Account Manager
//!
//! Manages Starknet account loading from keystore and transaction signing
//! for BitSage Network contract interactions.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use starknet::{
    accounts::{Account, Call, ExecutionEncoding, SingleOwnerAccount},
    core::types::FieldElement,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

/// Encrypted keystore format (compatible with starkli/argent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub crypto: KeystoreCrypto,
    pub id: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreCrypto {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

/// Starknet account manager configuration
#[derive(Debug, Clone)]
pub struct AccountManagerConfig {
    /// Path to encrypted keystore file
    pub keystore_path: PathBuf,

    /// Keystore password
    pub keystore_password: String,

    /// Account address
    pub account_address: FieldElement,

    /// Starknet RPC URL
    pub rpc_url: String,

    /// Chain ID (SN_SEPOLIA or SN_MAIN)
    pub chain_id: FieldElement,
}

impl AccountManagerConfig {
    /// Create config from TOML settings
    pub fn from_toml(
        keystore_path: impl AsRef<Path>,
        keystore_password: String,
        account_address: &str,
        rpc_url: String,
        network: &str,
    ) -> Result<Self> {
        let account_address = FieldElement::from_hex_be(account_address)
            .context("Invalid account address")?;

        // Chain IDs (in FieldElement format)
        let chain_id = match network {
            "sepolia" => FieldElement::from_hex_be("0x534e5f5345504f4c4941")?, // SN_SEPOLIA
            "mainnet" => FieldElement::from_hex_be("0x534e5f4d41494e")?,       // SN_MAIN
            _ => return Err(anyhow::anyhow!("Unknown network: {}", network)),
        };

        Ok(Self {
            keystore_path: keystore_path.as_ref().to_path_buf(),
            keystore_password,
            account_address,
            rpc_url,
            chain_id,
        })
    }
}

/// Starknet account manager for signing transactions
pub struct AccountManager {
    config: AccountManagerConfig,
    account: Arc<SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>>,
    provider: Arc<JsonRpcClient<HttpTransport>>,
}

impl AccountManager {
    /// Create a new account manager from configuration
    pub async fn new(config: AccountManagerConfig) -> Result<Self> {
        info!("Initializing Starknet account manager");

        // Load keystore
        let keystore_bytes = std::fs::read(&config.keystore_path)
            .with_context(|| format!("Failed to read keystore: {:?}", config.keystore_path))?;

        let keystore: Keystore = serde_json::from_slice(&keystore_bytes)
            .context("Failed to parse keystore JSON")?;

        // Decrypt private key
        let private_key = Self::decrypt_keystore(&keystore, &config.keystore_password)?;

        debug!("Keystore decrypted successfully");

        // Create signer
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));

        // Create provider
        let provider = JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(&config.rpc_url).context("Invalid RPC URL")?,
        ));
        let provider = Arc::new(provider);

        // Create account
        // Note: SingleOwnerAccount expects JsonRpcClient directly, not Arc
        // We need to create a new provider instance for the account
        let account_provider = JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(&config.rpc_url).context("Invalid RPC URL")?,
        ));

        let account = SingleOwnerAccount::new(
            account_provider,
            signer,
            config.account_address,
            config.chain_id,
            ExecutionEncoding::New,
        );

        info!(
            "Account manager initialized for address: {:#064x}",
            config.account_address
        );

        Ok(Self {
            config,
            account: Arc::new(account),
            provider,
        })
    }

    /// Decrypt keystore using password
    ///
    /// Implements Web3 Secret Storage Definition keystore decryption:
    /// 1. Derive key from password using scrypt KDF
    /// 2. Verify MAC to ensure password is correct
    /// 3. Decrypt ciphertext using AES-128-CTR
    fn decrypt_keystore(keystore: &Keystore, password: &str) -> Result<FieldElement> {
        use aes::Aes128;
        use ctr::cipher::{KeyIvInit, StreamCipher};
        use scrypt::{scrypt, Params as ScryptParams};

        debug!("Decrypting keystore with scrypt KDF");

        // 1. Parse keystore parameters
        let salt = hex::decode(&keystore.crypto.kdfparams.salt)
            .context("Failed to decode salt")?;

        let iv = hex::decode(&keystore.crypto.cipherparams.iv)
            .context("Failed to decode IV")?;

        let ciphertext = hex::decode(&keystore.crypto.ciphertext)
            .context("Failed to decode ciphertext")?;

        let mac = hex::decode(&keystore.crypto.mac)
            .context("Failed to decode MAC")?;

        // 2. Derive key using scrypt
        let scrypt_params = ScryptParams::new(
            keystore.crypto.kdfparams.n.trailing_zeros() as u8, // log_n
            keystore.crypto.kdfparams.r,
            keystore.crypto.kdfparams.p,
            ScryptParams::RECOMMENDED_LEN,
        )
        .context("Invalid scrypt parameters")?;

        let mut derived_key = vec![0u8; keystore.crypto.kdfparams.dklen as usize];
        scrypt(
            password.as_bytes(),
            &salt,
            &scrypt_params,
            &mut derived_key,
        )
        .context("scrypt key derivation failed")?;

        // 3. Verify MAC
        // MAC = keccak256(derived_key[16..32] || ciphertext)
        use sha3::{Digest as _, Keccak256};

        let mut mac_data = Vec::new();
        mac_data.extend_from_slice(&derived_key[16..32]);
        mac_data.extend_from_slice(&ciphertext);

        let computed_mac = Keccak256::digest(&mac_data);

        if computed_mac.as_slice() != mac.as_slice() {
            return Err(anyhow!("MAC verification failed - incorrect password or corrupted keystore"));
        }

        debug!("MAC verified successfully");

        // 4. Decrypt using AES-128-CTR
        let key = &derived_key[0..16];
        let mut cipher = ctr::Ctr64BE::<Aes128>::new(key.into(), iv.as_slice().into());

        let mut plaintext = ciphertext.clone();
        cipher.apply_keystream(&mut plaintext);

        // 5. Convert plaintext to FieldElement
        // The plaintext should be a 32-byte private key
        if plaintext.len() != 32 {
            return Err(anyhow!(
                "Invalid private key length: expected 32 bytes, got {}",
                plaintext.len()
            ));
        }

        // Convert to hex string first, then to FieldElement
        let private_key_hex = format!("0x{}", hex::encode(&plaintext));
        let private_key = FieldElement::from_hex_be(&private_key_hex)
            .context("Failed to parse decrypted private key")?;

        info!("✅ Keystore decrypted successfully using scrypt KDF");

        Ok(private_key)
    }

    /// Get the account address
    pub fn address(&self) -> FieldElement {
        self.config.account_address
    }

    /// Get a reference to the account for transaction signing
    pub fn account(&self) -> &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet> {
        &self.account
    }

    /// Get a reference to the provider
    pub fn provider(&self) -> &JsonRpcClient<HttpTransport> {
        &self.provider
    }

    /// Execute a single contract call
    pub async fn execute_call(
        &self,
        contract_address: FieldElement,
        selector: FieldElement,
        calldata: Vec<FieldElement>,
    ) -> Result<FieldElement> {
        let call = Call {
            to: contract_address,
            selector,
            calldata,
        };

        debug!(
            "Executing call to contract {:#064x}, selector {:#064x}",
            contract_address, selector
        );

        let result = self.account
            .execute(vec![call])
            .send()
            .await
            .context("Failed to execute transaction")?;

        info!("Transaction sent: {:#064x}", result.transaction_hash);

        Ok(result.transaction_hash)
    }

    /// Execute multiple contract calls in a single transaction
    pub async fn execute_calls(&self, calls: Vec<Call>) -> Result<FieldElement> {
        debug!("Executing batch of {} calls", calls.len());

        let result = self.account
            .execute(calls)
            .send()
            .await
            .context("Failed to execute batch transaction")?;

        info!(
            "Batch transaction sent: {:#064x} ({} calls)",
            result.transaction_hash,
            result.transaction_hash
        );

        Ok(result.transaction_hash)
    }

    /// Get the current nonce for this account
    pub async fn get_nonce(&self) -> Result<FieldElement> {
        use starknet::core::types::BlockId;
        use starknet::core::types::BlockTag;

        let nonce = self.provider
            .get_nonce(BlockId::Tag(BlockTag::Pending), self.config.account_address)
            .await
            .context("Failed to get account nonce")?;

        Ok(nonce)
    }

    /// Check account balance (STRK tokens)
    pub async fn get_balance(&self) -> Result<FieldElement> {
        use starknet::core::types::{BlockId, BlockTag, FunctionCall};

        // STRK token address on Sepolia (example - update for actual network)
        let strk_token = FieldElement::from_hex_be(
            "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
        )?;

        let call = FunctionCall {
            contract_address: strk_token,
            entry_point_selector: starknet::core::utils::get_selector_from_name("balanceOf")?,
            calldata: vec![self.config.account_address],
        };

        let result = self.provider
            .call(call, BlockId::Tag(BlockTag::Pending))
            .await
            .context("Failed to get balance")?;

        Ok(result[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_parsing() {
        let keystore_json = r#"{
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": {"iv": "test"},
                "ciphertext": "test",
                "kdf": "scrypt",
                "kdfparams": {
                    "dklen": 32,
                    "n": 8192,
                    "p": 1,
                    "r": 8,
                    "salt": "test"
                },
                "mac": "test"
            },
            "id": "test-id",
            "version": 3
        }"#;

        let keystore: Keystore = serde_json::from_str(keystore_json).unwrap();
        assert_eq!(keystore.version, 3);
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
    }

    #[test]
    fn test_account_address_parsing() {
        let addr = "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344";
        let field_elem = FieldElement::from_hex_be(addr).unwrap();
        assert_eq!(format!("{:#064x}", field_elem), addr);
    }
}
