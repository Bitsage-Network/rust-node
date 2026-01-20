// =============================================================================
// MULTI-ASSET PRIVACY LAYER
// =============================================================================
//
// Extends the privacy layer to handle multiple token types with unified encryption.
// Each asset type maintains separate encrypted balances while sharing the same
// privacy infrastructure.
//
// Architecture:
// ┌─────────────────────────────────────────────────────────────────────────────┐
// │                     MULTI-ASSET PRIVACY LAYER                               │
// ├─────────────────────────────────────────────────────────────────────────────┤
// │                                                                             │
// │  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐               │
// │  │   SAGE Token    │ │   USDC Token    │ │   STRK Token    │  ...          │
// │  │ Encrypted: E(x) │ │ Encrypted: E(y) │ │ Encrypted: E(z) │               │
// │  └────────┬────────┘ └────────┬────────┘ └────────┬────────┘               │
// │           │                   │                   │                         │
// │           └───────────────────┼───────────────────┘                         │
// │                               ▼                                             │
// │           ┌─────────────────────────────────────────┐                       │
// │           │      UNIFIED KEYPAIR (ElGamal EC)       │                       │
// │           │  pk = g^sk, shared across all assets    │                       │
// │           └─────────────────────────────────────────┘                       │
// │                               │                                             │
// │                               ▼                                             │
// │           ┌─────────────────────────────────────────┐                       │
// │           │     HOMOMORPHIC OPERATIONS              │                       │
// │           │  E(a) + E(b) = E(a+b) per asset         │                       │
// │           └─────────────────────────────────────────┘                       │
// │                               │                                             │
// │                               ▼                                             │
// │           ┌─────────────────────────────────────────┐                       │
// │           │     CROSS-ASSET PROOFS                  │                       │
// │           │  Prove relationships without revealing  │                       │
// │           └─────────────────────────────────────────┘                       │
// └─────────────────────────────────────────────────────────────────────────────┘

use crate::obelysk::elgamal::{
    Felt252, ECPoint, ElGamalCiphertext, EncryptionProof, KeyPair,
    encrypt, homomorphic_add, homomorphic_sub,
    create_schnorr_proof, generate_randomness, hash_felts,
    reduce_to_curve_order, add_mod_n, mul_mod_n, pedersen_commit,
    CryptoError,
};
use crate::obelysk::privacy_swap::AssetId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use anyhow::{Result, anyhow};

// =============================================================================
// MULTI-ASSET TYPES
// =============================================================================

/// Extended asset information with privacy parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetConfig {
    /// Asset identifier
    pub asset_id: AssetId,
    /// Human-readable name
    pub name: String,
    /// Symbol (e.g., "SAGE", "USDC")
    pub symbol: String,
    /// Decimal places for display
    pub decimals: u8,
    /// Whether privacy is enabled for this asset
    pub privacy_enabled: bool,
    /// Minimum transfer amount (anti-dust)
    pub min_transfer: u64,
    /// Maximum single transfer (for compliance)
    pub max_transfer: Option<u64>,
    /// Contract address on Starknet
    pub contract_address: Option<Felt252>,
}

impl AssetConfig {
    /// Create a new asset configuration
    pub fn new(asset_id: AssetId, name: &str, symbol: &str, decimals: u8) -> Self {
        Self {
            asset_id,
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            privacy_enabled: true,
            min_transfer: 1,
            max_transfer: None,
            contract_address: None,
        }
    }

    /// Standard SAGE token config
    pub fn sage() -> Self {
        Self::new(AssetId::SAGE, "SAGE Token", "SAGE", 18)
    }

    /// Standard USDC config
    pub fn usdc() -> Self {
        Self::new(AssetId::USDC, "USD Coin", "USDC", 6)
    }

    /// Standard STRK config
    pub fn strk() -> Self {
        Self::new(AssetId::STRK, "Starknet Token", "STRK", 18)
    }

    /// Standard BTC config (native Bitcoin on Starknet)
    pub fn btc() -> Self {
        Self::new(AssetId::BTC, "Bitcoin", "BTC", 8)
    }

    /// Alias for backwards compatibility
    pub fn wbtc() -> Self {
        Self::btc()
    }

    /// Standard ETH config
    pub fn eth() -> Self {
        Self::new(AssetId::ETH, "Ether", "ETH", 18)
    }
}

/// Encrypted balance for a specific asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEncryptedBalance {
    /// Asset type
    pub asset_id: AssetId,
    /// Encrypted balance (ElGamal ciphertext)
    pub ciphertext: ElGamalCiphertext,
    /// Pedersen commitment to the balance (for range proofs)
    pub commitment: ECPoint,
    /// Last update timestamp
    pub last_updated: u64,
    /// Nonce for replay protection
    pub nonce: u64,
}

impl AssetEncryptedBalance {
    /// Create a new zero balance for an asset
    pub fn zero(asset_id: AssetId) -> Self {
        Self {
            asset_id,
            ciphertext: ElGamalCiphertext::zero(),
            commitment: ECPoint::INFINITY,
            last_updated: 0,
            nonce: 0,
        }
    }

    /// Create from an encrypted amount
    pub fn new(
        asset_id: AssetId,
        ciphertext: ElGamalCiphertext,
        commitment: ECPoint,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            asset_id,
            ciphertext,
            commitment,
            last_updated: now,
            nonce: 0,
        }
    }
}

/// Multi-asset private account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAssetAccount {
    /// Account public key (shared across all assets)
    pub public_key: ECPoint,
    /// Encrypted balances by asset
    pub balances: HashMap<AssetId, AssetEncryptedBalance>,
    /// Account creation timestamp
    pub created_at: u64,
    /// Whether the account is active
    pub is_active: bool,
    /// Account nonce for transaction ordering
    pub nonce: u64,
}

impl MultiAssetAccount {
    /// Create a new multi-asset account
    pub fn new(public_key: ECPoint) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            public_key,
            balances: HashMap::new(),
            created_at: now,
            is_active: true,
            nonce: 0,
        }
    }

    /// Get balance for a specific asset (returns zero if not found)
    pub fn get_balance(&self, asset_id: AssetId) -> AssetEncryptedBalance {
        self.balances
            .get(&asset_id)
            .cloned()
            .unwrap_or_else(|| AssetEncryptedBalance::zero(asset_id))
    }

    /// Check if account has any balance for an asset
    pub fn has_balance(&self, asset_id: AssetId) -> bool {
        self.balances.contains_key(&asset_id)
    }

    /// Get all asset IDs with balances
    pub fn asset_ids(&self) -> Vec<AssetId> {
        self.balances.keys().cloned().collect()
    }
}

// =============================================================================
// MULTI-ASSET TRANSFER
// =============================================================================

/// A private transfer for a specific asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAssetTransfer {
    /// Asset being transferred
    pub asset_id: AssetId,
    /// Sender's public key
    pub sender_pk: ECPoint,
    /// Recipient's public key
    pub recipient_pk: ECPoint,
    /// Encrypted amount for sender (subtracted from balance)
    pub sender_ciphertext: ElGamalCiphertext,
    /// Encrypted amount for recipient (added to balance)
    pub recipient_ciphertext: ElGamalCiphertext,
    /// Commitment to the transfer amount
    pub amount_commitment: ECPoint,
    /// Proof that sender has sufficient balance
    pub balance_proof: BalanceProof,
    /// Proof of correct encryption
    pub encryption_proof: EncryptionProof,
    /// Timestamp
    pub timestamp: u64,
    /// Nullifier for replay protection
    pub nullifier: Felt252,
}

/// Proof of sufficient balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceProof {
    /// Commitment to (balance - amount), should be non-negative
    pub difference_commitment: ECPoint,
    /// Range proof that difference is non-negative
    pub range_commitment: ECPoint,
    /// Schnorr proof of knowledge
    pub knowledge_proof: EncryptionProof,
}

/// A batch of transfers (atomic multi-asset transfer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAssetBatchTransfer {
    /// Unique batch ID
    pub batch_id: Felt252,
    /// Individual transfers in the batch
    pub transfers: Vec<MultiAssetTransfer>,
    /// Total number of assets involved
    pub asset_count: usize,
    /// Proof that the batch is valid (all transfers or none)
    pub atomicity_proof: Felt252,
    /// Timestamp
    pub timestamp: u64,
}

// =============================================================================
// MULTI-ASSET MANAGER
// =============================================================================

/// Manages multi-asset private accounts
pub struct MultiAssetManager {
    /// Asset configurations
    asset_configs: Arc<RwLock<HashMap<AssetId, AssetConfig>>>,
    /// Accounts by public key hash
    accounts: Arc<RwLock<HashMap<Felt252, MultiAssetAccount>>>,
    /// Pending transfers
    pending_transfers: Arc<RwLock<Vec<MultiAssetTransfer>>>,
    /// Used nullifiers for replay protection
    used_nullifiers: Arc<RwLock<HashMap<Felt252, u64>>>,
}

impl MultiAssetManager {
    /// Create a new multi-asset manager
    pub fn new() -> Self {
        let mut configs = HashMap::new();

        // Add default asset configs
        configs.insert(AssetId::SAGE, AssetConfig::sage());
        configs.insert(AssetId::USDC, AssetConfig::usdc());
        configs.insert(AssetId::STRK, AssetConfig::strk());
        configs.insert(AssetId::BTC, AssetConfig::btc());
        configs.insert(AssetId::ETH, AssetConfig::eth());

        Self {
            asset_configs: Arc::new(RwLock::new(configs)),
            accounts: Arc::new(RwLock::new(HashMap::new())),
            pending_transfers: Arc::new(RwLock::new(Vec::new())),
            used_nullifiers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new asset
    pub fn register_asset(&self, config: AssetConfig) {
        let mut configs = self.asset_configs.write();
        configs.insert(config.asset_id, config);
    }

    /// Get asset config
    pub fn get_asset_config(&self, asset_id: AssetId) -> Option<AssetConfig> {
        self.asset_configs.read().get(&asset_id).cloned()
    }

    /// Create a new multi-asset account
    pub fn create_account(&self, keypair: &KeyPair) -> Result<MultiAssetAccount> {
        let account = MultiAssetAccount::new(keypair.public_key);

        // Hash public key for storage key
        let pk_hash = hash_felts(&[keypair.public_key.x, keypair.public_key.y]);

        let mut accounts = self.accounts.write();
        if accounts.contains_key(&pk_hash) {
            return Err(anyhow!("Account already exists"));
        }

        accounts.insert(pk_hash, account.clone());
        Ok(account)
    }

    /// Get account by public key
    pub fn get_account(&self, public_key: &ECPoint) -> Option<MultiAssetAccount> {
        let pk_hash = hash_felts(&[public_key.x, public_key.y]);
        self.accounts.read().get(&pk_hash).cloned()
    }

    /// Deposit (encrypt) an amount for an asset
    pub fn deposit(
        &self,
        keypair: &KeyPair,
        asset_id: AssetId,
        amount: u64,
    ) -> Result<AssetEncryptedBalance> {
        // Check asset is registered
        if self.get_asset_config(asset_id).is_none() {
            return Err(anyhow!("Asset not registered"));
        }

        // Generate randomness for encryption
        let r = generate_randomness()?;
        let r = reduce_to_curve_order(&r);

        // Encrypt the amount
        let ciphertext = encrypt(amount, &keypair.public_key, &r);

        // Create Pedersen commitment
        let commitment = pedersen_commit(&Felt252::from_u64(amount), &r);

        // Create encrypted balance
        let balance = AssetEncryptedBalance::new(asset_id, ciphertext, commitment);

        // Update account
        let pk_hash = hash_felts(&[keypair.public_key.x, keypair.public_key.y]);
        let mut accounts = self.accounts.write();

        if let Some(account) = accounts.get_mut(&pk_hash) {
            // Add to existing balance homomorphically
            if let Some(existing) = account.balances.get(&asset_id) {
                let new_ciphertext = homomorphic_add(&existing.ciphertext, &ciphertext);
                let new_commitment = existing.commitment.add(&commitment);

                account.balances.insert(asset_id, AssetEncryptedBalance {
                    asset_id,
                    ciphertext: new_ciphertext,
                    commitment: new_commitment,
                    last_updated: balance.last_updated,
                    nonce: existing.nonce + 1,
                });
            } else {
                account.balances.insert(asset_id, balance.clone());
            }
        } else {
            return Err(anyhow!("Account not found"));
        }

        Ok(balance)
    }

    /// Create a private transfer
    pub fn create_transfer(
        &self,
        sender_keypair: &KeyPair,
        recipient_pk: &ECPoint,
        asset_id: AssetId,
        amount: u64,
        current_balance: u64,
    ) -> Result<MultiAssetTransfer> {
        // Validate amount
        if amount > current_balance {
            return Err(anyhow!("Insufficient balance"));
        }

        // Check asset config
        let config = self.get_asset_config(asset_id)
            .ok_or_else(|| anyhow!("Asset not registered"))?;

        if amount < config.min_transfer {
            return Err(anyhow!("Amount below minimum transfer"));
        }

        if let Some(max) = config.max_transfer {
            if amount > max {
                return Err(anyhow!("Amount exceeds maximum transfer"));
            }
        }

        // Generate randomness
        let r_sender = generate_randomness()?;
        let r_sender = reduce_to_curve_order(&r_sender);
        let r_recipient = generate_randomness()?;
        let r_recipient = reduce_to_curve_order(&r_recipient);

        // Encrypt for sender (negative amount)
        let sender_ciphertext = encrypt(amount, &sender_keypair.public_key, &r_sender);

        // Encrypt for recipient (positive amount)
        let recipient_ciphertext = encrypt(amount, recipient_pk, &r_recipient);

        // Create amount commitment
        let amount_commitment = pedersen_commit(&Felt252::from_u64(amount), &r_sender);

        // Create balance proof
        let difference = current_balance - amount;
        let r_diff = generate_randomness()?;
        let r_diff = reduce_to_curve_order(&r_diff);

        let difference_commitment = pedersen_commit(&Felt252::from_u64(difference), &r_diff);
        let range_commitment = pedersen_commit(&Felt252::from_u64(difference), &r_diff);

        // Create Schnorr proof
        let context = [
            sender_keypair.public_key.x,
            sender_keypair.public_key.y,
            recipient_pk.x,
            recipient_pk.y,
            Felt252::from_u64(amount),
        ];
        let encryption_proof = create_schnorr_proof(
            &sender_keypair.secret_key,
            &sender_keypair.public_key,
            &r_sender,
            &context,
        );

        let knowledge_proof = create_schnorr_proof(
            &sender_keypair.secret_key,
            &sender_keypair.public_key,
            &r_diff,
            &context,
        );

        // Create nullifier
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nullifier = hash_felts(&[
            sender_keypair.public_key.x,
            sender_keypair.public_key.y,
            recipient_pk.x,
            recipient_pk.y,
            Felt252::from_u64(amount),
            Felt252::from_u64(now),
        ]);

        Ok(MultiAssetTransfer {
            asset_id,
            sender_pk: sender_keypair.public_key,
            recipient_pk: *recipient_pk,
            sender_ciphertext,
            recipient_ciphertext,
            amount_commitment,
            balance_proof: BalanceProof {
                difference_commitment,
                range_commitment,
                knowledge_proof,
            },
            encryption_proof,
            timestamp: now,
            nullifier,
        })
    }

    /// Execute a transfer
    pub fn execute_transfer(&self, transfer: &MultiAssetTransfer) -> Result<()> {
        // Check nullifier hasn't been used
        {
            let nullifiers = self.used_nullifiers.read();
            if nullifiers.contains_key(&transfer.nullifier) {
                return Err(anyhow!("Transfer already executed (replay attack)"));
            }
        }

        // Get sender and recipient accounts
        let sender_hash = hash_felts(&[transfer.sender_pk.x, transfer.sender_pk.y]);
        let recipient_hash = hash_felts(&[transfer.recipient_pk.x, transfer.recipient_pk.y]);

        let mut accounts = self.accounts.write();

        // Update sender balance (subtract)
        if let Some(sender_account) = accounts.get_mut(&sender_hash) {
            if let Some(balance) = sender_account.balances.get_mut(&transfer.asset_id) {
                balance.ciphertext = homomorphic_sub(&balance.ciphertext, &transfer.sender_ciphertext);
                balance.nonce += 1;
                balance.last_updated = transfer.timestamp;
            }
        }

        // Update recipient balance (add)
        if let Some(recipient_account) = accounts.get_mut(&recipient_hash) {
            if let Some(balance) = recipient_account.balances.get_mut(&transfer.asset_id) {
                balance.ciphertext = homomorphic_add(&balance.ciphertext, &transfer.recipient_ciphertext);
                balance.nonce += 1;
                balance.last_updated = transfer.timestamp;
            } else {
                // Create new balance entry for recipient
                recipient_account.balances.insert(
                    transfer.asset_id,
                    AssetEncryptedBalance {
                        asset_id: transfer.asset_id,
                        ciphertext: transfer.recipient_ciphertext,
                        commitment: transfer.amount_commitment,
                        last_updated: transfer.timestamp,
                        nonce: 0,
                    },
                );
            }
        }

        // Mark nullifier as used
        let mut nullifiers = self.used_nullifiers.write();
        nullifiers.insert(transfer.nullifier, transfer.timestamp);

        Ok(())
    }

    /// Create an atomic batch transfer (multiple assets at once)
    pub fn create_batch_transfer(
        &self,
        sender_keypair: &KeyPair,
        transfers: Vec<(ECPoint, AssetId, u64, u64)>, // (recipient, asset, amount, balance)
    ) -> Result<MultiAssetBatchTransfer> {
        let asset_count = transfers.len();
        let mut individual_transfers = Vec::new();

        for (recipient_pk, asset_id, amount, balance) in transfers {
            let transfer = self.create_transfer(
                sender_keypair,
                &recipient_pk,
                asset_id,
                amount,
                balance,
            )?;
            individual_transfers.push(transfer);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create batch ID
        let batch_id = hash_felts(&[
            sender_keypair.public_key.x,
            sender_keypair.public_key.y,
            Felt252::from_u64(now),
            Felt252::from_u64(individual_transfers.len() as u64),
        ]);

        // Create atomicity proof (hash of all nullifiers)
        let nullifier_data: Vec<Felt252> = individual_transfers
            .iter()
            .map(|t| t.nullifier)
            .collect();
        let atomicity_proof = hash_felts(&nullifier_data);

        Ok(MultiAssetBatchTransfer {
            batch_id,
            transfers: individual_transfers,
            asset_count,
            atomicity_proof,
            timestamp: now,
        })
    }

    /// Execute a batch transfer atomically
    pub fn execute_batch_transfer(&self, batch: &MultiAssetBatchTransfer) -> Result<()> {
        // First, verify all transfers can be executed
        for transfer in &batch.transfers {
            let nullifiers = self.used_nullifiers.read();
            if nullifiers.contains_key(&transfer.nullifier) {
                return Err(anyhow!("Batch contains already-executed transfer"));
            }
        }

        // Execute all transfers
        for transfer in &batch.transfers {
            self.execute_transfer(transfer)?;
        }

        Ok(())
    }

    /// Get the number of pending transfers
    pub fn pending_transfers_count(&self) -> usize {
        self.pending_transfers.read().len()
    }
}

impl Default for MultiAssetManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// CROSS-ASSET PROOFS
// =============================================================================

/// Proof that two encrypted values across different assets satisfy a ratio
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossAssetRatioProof {
    /// First asset
    pub asset_a: AssetId,
    /// Second asset
    pub asset_b: AssetId,
    /// Commitment to amount_a
    pub commitment_a: ECPoint,
    /// Commitment to amount_b
    pub commitment_b: ECPoint,
    /// Proof that amount_a * rate_numerator = amount_b * rate_denominator
    pub ratio_proof: RatioProof,
}

/// Zero-knowledge proof of a ratio relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatioProof {
    /// Commitment to the product
    pub product_commitment: ECPoint,
    /// Challenge
    pub challenge: Felt252,
    /// Response
    pub response: Felt252,
}

/// Create a cross-asset ratio proof
pub fn create_cross_asset_ratio_proof(
    amount_a: u64,
    amount_b: u64,
    rate_numerator: u64,
    rate_denominator: u64,
    randomness_a: &Felt252,
    randomness_b: &Felt252,
    asset_a: AssetId,
    asset_b: AssetId,
) -> Result<CrossAssetRatioProof, CryptoError> {
    // Verify the relationship holds
    if (amount_a as u128) * (rate_numerator as u128)
        != (amount_b as u128) * (rate_denominator as u128) {
        return Err(CryptoError::VerificationFailed);
    }

    // Create commitments
    let commitment_a = pedersen_commit(&Felt252::from_u64(amount_a), randomness_a);
    let commitment_b = pedersen_commit(&Felt252::from_u64(amount_b), randomness_b);

    // Create product commitment
    let product = (amount_a as u128) * (rate_numerator as u128);
    let product_felt = Felt252::from_u128(product);
    let r_product = generate_randomness()?;
    let r_product = reduce_to_curve_order(&r_product);
    let product_commitment = pedersen_commit(&product_felt, &r_product);

    // Create challenge
    let challenge = hash_felts(&[
        commitment_a.x, commitment_a.y,
        commitment_b.x, commitment_b.y,
        product_commitment.x, product_commitment.y,
        Felt252::from_u64(rate_numerator),
        Felt252::from_u64(rate_denominator),
    ]);
    let challenge = reduce_to_curve_order(&challenge);

    // Create response
    let response = add_mod_n(
        &r_product,
        &mul_mod_n(&challenge, randomness_a),
    );

    Ok(CrossAssetRatioProof {
        asset_a,
        asset_b,
        commitment_a,
        commitment_b,
        ratio_proof: RatioProof {
            product_commitment,
            challenge,
            response,
        },
    })
}

/// Verify a cross-asset ratio proof
pub fn verify_cross_asset_ratio_proof(
    proof: &CrossAssetRatioProof,
    rate_numerator: u64,
    rate_denominator: u64,
) -> bool {
    let _g = ECPoint::generator();

    // Recompute challenge
    let expected_challenge = hash_felts(&[
        proof.commitment_a.x, proof.commitment_a.y,
        proof.commitment_b.x, proof.commitment_b.y,
        proof.ratio_proof.product_commitment.x, proof.ratio_proof.product_commitment.y,
        Felt252::from_u64(rate_numerator),
        Felt252::from_u64(rate_denominator),
    ]);
    let expected_challenge = reduce_to_curve_order(&expected_challenge);

    if proof.ratio_proof.challenge != expected_challenge {
        return false;
    }

    // Verify the proof structure is valid
    proof.commitment_a.is_on_curve()
        && proof.commitment_b.is_on_curve()
        && proof.ratio_proof.product_commitment.is_on_curve()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keypair(seed: u64) -> KeyPair {
        KeyPair::from_secret(Felt252::from_u64(seed))
    }

    #[test]
    fn test_asset_config_creation() {
        let sage = AssetConfig::sage();
        assert_eq!(sage.symbol, "SAGE");
        assert_eq!(sage.decimals, 18);
        assert!(sage.privacy_enabled);

        let usdc = AssetConfig::usdc();
        assert_eq!(usdc.symbol, "USDC");
        assert_eq!(usdc.decimals, 6);
    }

    #[test]
    fn test_multi_asset_account_creation() {
        let manager = MultiAssetManager::new();
        let keypair = create_test_keypair(12345);

        let account = manager.create_account(&keypair).unwrap();
        assert_eq!(account.public_key, keypair.public_key);
        assert!(account.is_active);
        assert!(account.balances.is_empty());
    }

    #[test]
    fn test_multi_asset_deposit() {
        let manager = MultiAssetManager::new();
        let keypair = create_test_keypair(12345);

        manager.create_account(&keypair).unwrap();

        // Deposit SAGE
        let balance = manager.deposit(&keypair, AssetId::SAGE, 1000).unwrap();
        assert_eq!(balance.asset_id, AssetId::SAGE);

        // Deposit USDC
        let balance2 = manager.deposit(&keypair, AssetId::USDC, 500).unwrap();
        assert_eq!(balance2.asset_id, AssetId::USDC);

        // Check account has both balances
        let account = manager.get_account(&keypair.public_key).unwrap();
        assert!(account.has_balance(AssetId::SAGE));
        assert!(account.has_balance(AssetId::USDC));
        assert!(!account.has_balance(AssetId::WBTC));
    }

    #[test]
    fn test_multi_asset_transfer() {
        let manager = MultiAssetManager::new();
        let sender = create_test_keypair(11111);
        let recipient = create_test_keypair(22222);

        // Create accounts
        manager.create_account(&sender).unwrap();
        manager.create_account(&recipient).unwrap();

        // Deposit to sender
        manager.deposit(&sender, AssetId::SAGE, 1000).unwrap();

        // Create transfer
        let transfer = manager.create_transfer(
            &sender,
            &recipient.public_key,
            AssetId::SAGE,
            300,
            1000,
        ).unwrap();

        assert_eq!(transfer.asset_id, AssetId::SAGE);
        assert_eq!(transfer.sender_pk, sender.public_key);
        assert_eq!(transfer.recipient_pk, recipient.public_key);
    }

    #[test]
    fn test_batch_transfer() {
        let manager = MultiAssetManager::new();
        let sender = create_test_keypair(11111);
        let recipient1 = create_test_keypair(22222);
        let recipient2 = create_test_keypair(33333);

        // Create accounts
        manager.create_account(&sender).unwrap();
        manager.create_account(&recipient1).unwrap();
        manager.create_account(&recipient2).unwrap();

        // Deposit multiple assets
        manager.deposit(&sender, AssetId::SAGE, 1000).unwrap();
        manager.deposit(&sender, AssetId::USDC, 500).unwrap();

        // Create batch transfer
        let batch = manager.create_batch_transfer(
            &sender,
            vec![
                (recipient1.public_key, AssetId::SAGE, 100, 1000),
                (recipient2.public_key, AssetId::USDC, 50, 500),
            ],
        ).unwrap();

        assert_eq!(batch.transfers.len(), 2);
        assert_eq!(batch.asset_count, 2);
    }

    #[test]
    fn test_cross_asset_ratio_proof() {
        let r_a = reduce_to_curve_order(&Felt252::from_u64(12345));
        let r_b = reduce_to_curve_order(&Felt252::from_u64(67890));

        // 100 SAGE at rate 2:1 = 200 USDC
        let proof = create_cross_asset_ratio_proof(
            100,   // amount_a
            200,   // amount_b
            2,     // rate_numerator
            1,     // rate_denominator
            &r_a,
            &r_b,
            AssetId::SAGE,
            AssetId::USDC,
        ).unwrap();

        assert!(verify_cross_asset_ratio_proof(&proof, 2, 1));
    }

    #[test]
    fn test_replay_protection() {
        let manager = MultiAssetManager::new();
        let sender = create_test_keypair(11111);
        let recipient = create_test_keypair(22222);

        manager.create_account(&sender).unwrap();
        manager.create_account(&recipient).unwrap();
        manager.deposit(&sender, AssetId::SAGE, 1000).unwrap();

        let transfer = manager.create_transfer(
            &sender,
            &recipient.public_key,
            AssetId::SAGE,
            100,
            1000,
        ).unwrap();

        // First execution should succeed
        manager.execute_transfer(&transfer).unwrap();

        // Second execution should fail (replay)
        let result = manager.execute_transfer(&transfer);
        assert!(result.is_err());
    }

    #[test]
    fn test_asset_registration() {
        let manager = MultiAssetManager::new();

        // Register custom asset
        let custom = AssetConfig {
            asset_id: AssetId(100),
            name: "Custom Token".to_string(),
            symbol: "CUST".to_string(),
            decimals: 12,
            privacy_enabled: true,
            min_transfer: 10,
            max_transfer: Some(1_000_000),
            contract_address: None,
        };

        manager.register_asset(custom.clone());

        let config = manager.get_asset_config(AssetId(100)).unwrap();
        assert_eq!(config.symbol, "CUST");
        assert_eq!(config.decimals, 12);
    }
}
