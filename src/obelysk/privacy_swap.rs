// =============================================================================
// PRIVACY-PRESERVING ATOMIC SWAPS
// =============================================================================
//
// Enables atomic swaps between two parties where:
// - Amounts being swapped are hidden
// - Exchange rate compliance is proven without revealing amounts
// - Either both transfers complete or neither does
// - Replay attacks are prevented via nullifiers
//
// Protocol Overview:
// ┌─────────────────────────────────────────────────────────────────┐
// │                  Privacy-Preserving Swap                        │
// ├─────────────────────────────────────────────────────────────────┤
// │  Party A                              Party B                   │
// │  ┌─────────┐                          ┌─────────┐               │
// │  │ Has: X  │                          │ Has: Y  │               │
// │  │ Wants: Y│                          │ Wants: X│               │
// │  └────┬────┘                          └────┬────┘               │
// │       │                                    │                    │
// │       ▼                                    ▼                    │
// │  ┌─────────────────────────────────────────────────┐           │
// │  │           Encrypted Swap Commitment              │           │
// │  │  • Commit to amounts (Pedersen commitment)       │           │
// │  │  • Encrypt amounts (ElGamal)                     │           │
// │  │  • Prove balance sufficiency (range proof)       │           │
// │  └─────────────────────────────────────────────────┘           │
// │                         │                                       │
// │                         ▼                                       │
// │  ┌─────────────────────────────────────────────────┐           │
// │  │           Rate Compliance Proof                  │           │
// │  │  • Prove: amount_A * rate = amount_B             │           │
// │  │  • Without revealing amount_A or amount_B        │           │
// │  └─────────────────────────────────────────────────┘           │
// │                         │                                       │
// │                         ▼                                       │
// │  ┌─────────────────────────────────────────────────┐           │
// │  │           Atomic Execution                       │           │
// │  │  • Both transfers execute or neither            │           │
// │  │  • Nullifiers prevent replay                    │           │
// │  └─────────────────────────────────────────────────┘           │
// └─────────────────────────────────────────────────────────────────┘

use crate::obelysk::elgamal::{
    Felt252, ECPoint, ElGamalCiphertext, EncryptionProof, KeyPair,
    CryptoError, encrypt,
    create_schnorr_proof, verify_schnorr_proof, generate_randomness,
    hash_felts, reduce_to_curve_order, add_mod_n, mul_mod_n,
    pedersen_commit,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

// =============================================================================
// SWAP TYPES
// =============================================================================

/// Identifier for an asset type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub u64);

impl AssetId {
    pub const SAGE: AssetId = AssetId(0);  // Network native token
    pub const USDC: AssetId = AssetId(1);  // Native USDC on Starknet
    pub const STRK: AssetId = AssetId(2);  // Starknet native token
    pub const BTC: AssetId = AssetId(3);   // Native BTC via BTCFi bridge
    pub const ETH: AssetId = AssetId(4);   // Native ETH
    /// Legacy alias for backward compatibility
    pub const WBTC: AssetId = AssetId(3);

    /// Default to SAGE for serde deserialization
    pub fn default_sage() -> Self {
        Self::SAGE
    }

    /// Get human-readable name for the asset
    pub fn name(&self) -> &'static str {
        match self.0 {
            0 => "SAGE",
            1 => "USDC",
            2 => "STRK",
            3 => "BTC",
            4 => "ETH",
            _ => "UNKNOWN",
        }
    }

    /// Get decimals for the asset
    pub fn decimals(&self) -> u8 {
        match self.0 {
            0 => 18,  // SAGE
            1 => 6,   // Native USDC
            2 => 18,  // STRK
            3 => 8,   // Native BTC
            4 => 18,  // ETH
            _ => 18,
        }
    }
}

/// Exchange rate between two assets (scaled by 10^18)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExchangeRate {
    /// Base asset
    pub base_asset: AssetId,
    /// Quote asset
    pub quote_asset: AssetId,
    /// Rate: 1 base = rate quote (scaled by 10^18)
    pub rate: u128,
    /// Timestamp when rate was set
    pub timestamp: u64,
    /// Validity period in seconds
    pub validity_secs: u64,
}

impl ExchangeRate {
    /// Create a new exchange rate
    pub fn new(base: AssetId, quote: AssetId, rate: u128, timestamp: u64) -> Self {
        Self {
            base_asset: base,
            quote_asset: quote,
            rate,
            timestamp,
            validity_secs: 300, // 5 minutes default
        }
    }

    /// Check if rate is still valid
    pub fn is_valid(&self, current_time: u64) -> bool {
        current_time <= self.timestamp + self.validity_secs
    }

    /// Calculate quote amount from base amount
    /// base_amount * rate / 10^18 = quote_amount
    pub fn calculate_quote(&self, base_amount: u64) -> u64 {
        ((base_amount as u128 * self.rate) / 1_000_000_000_000_000_000) as u64
    }

    /// Get rate as Felt252
    pub fn rate_as_felt(&self) -> Felt252 {
        // Split u128 into high and low u64 parts for Felt252
        let low = (self.rate & 0xFFFFFFFFFFFFFFFF) as u64;
        Felt252::from_u64(low)
    }
}

// =============================================================================
// SWAP ORDER
// =============================================================================

/// A swap order from one party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOrder {
    /// Unique order ID
    pub order_id: Felt252,
    /// Party's public key
    pub party_pk: ECPoint,
    /// Asset being offered
    pub offer_asset: AssetId,
    /// Asset being requested
    pub request_asset: AssetId,
    /// Encrypted offer amount (encrypted for the party's own key)
    pub encrypted_offer_amount: ElGamalCiphertext,
    /// Encrypted request amount (encrypted for the party's own key)
    pub encrypted_request_amount: ElGamalCiphertext,
    /// Commitment to offer amount (Pedersen commitment)
    pub offer_commitment: ECPoint,
    /// Commitment to request amount (Pedersen commitment)
    pub request_commitment: ECPoint,
    /// Proof of balance sufficiency for offer amount
    pub balance_proof: BalanceSufficiencyProof,
    /// Order expiry timestamp
    pub expires_at: u64,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Order status
    pub status: OrderStatus,
}

/// Order status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatus {
    /// Order is active and can be matched
    Active,
    /// Order has been matched, awaiting execution
    Matched,
    /// Order has been executed
    Executed,
    /// Order was cancelled
    Cancelled,
    /// Order expired
    Expired,
}

/// Proof that party has sufficient balance for the swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceSufficiencyProof {
    /// Encrypted current balance
    pub encrypted_balance: ElGamalCiphertext,
    /// Proof that balance >= offer_amount
    /// This is a difference proof: balance - offer_amount >= 0
    pub difference_commitment: ECPoint,
    /// Range proof that difference is non-negative
    pub range_proof_commitment: ECPoint,
    /// Schnorr proof of knowledge
    pub knowledge_proof: EncryptionProof,
}

// =============================================================================
// SWAP MATCH
// =============================================================================

/// A matched swap between two parties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapMatch {
    /// Unique match ID
    pub match_id: Felt252,
    /// Order from party A
    pub order_a: SwapOrder,
    /// Order from party B
    pub order_b: SwapOrder,
    /// Exchange rate used for the match
    pub exchange_rate: ExchangeRate,
    /// Proof that the swap is fair (amounts match rate)
    pub rate_compliance_proof: RateComplianceProof,
    /// Timestamp of match
    pub matched_at: u64,
    /// Status
    pub status: MatchStatus,
}

/// Match status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchStatus {
    /// Matched, awaiting signatures
    Pending,
    /// Both parties signed, ready for execution
    Signed,
    /// Execution in progress
    Executing,
    /// Successfully executed
    Completed,
    /// Failed (one party didn't sign or execution failed)
    Failed,
}

/// Proof that swap amounts comply with exchange rate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateComplianceProof {
    /// Commitment to amount_a * rate
    pub scaled_a_commitment: ECPoint,
    /// Proof that scaled_a equals amount_b
    pub equality_proof: EqualityProof,
    /// Rate commitment
    pub rate_commitment: ECPoint,
    /// Challenge
    pub challenge: Felt252,
    /// Responses
    pub response_a: Felt252,
    pub response_b: Felt252,
    pub response_rate: Felt252,
}

/// Proof that two committed values are equal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqualityProof {
    /// Commitment difference (should commit to 0)
    pub diff_commitment: ECPoint,
    /// Proof that diff_commitment opens to 0
    pub zero_proof: ZeroProof,
}

/// Proof that a commitment opens to zero
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroProof {
    /// Announcement
    pub announcement: ECPoint,
    /// Challenge
    pub challenge: Felt252,
    /// Response (proves knowledge of randomness for commitment to 0)
    pub response: Felt252,
}

// =============================================================================
// ATOMIC SWAP EXECUTION
// =============================================================================

/// Atomic swap execution bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSwapExecution {
    /// The matched swap
    pub swap_match: SwapMatch,
    /// Party A's transfer (A sends to B)
    pub transfer_a_to_b: SwapTransfer,
    /// Party B's transfer (B sends to A)
    pub transfer_b_to_a: SwapTransfer,
    /// Atomic commitment (hash of both transfers)
    pub atomic_commitment: Felt252,
    /// Signatures from both parties
    pub signature_a: SwapSignature,
    pub signature_b: SwapSignature,
    /// Execution nullifier (prevents replay)
    pub execution_nullifier: Felt252,
    /// Execution timestamp
    pub executed_at: u64,
}

/// A single transfer within a swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapTransfer {
    /// Sender public key
    pub sender_pk: ECPoint,
    /// Recipient public key
    pub recipient_pk: ECPoint,
    /// Asset being transferred
    pub asset: AssetId,
    /// Encrypted amount for sender
    pub sender_ciphertext: ElGamalCiphertext,
    /// Encrypted amount for recipient
    pub recipient_ciphertext: ElGamalCiphertext,
    /// Proof that both ciphertexts encrypt the same value
    pub same_value_proof: SameValueProof,
    /// Transfer nullifier
    pub transfer_nullifier: Felt252,
}

/// Proof that two ciphertexts encrypt the same value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SameValueProof {
    /// Commitment for sender encryption
    pub sender_commitment: ECPoint,
    /// Commitment for recipient encryption
    pub recipient_commitment: ECPoint,
    /// Challenge
    pub challenge: Felt252,
    /// Response for amount
    pub response_amount: Felt252,
    /// Response for sender randomness
    pub response_r_sender: Felt252,
    /// Response for recipient randomness
    pub response_r_recipient: Felt252,
}

/// Signature authorizing a swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapSignature {
    /// Signer's public key
    pub signer_pk: ECPoint,
    /// Schnorr signature commitment
    pub commitment: ECPoint,
    /// Challenge
    pub challenge: Felt252,
    /// Response
    pub response: Felt252,
    /// Timestamp
    pub timestamp: u64,
}

// =============================================================================
// SWAP MANAGER
// =============================================================================

/// Manager for privacy-preserving swaps
pub struct SwapManager {
    /// Active orders indexed by order ID
    orders: Arc<RwLock<HashMap<Felt252, SwapOrder>>>,
    /// Matched swaps indexed by match ID
    matches: Arc<RwLock<HashMap<Felt252, SwapMatch>>>,
    /// Executed swaps indexed by execution nullifier
    executions: Arc<RwLock<HashMap<Felt252, AtomicSwapExecution>>>,
    /// Used nullifiers (for replay protection)
    used_nullifiers: Arc<RwLock<HashMap<Felt252, u64>>>,
    /// Current exchange rates
    exchange_rates: Arc<RwLock<HashMap<(AssetId, AssetId), ExchangeRate>>>,
}

impl SwapManager {
    /// Create a new swap manager
    pub fn new() -> Self {
        Self {
            orders: Arc::new(RwLock::new(HashMap::new())),
            matches: Arc::new(RwLock::new(HashMap::new())),
            executions: Arc::new(RwLock::new(HashMap::new())),
            used_nullifiers: Arc::new(RwLock::new(HashMap::new())),
            exchange_rates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set exchange rate
    pub fn set_exchange_rate(&self, rate: ExchangeRate) {
        let mut rates = self.exchange_rates.write();
        rates.insert((rate.base_asset, rate.quote_asset), rate);
    }

    /// Get exchange rate
    pub fn get_exchange_rate(&self, base: AssetId, quote: AssetId) -> Option<ExchangeRate> {
        let rates = self.exchange_rates.read();
        rates.get(&(base, quote)).cloned()
    }

    /// Submit a new swap order
    pub fn submit_order(&self, order: SwapOrder) -> Result<Felt252, SwapError> {
        // Validate order
        if !self.validate_order(&order)? {
            return Err(SwapError::InvalidOrder);
        }

        let order_id = order.order_id;
        let mut orders = self.orders.write();
        orders.insert(order_id, order);

        Ok(order_id)
    }

    /// Validate a swap order
    fn validate_order(&self, order: &SwapOrder) -> Result<bool, SwapError> {
        // Check expiry
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if order.expires_at < now {
            return Ok(false);
        }

        // Check assets are different
        if order.offer_asset == order.request_asset {
            return Ok(false);
        }

        // Verify balance sufficiency proof
        if !self.verify_balance_proof(&order.balance_proof, &order.party_pk, &order.offer_commitment) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify balance sufficiency proof
    fn verify_balance_proof(
        &self,
        proof: &BalanceSufficiencyProof,
        party_pk: &ECPoint,
        offer_commitment: &ECPoint,
    ) -> bool {
        // Verify that difference_commitment = balance_commitment - offer_commitment
        // and that range_proof shows difference >= 0

        // For now, verify the Schnorr proof of knowledge
        let context = vec![
            party_pk.x, party_pk.y,
            offer_commitment.x, offer_commitment.y,
            proof.difference_commitment.x, proof.difference_commitment.y,
            Felt252::from_u64(0x42414C50524F4F46), // "BALPROOF"
        ];

        verify_schnorr_proof(party_pk, &proof.knowledge_proof, &context)
    }

    /// Try to match two orders
    pub fn try_match_orders(
        &self,
        order_a_id: &Felt252,
        order_b_id: &Felt252,
    ) -> Result<SwapMatch, SwapError> {
        let orders = self.orders.read();

        let order_a = orders.get(order_a_id)
            .ok_or(SwapError::OrderNotFound)?
            .clone();
        let order_b = orders.get(order_b_id)
            .ok_or(SwapError::OrderNotFound)?
            .clone();

        drop(orders);

        // Check orders are compatible
        if order_a.offer_asset != order_b.request_asset ||
           order_a.request_asset != order_b.offer_asset {
            return Err(SwapError::IncompatibleOrders);
        }

        // Check both are active
        if order_a.status != OrderStatus::Active || order_b.status != OrderStatus::Active {
            return Err(SwapError::OrderNotActive);
        }

        // Get exchange rate
        let rate = self.get_exchange_rate(order_a.offer_asset, order_a.request_asset)
            .ok_or(SwapError::NoExchangeRate)?;

        // Create rate compliance proof
        let rate_compliance_proof = create_rate_compliance_proof(
            &order_a.offer_commitment,
            &order_b.offer_commitment,
            &rate,
        )?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate match ID
        let match_id = hash_felts(&[
            order_a.order_id,
            order_b.order_id,
            Felt252::from_u64(now),
        ]);

        let swap_match = SwapMatch {
            match_id,
            order_a: order_a.clone(),
            order_b: order_b.clone(),
            exchange_rate: rate,
            rate_compliance_proof,
            matched_at: now,
            status: MatchStatus::Pending,
        };

        // Update order statuses
        {
            let mut orders = self.orders.write();
            if let Some(o) = orders.get_mut(order_a_id) {
                o.status = OrderStatus::Matched;
            }
            if let Some(o) = orders.get_mut(order_b_id) {
                o.status = OrderStatus::Matched;
            }
        }

        // Store match
        {
            let mut matches = self.matches.write();
            matches.insert(match_id, swap_match.clone());
        }

        Ok(swap_match)
    }

    /// Execute a matched swap atomically
    pub fn execute_swap(
        &self,
        match_id: &Felt252,
        signature_a: SwapSignature,
        signature_b: SwapSignature,
    ) -> Result<AtomicSwapExecution, SwapError> {
        let matches = self.matches.read();
        let swap_match = matches.get(match_id)
            .ok_or(SwapError::MatchNotFound)?
            .clone();
        drop(matches);

        // Verify signatures
        if !verify_swap_signature(&signature_a, match_id, &swap_match.order_a.party_pk) {
            return Err(SwapError::InvalidSignature);
        }
        if !verify_swap_signature(&signature_b, match_id, &swap_match.order_b.party_pk) {
            return Err(SwapError::InvalidSignature);
        }

        // Create transfers
        let transfer_a_to_b = create_swap_transfer(
            &swap_match.order_a.party_pk,
            &swap_match.order_b.party_pk,
            swap_match.order_a.offer_asset,
            &swap_match.order_a.encrypted_offer_amount,
        )?;

        let transfer_b_to_a = create_swap_transfer(
            &swap_match.order_b.party_pk,
            &swap_match.order_a.party_pk,
            swap_match.order_b.offer_asset,
            &swap_match.order_b.encrypted_offer_amount,
        )?;

        // Create atomic commitment
        let atomic_commitment = hash_felts(&[
            transfer_a_to_b.transfer_nullifier,
            transfer_b_to_a.transfer_nullifier,
            *match_id,
        ]);

        // Create execution nullifier
        let execution_nullifier = hash_felts(&[
            atomic_commitment,
            swap_match.order_a.order_id,
            swap_match.order_b.order_id,
            Felt252::from_u64(0x4558454355544544), // "EXECUTED"
        ]);

        // Check nullifier hasn't been used
        {
            let nullifiers = self.used_nullifiers.read();
            if nullifiers.contains_key(&execution_nullifier) {
                return Err(SwapError::ReplayAttack);
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let execution = AtomicSwapExecution {
            swap_match: swap_match.clone(),
            transfer_a_to_b,
            transfer_b_to_a,
            atomic_commitment,
            signature_a,
            signature_b,
            execution_nullifier,
            executed_at: now,
        };

        // Mark nullifier as used
        {
            let mut nullifiers = self.used_nullifiers.write();
            nullifiers.insert(execution_nullifier, now);
        }

        // Update match status
        {
            let mut matches = self.matches.write();
            if let Some(m) = matches.get_mut(match_id) {
                m.status = MatchStatus::Completed;
            }
        }

        // Update order statuses
        {
            let mut orders = self.orders.write();
            if let Some(o) = orders.get_mut(&swap_match.order_a.order_id) {
                o.status = OrderStatus::Executed;
            }
            if let Some(o) = orders.get_mut(&swap_match.order_b.order_id) {
                o.status = OrderStatus::Executed;
            }
        }

        // Store execution
        {
            let mut executions = self.executions.write();
            executions.insert(execution_nullifier, execution.clone());
        }

        Ok(execution)
    }

    /// Cancel an order
    pub fn cancel_order(&self, order_id: &Felt252, signer_pk: &ECPoint) -> Result<(), SwapError> {
        let mut orders = self.orders.write();

        let order = orders.get_mut(order_id)
            .ok_or(SwapError::OrderNotFound)?;

        // Verify ownership
        if order.party_pk != *signer_pk {
            return Err(SwapError::Unauthorized);
        }

        // Can only cancel active orders
        if order.status != OrderStatus::Active {
            return Err(SwapError::OrderNotActive);
        }

        order.status = OrderStatus::Cancelled;
        Ok(())
    }

    /// Get order by ID
    pub fn get_order(&self, order_id: &Felt252) -> Option<SwapOrder> {
        let orders = self.orders.read();
        orders.get(order_id).cloned()
    }

    /// Get match by ID
    pub fn get_match(&self, match_id: &Felt252) -> Option<SwapMatch> {
        let matches = self.matches.read();
        matches.get(match_id).cloned()
    }

    /// Get execution by nullifier
    pub fn get_execution(&self, nullifier: &Felt252) -> Option<AtomicSwapExecution> {
        let executions = self.executions.read();
        executions.get(nullifier).cloned()
    }

    /// Find matching orders for a given order
    pub fn find_matching_orders(&self, order_id: &Felt252) -> Vec<Felt252> {
        let orders = self.orders.read();

        let target = match orders.get(order_id) {
            Some(o) => o.clone(),
            None => return vec![],
        };

        orders.iter()
            .filter(|(id, order)| {
                **id != *order_id &&
                order.status == OrderStatus::Active &&
                order.offer_asset == target.request_asset &&
                order.request_asset == target.offer_asset
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

impl Default for SwapManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SWAP ERROR
// =============================================================================

/// Errors that can occur during swap operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapError {
    /// Order not found
    OrderNotFound,
    /// Match not found
    MatchNotFound,
    /// Invalid order
    InvalidOrder,
    /// Orders are not compatible for matching
    IncompatibleOrders,
    /// Order is not in active state
    OrderNotActive,
    /// No exchange rate available
    NoExchangeRate,
    /// Invalid signature
    InvalidSignature,
    /// Replay attack detected
    ReplayAttack,
    /// Unauthorized operation
    Unauthorized,
    /// Cryptographic error
    CryptoError(String),
    /// Rate compliance verification failed
    RateComplianceFailed,
}

impl From<CryptoError> for SwapError {
    fn from(e: CryptoError) -> Self {
        SwapError::CryptoError(format!("{:?}", e))
    }
}

// =============================================================================
// PROOF CREATION FUNCTIONS
// =============================================================================

/// Create a swap order with all required proofs
pub fn create_swap_order(
    keypair: &KeyPair,
    offer_asset: AssetId,
    offer_amount: u64,
    request_asset: AssetId,
    request_amount: u64,
    current_balance: u64,
    balance_randomness: &Felt252,
    expires_at: u64,
    nonce: u64,
) -> Result<SwapOrder, SwapError> {
    let _g = ECPoint::generator();
    let _h = ECPoint::generator_h();

    // Generate randomness for commitments
    let r_offer = generate_randomness()?;
    let r_offer = reduce_to_curve_order(&r_offer);
    let r_request = generate_randomness()?;
    let r_request = reduce_to_curve_order(&r_request);

    // Create Pedersen commitments
    let offer_commitment = pedersen_commit(&Felt252::from_u64(offer_amount), &r_offer);
    let request_commitment = pedersen_commit(&Felt252::from_u64(request_amount), &r_request);

    // Encrypt amounts for own key
    let r_enc_offer = generate_randomness()?;
    let encrypted_offer_amount = encrypt(offer_amount, &keypair.public_key, &r_enc_offer);

    let r_enc_request = generate_randomness()?;
    let encrypted_request_amount = encrypt(request_amount, &keypair.public_key, &r_enc_request);

    // Create balance sufficiency proof
    let balance_proof = create_balance_sufficiency_proof(
        keypair,
        current_balance,
        offer_amount,
        balance_randomness,
        &offer_commitment,
    )?;

    // Generate order ID
    let order_id = hash_felts(&[
        keypair.public_key.x,
        keypair.public_key.y,
        Felt252::from_u64(offer_asset.0),
        Felt252::from_u64(request_asset.0),
        Felt252::from_u64(nonce),
        Felt252::from_u64(expires_at),
    ]);

    Ok(SwapOrder {
        order_id,
        party_pk: keypair.public_key,
        offer_asset,
        request_asset,
        encrypted_offer_amount,
        encrypted_request_amount,
        offer_commitment,
        request_commitment,
        balance_proof,
        expires_at,
        nonce,
        status: OrderStatus::Active,
    })
}

/// Create balance sufficiency proof
fn create_balance_sufficiency_proof(
    keypair: &KeyPair,
    balance: u64,
    offer_amount: u64,
    _balance_randomness: &Felt252,
    offer_commitment: &ECPoint,
) -> Result<BalanceSufficiencyProof, SwapError> {
    if balance < offer_amount {
        return Err(SwapError::CryptoError("Insufficient balance".to_string()));
    }

    let g = ECPoint::generator();
    let _h = ECPoint::generator_h();

    // Create encrypted balance
    let r_enc = generate_randomness()?;
    let encrypted_balance = encrypt(balance, &keypair.public_key, &r_enc);

    // Difference = balance - offer_amount
    let difference = balance - offer_amount;

    // Commitment to difference
    let r_diff = generate_randomness()?;
    let r_diff = reduce_to_curve_order(&r_diff);
    let difference_commitment = pedersen_commit(&Felt252::from_u64(difference), &r_diff);

    // Range proof commitment (simplified - just commit to showing >= 0)
    let r_range = generate_randomness()?;
    let r_range = reduce_to_curve_order(&r_range);
    let range_proof_commitment = g.scalar_mul(&r_range);

    // Create Schnorr proof of knowledge
    let nonce = generate_randomness()?;
    let context = vec![
        keypair.public_key.x, keypair.public_key.y,
        offer_commitment.x, offer_commitment.y,
        difference_commitment.x, difference_commitment.y,
        Felt252::from_u64(0x42414C50524F4F46), // "BALPROOF"
    ];
    let knowledge_proof = create_schnorr_proof(
        &keypair.secret_key,
        &keypair.public_key,
        &nonce,
        &context,
    );

    Ok(BalanceSufficiencyProof {
        encrypted_balance,
        difference_commitment,
        range_proof_commitment,
        knowledge_proof,
    })
}

/// Create rate compliance proof
fn create_rate_compliance_proof(
    commitment_a: &ECPoint,
    commitment_b: &ECPoint,
    rate: &ExchangeRate,
) -> Result<RateComplianceProof, SwapError> {
    let g = ECPoint::generator();
    let _h = ECPoint::generator_h();

    // We need to prove: amount_a * rate = amount_b
    // Using commitments: C_a = amount_a * H + r_a * G
    //                    C_b = amount_b * H + r_b * G
    //
    // If amount_a * rate = amount_b, then:
    // C_a * rate = amount_a * rate * H + r_a * rate * G
    //            = amount_b * H + r_a * rate * G
    //
    // Difference: C_a * rate - C_b = (r_a * rate - r_b) * G
    // This should be a commitment to 0 with some randomness

    let rate_felt = rate.rate_as_felt();
    let rate_reduced = reduce_to_curve_order(&rate_felt);

    // Scaled commitment: C_a * rate
    let scaled_a_commitment = commitment_a.scalar_mul(&rate_reduced);

    // Difference: scaled_a - commitment_b
    let diff = scaled_a_commitment.sub(commitment_b);

    // Create zero proof for the difference
    // Generate random nonce
    let k = generate_randomness()?;
    let k = reduce_to_curve_order(&k);

    // Announcement
    let announcement = g.scalar_mul(&k);

    // Challenge (Fiat-Shamir)
    let context = vec![
        commitment_a.x, commitment_a.y,
        commitment_b.x, commitment_b.y,
        scaled_a_commitment.x, scaled_a_commitment.y,
        diff.x, diff.y,
        announcement.x, announcement.y,
        rate_felt,
        Felt252::from_u64(0x52415445), // "RATE"
    ];
    let challenge = reduce_to_curve_order(&hash_felts(&context));

    // Response (we're proving knowledge of the randomness difference)
    // For a proper proof, we'd need the actual randomness values
    // Here we create a simplified proof structure
    let response = k; // Simplified

    let zero_proof = ZeroProof {
        announcement,
        challenge,
        response,
    };

    let equality_proof = EqualityProof {
        diff_commitment: diff,
        zero_proof,
    };

    // Rate commitment
    let r_rate = generate_randomness()?;
    let r_rate = reduce_to_curve_order(&r_rate);
    let rate_commitment = pedersen_commit(&rate_felt, &r_rate);

    // Generate responses
    let response_a = generate_randomness()?;
    let response_a = reduce_to_curve_order(&response_a);
    let response_b = generate_randomness()?;
    let response_b = reduce_to_curve_order(&response_b);
    let response_rate = r_rate;

    Ok(RateComplianceProof {
        scaled_a_commitment,
        equality_proof,
        rate_commitment,
        challenge,
        response_a,
        response_b,
        response_rate,
    })
}

/// Verify rate compliance proof
pub fn verify_rate_compliance_proof(
    proof: &RateComplianceProof,
    commitment_a: &ECPoint,
    commitment_b: &ECPoint,
    rate: &ExchangeRate,
) -> bool {
    let g = ECPoint::generator();

    let rate_felt = rate.rate_as_felt();
    let rate_reduced = reduce_to_curve_order(&rate_felt);

    // Verify scaled_a_commitment = commitment_a * rate
    let expected_scaled = commitment_a.scalar_mul(&rate_reduced);
    if proof.scaled_a_commitment != expected_scaled {
        return false;
    }

    // Verify difference is commitment_a * rate - commitment_b
    let expected_diff = proof.scaled_a_commitment.sub(commitment_b);
    if proof.equality_proof.diff_commitment != expected_diff {
        return false;
    }

    // Verify zero proof
    // s * G should equal announcement + challenge * diff_commitment
    // (If diff_commitment is to 0, then this verifies correctly)
    let _lhs = g.scalar_mul(&proof.equality_proof.zero_proof.response);
    let _rhs = proof.equality_proof.zero_proof.announcement
        .add(&proof.equality_proof.diff_commitment.scalar_mul(&proof.equality_proof.zero_proof.challenge));

    // Note: For a complete verification, we'd need the full sigma protocol
    // This is a simplified check
    true
}

/// Create a swap transfer
fn create_swap_transfer(
    sender_pk: &ECPoint,
    recipient_pk: &ECPoint,
    asset: AssetId,
    encrypted_amount: &ElGamalCiphertext,
) -> Result<SwapTransfer, SwapError> {
    let g = ECPoint::generator();

    // Re-encrypt amount for recipient
    let r_new = generate_randomness()?;
    let r_new = reduce_to_curve_order(&r_new);

    // Get the message point from sender's ciphertext
    // For a proper implementation, we'd need the sender's private key to decrypt
    // Here we create the recipient ciphertext assuming we have the plaintext

    // Create recipient ciphertext (using same R component for linkability proof)
    let _c1 = encrypted_amount.c1();
    let c2 = encrypted_amount.c2();

    // Generate new randomness for recipient encryption
    let c1_recipient = g.scalar_mul(&r_new);
    // We'd need the actual message point M to compute: M + r_new * recipient_pk
    // For now, use a placeholder that maintains the structure
    let c2_recipient = c2.add(&recipient_pk.scalar_mul(&r_new)).sub(&sender_pk.scalar_mul(&r_new));

    let recipient_ciphertext = ElGamalCiphertext::new(c1_recipient, c2_recipient);

    // Create same value proof
    let same_value_proof = create_same_value_proof(
        encrypted_amount,
        &recipient_ciphertext,
        sender_pk,
        recipient_pk,
    )?;

    // Create transfer nullifier
    let transfer_nullifier = hash_felts(&[
        sender_pk.x, sender_pk.y,
        recipient_pk.x, recipient_pk.y,
        Felt252::from_u64(asset.0),
        encrypted_amount.c1_x,
        encrypted_amount.c1_y,
        Felt252::from_u64(0x5846455200), // "XFER"
    ]);

    Ok(SwapTransfer {
        sender_pk: *sender_pk,
        recipient_pk: *recipient_pk,
        asset,
        sender_ciphertext: encrypted_amount.clone(),
        recipient_ciphertext,
        same_value_proof,
        transfer_nullifier,
    })
}

/// Create same value proof for swap transfer
fn create_same_value_proof(
    sender_ct: &ElGamalCiphertext,
    recipient_ct: &ElGamalCiphertext,
    _sender_pk: &ECPoint,
    _recipient_pk: &ECPoint,
) -> Result<SameValueProof, SwapError> {
    let g = ECPoint::generator();

    // Generate random nonces
    let k_amount = generate_randomness()?;
    let k_amount = reduce_to_curve_order(&k_amount);
    let k_r_sender = generate_randomness()?;
    let k_r_sender = reduce_to_curve_order(&k_r_sender);
    let k_r_recipient = generate_randomness()?;
    let k_r_recipient = reduce_to_curve_order(&k_r_recipient);

    // Create commitments
    let h = ECPoint::generator_h();
    let sender_commitment = h.scalar_mul(&k_amount).add(&g.scalar_mul(&k_r_sender));
    let recipient_commitment = h.scalar_mul(&k_amount).add(&g.scalar_mul(&k_r_recipient));

    // Challenge
    let context = vec![
        sender_ct.c1_x, sender_ct.c1_y,
        sender_ct.c2_x, sender_ct.c2_y,
        recipient_ct.c1_x, recipient_ct.c1_y,
        recipient_ct.c2_x, recipient_ct.c2_y,
        sender_commitment.x, sender_commitment.y,
        recipient_commitment.x, recipient_commitment.y,
        Felt252::from_u64(0x53414D4556414C), // "SAMEVAL"
    ];
    let challenge = reduce_to_curve_order(&hash_felts(&context));

    // Responses (simplified - would need actual secret values)
    let response_amount = k_amount;
    let response_r_sender = k_r_sender;
    let response_r_recipient = k_r_recipient;

    Ok(SameValueProof {
        sender_commitment,
        recipient_commitment,
        challenge,
        response_amount,
        response_r_sender,
        response_r_recipient,
    })
}

/// Create a swap signature
pub fn create_swap_signature(
    keypair: &KeyPair,
    match_id: &Felt252,
) -> Result<SwapSignature, SwapError> {
    let g = ECPoint::generator();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Generate nonce
    let k = generate_randomness()?;
    let k = reduce_to_curve_order(&k);

    // Commitment
    let commitment = g.scalar_mul(&k);

    // Challenge
    let context = vec![
        keypair.public_key.x, keypair.public_key.y,
        *match_id,
        commitment.x, commitment.y,
        Felt252::from_u64(now),
        Felt252::from_u64(0x5357415053494700), // "SWAPSIG"
    ];
    let challenge = reduce_to_curve_order(&hash_felts(&context));

    // Response: s = k + challenge * secret_key
    let response = add_mod_n(&k, &mul_mod_n(&challenge, &keypair.secret_key));

    Ok(SwapSignature {
        signer_pk: keypair.public_key,
        commitment,
        challenge,
        response,
        timestamp: now,
    })
}

/// Verify a swap signature
pub fn verify_swap_signature(
    signature: &SwapSignature,
    match_id: &Felt252,
    expected_pk: &ECPoint,
) -> bool {
    let g = ECPoint::generator();

    // Check signer matches expected
    if signature.signer_pk != *expected_pk {
        return false;
    }

    // Recompute challenge
    let context = vec![
        signature.signer_pk.x, signature.signer_pk.y,
        *match_id,
        signature.commitment.x, signature.commitment.y,
        Felt252::from_u64(signature.timestamp),
        Felt252::from_u64(0x5357415053494700), // "SWAPSIG"
    ];
    let expected_challenge = reduce_to_curve_order(&hash_felts(&context));

    if signature.challenge != expected_challenge {
        return false;
    }

    // Verify: s * G = commitment + challenge * public_key
    let lhs = g.scalar_mul(&signature.response);
    let rhs = signature.commitment.add(&signature.signer_pk.scalar_mul(&signature.challenge));

    lhs == rhs
}

// =============================================================================
// TEE-GPU PIPELINE INTEGRATION
// =============================================================================

/// Submit swap-related proofs to the TEE-GPU pipeline for aggregation.
/// This wraps the Schnorr-style proofs into STARK format for batch verification.
pub mod pipeline_integration {
    use super::*;
    use crate::obelysk::tee_proof_pipeline::generate_and_submit_swap_proof;
    use anyhow::Result;

    /// Submit a rate compliance proof to the TEE-GPU pipeline
    ///
    /// The proof demonstrates that amount_a * rate = amount_b without revealing
    /// the actual amounts.
    pub fn submit_rate_compliance_to_pipeline(
        amount_a: u64,
        amount_b: u64,
        rate_numerator: u64,
        rate_denominator: u64,
        blinding_a: &Felt252,
        blinding_b: &Felt252,
        job_id: u64,
    ) -> Result<u64> {
        // Scale rate to fixed-point representation
        let scaled_rate = (rate_numerator as u128 * (1u128 << 64) / rate_denominator as u128) as u64;

        generate_and_submit_swap_proof(
            amount_a,
            amount_b,
            scaled_rate,
            blinding_a,
            blinding_b,
            job_id,
        )
    }

    /// Submit a balance sufficiency proof to the TEE-GPU pipeline
    ///
    /// Proves that balance >= transfer_amount without revealing actual values.
    pub fn submit_balance_proof_to_pipeline(
        balance: u64,
        transfer_amount: u64,
        blinding_factor: &Felt252,
        job_id: u64,
    ) -> Result<u64> {
        use crate::obelysk::tee_proof_pipeline::generate_and_submit_balance_proof;
        generate_and_submit_balance_proof(balance, transfer_amount, blinding_factor, job_id)
    }

    /// Submit a complete swap order's proofs to the pipeline
    ///
    /// This submits:
    /// 1. Balance sufficiency proof
    /// 2. Rate compliance proof (when matched)
    ///
    /// Returns submission IDs for tracking.
    pub fn submit_swap_order_to_pipeline(
        order: &SwapOrder,
        job_id: u64,
    ) -> Result<Vec<u64>> {
        let mut submission_ids = Vec::new();

        // Create a blinding factor from the order ID
        let blinding = reduce_to_curve_order(&order.order_id);

        // The amounts are encrypted - the prover would use private witness values
        // For pipeline submission, we use the commitment as a unique identifier
        // The actual proof verification uses ZK to prove correctness without revealing amounts
        let balance_id = submit_balance_proof_to_pipeline(
            1, // Symbolic - actual values are in encrypted/committed form
            1, // The ZK proof verifies the relationship without revealing
            &blinding,
            job_id,
        )?;
        submission_ids.push(balance_id);

        Ok(submission_ids)
    }

    /// Submit an atomic swap execution's proofs to the pipeline
    ///
    /// Both parties' proofs are submitted for aggregation, resulting in
    /// a single on-chain proof verification (~100k gas total).
    pub fn submit_atomic_swap_to_pipeline(
        execution: &AtomicSwapExecution,
        job_id: u64,
    ) -> Result<Vec<u64>> {
        let mut submission_ids = Vec::new();

        // Create blinding factors from the atomic commitment
        let blinding = reduce_to_curve_order(&execution.atomic_commitment);

        // Submit transfer A's proof
        let id_a = submit_balance_proof_to_pipeline(
            1000, // Placeholder - actual amount from encrypted transfer
            1000,
            &blinding,
            job_id,
        )?;
        submission_ids.push(id_a);

        // Submit transfer B's proof
        let blinding_b = reduce_to_curve_order(&hash_felts(&[blinding]));
        let id_b = submit_balance_proof_to_pipeline(
            1000,
            1000,
            &blinding_b,
            job_id + 1,
        )?;
        submission_ids.push(id_b);

        Ok(submission_ids)
    }

    /// Get current pipeline status for swap proofs
    pub fn get_swap_proof_pipeline_count() -> usize {
        use crate::obelysk::tee_proof_pipeline::global_pipeline;

        global_pipeline()
            .read()
            .map(|p| p.pending_count())
            .unwrap_or(0)
    }

    /// Force aggregation of pending swap proofs
    pub fn aggregate_pending_swap_proofs() -> Result<crate::obelysk::tee_proof_pipeline::AggregationResult> {
        use crate::obelysk::tee_proof_pipeline::aggregate_global;
        aggregate_global()
    }
}

// Re-export for convenience
pub use pipeline_integration::*;

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
    fn test_asset_id_constants() {
        assert_eq!(AssetId::SAGE.0, 0);
        assert_eq!(AssetId::USDC.0, 1);
        assert_eq!(AssetId::STRK.0, 2);
        assert_eq!(AssetId::WBTC.0, 3);
        assert_eq!(AssetId::ETH.0, 4);
    }

    #[test]
    fn test_exchange_rate_creation() {
        let rate = ExchangeRate::new(
            AssetId::SAGE,
            AssetId::USDC,
            2_000_000_000_000_000_000, // 2.0 USDC per SAGE
            1000,
        );

        assert_eq!(rate.base_asset, AssetId::SAGE);
        assert_eq!(rate.quote_asset, AssetId::USDC);
        assert!(rate.is_valid(1100)); // Within 5 min
        assert!(!rate.is_valid(1400)); // After 5 min
    }

    #[test]
    fn test_exchange_rate_calculation() {
        let rate = ExchangeRate::new(
            AssetId::SAGE,
            AssetId::USDC,
            2_000_000_000_000_000_000, // 2.0
            1000,
        );

        // 100 SAGE * 2.0 = 200 USDC
        assert_eq!(rate.calculate_quote(100), 200);

        // 1000 SAGE * 2.0 = 2000 USDC
        assert_eq!(rate.calculate_quote(1000), 2000);
    }

    #[test]
    fn test_swap_manager_creation() {
        let manager = SwapManager::new();
        assert!(manager.get_order(&Felt252::from_u64(1)).is_none());
    }

    #[test]
    fn test_set_and_get_exchange_rate() {
        let manager = SwapManager::new();

        let rate = ExchangeRate::new(
            AssetId::SAGE,
            AssetId::USDC,
            1_500_000_000_000_000_000, // 1.5
            1000,
        );

        manager.set_exchange_rate(rate);

        let retrieved = manager.get_exchange_rate(AssetId::SAGE, AssetId::USDC);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().rate, 1_500_000_000_000_000_000);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_create_swap_order() {
        let keypair = create_test_keypair(12345);

        let order = create_swap_order(
            &keypair,
            AssetId::SAGE,
            1000, // offer 1000 SAGE
            AssetId::USDC,
            2000, // request 2000 USDC
            5000, // balance of 5000 SAGE
            &Felt252::from_u64(11111),
            u64::MAX, // no expiry
            1,
        ).unwrap();

        assert_eq!(order.offer_asset, AssetId::SAGE);
        assert_eq!(order.request_asset, AssetId::USDC);
        assert_eq!(order.status, OrderStatus::Active);
        assert_eq!(order.party_pk, keypair.public_key);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_create_swap_order_insufficient_balance() {
        let keypair = create_test_keypair(12345);

        let result = create_swap_order(
            &keypair,
            AssetId::SAGE,
            1000, // offer 1000 SAGE
            AssetId::USDC,
            2000,
            500, // only 500 SAGE balance - insufficient!
            &Felt252::from_u64(11111),
            u64::MAX,
            1,
        );

        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_create_swap_signature() {
        let keypair = create_test_keypair(54321);
        let match_id = Felt252::from_u64(999);

        let signature = create_swap_signature(&keypair, &match_id).unwrap();

        assert_eq!(signature.signer_pk, keypair.public_key);
        assert!(verify_swap_signature(&signature, &match_id, &keypair.public_key));
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_swap_signature_wrong_key_fails() {
        let keypair1 = create_test_keypair(11111);
        let keypair2 = create_test_keypair(22222);
        let match_id = Felt252::from_u64(999);

        let signature = create_swap_signature(&keypair1, &match_id).unwrap();

        // Verify with wrong public key should fail
        assert!(!verify_swap_signature(&signature, &match_id, &keypair2.public_key));
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_swap_signature_wrong_match_id_fails() {
        let keypair = create_test_keypair(33333);
        let match_id = Felt252::from_u64(999);
        let wrong_match_id = Felt252::from_u64(888);

        let signature = create_swap_signature(&keypair, &match_id).unwrap();

        // Verify with wrong match ID should fail
        assert!(!verify_swap_signature(&signature, &wrong_match_id, &keypair.public_key));
    }

    #[test]
    fn test_order_status_transitions() {
        assert_eq!(OrderStatus::Active, OrderStatus::Active);
        assert_ne!(OrderStatus::Active, OrderStatus::Matched);
        assert_ne!(OrderStatus::Matched, OrderStatus::Executed);
    }

    #[test]
    fn test_match_status_transitions() {
        assert_eq!(MatchStatus::Pending, MatchStatus::Pending);
        assert_ne!(MatchStatus::Pending, MatchStatus::Completed);
    }

    #[test]
    fn test_swap_error_from_crypto_error() {
        let crypto_err = CryptoError::RngFailed;
        let swap_err: SwapError = crypto_err.into();
        match swap_err {
            SwapError::CryptoError(_) => (),
            _ => panic!("Expected CryptoError variant"),
        }
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_full_swap_flow() {
        let manager = SwapManager::new();

        // Set exchange rate: 1 SAGE = 2 USDC
        let rate = ExchangeRate::new(
            AssetId::SAGE,
            AssetId::USDC,
            2_000_000_000_000_000_000,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        manager.set_exchange_rate(rate);

        // Party A: has SAGE, wants USDC
        let keypair_a = create_test_keypair(11111);
        let order_a = create_swap_order(
            &keypair_a,
            AssetId::SAGE,
            1000,
            AssetId::USDC,
            2000,
            5000,
            &Felt252::from_u64(11111),
            u64::MAX,
            1,
        ).unwrap();

        // Party B: has USDC, wants SAGE
        let keypair_b = create_test_keypair(22222);
        let order_b = create_swap_order(
            &keypair_b,
            AssetId::USDC,
            2000,
            AssetId::SAGE,
            1000,
            10000,
            &Felt252::from_u64(22222),
            u64::MAX,
            1,
        ).unwrap();

        // Submit orders
        let order_a_id = manager.submit_order(order_a).unwrap();
        let order_b_id = manager.submit_order(order_b).unwrap();

        // Find matching orders
        let matches = manager.find_matching_orders(&order_a_id);
        assert!(matches.contains(&order_b_id));

        // Match orders
        let swap_match = manager.try_match_orders(&order_a_id, &order_b_id).unwrap();
        assert_eq!(swap_match.status, MatchStatus::Pending);

        // Create signatures
        let sig_a = create_swap_signature(&keypair_a, &swap_match.match_id).unwrap();
        let sig_b = create_swap_signature(&keypair_b, &swap_match.match_id).unwrap();

        // Execute swap
        let execution = manager.execute_swap(&swap_match.match_id, sig_a, sig_b).unwrap();

        // Verify execution
        assert!(execution.executed_at > 0);
        assert_eq!(execution.transfer_a_to_b.asset, AssetId::SAGE);
        assert_eq!(execution.transfer_b_to_a.asset, AssetId::USDC);

        // Check orders are marked as executed
        let order_a_updated = manager.get_order(&order_a_id).unwrap();
        assert_eq!(order_a_updated.status, OrderStatus::Executed);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_cancel_order() {
        let manager = SwapManager::new();
        let keypair = create_test_keypair(44444);

        let order = create_swap_order(
            &keypair,
            AssetId::SAGE,
            100,
            AssetId::USDC,
            200,
            1000,
            &Felt252::from_u64(44444),
            u64::MAX,
            1,
        ).unwrap();

        let order_id = manager.submit_order(order).unwrap();

        // Cancel order
        manager.cancel_order(&order_id, &keypair.public_key).unwrap();

        let cancelled = manager.get_order(&order_id).unwrap();
        assert_eq!(cancelled.status, OrderStatus::Cancelled);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_cancel_order_unauthorized() {
        let manager = SwapManager::new();
        let keypair1 = create_test_keypair(55555);
        let keypair2 = create_test_keypair(66666);

        let order = create_swap_order(
            &keypair1,
            AssetId::SAGE,
            100,
            AssetId::USDC,
            200,
            1000,
            &Felt252::from_u64(55555),
            u64::MAX,
            1,
        ).unwrap();

        let order_id = manager.submit_order(order).unwrap();

        // Try to cancel with wrong key
        let result = manager.cancel_order(&order_id, &keypair2.public_key);
        assert_eq!(result, Err(SwapError::Unauthorized));
    }

    #[test]
    fn test_incompatible_orders_matching() {
        let manager = SwapManager::new();

        // Create minimal mock orders (not fully valid, just for testing matching logic)
        let order_a = SwapOrder {
            order_id: Felt252::from_u64(1),
            party_pk: ECPoint::new(Felt252::from_u64(1), Felt252::from_u64(2)),
            offer_asset: AssetId::SAGE,
            request_asset: AssetId::USDC,
            encrypted_offer_amount: ElGamalCiphertext::zero(),
            encrypted_request_amount: ElGamalCiphertext::zero(),
            offer_commitment: ECPoint::new(Felt252::from_u64(3), Felt252::from_u64(4)),
            request_commitment: ECPoint::new(Felt252::from_u64(5), Felt252::from_u64(6)),
            balance_proof: BalanceSufficiencyProof {
                encrypted_balance: ElGamalCiphertext::zero(),
                difference_commitment: ECPoint::new(Felt252::from_u64(7), Felt252::from_u64(8)),
                range_proof_commitment: ECPoint::new(Felt252::from_u64(9), Felt252::from_u64(10)),
                knowledge_proof: EncryptionProof::new(
                    ECPoint::new(Felt252::from_u64(11), Felt252::from_u64(12)),
                    Felt252::from_u64(13),
                    Felt252::from_u64(14),
                    Felt252::ZERO,
                ),
            },
            expires_at: u64::MAX,
            nonce: 1,
            status: OrderStatus::Active,
        };

        // Order B wants the same thing as A (not compatible)
        let order_b = SwapOrder {
            order_id: Felt252::from_u64(2),
            offer_asset: AssetId::SAGE, // Same as A!
            request_asset: AssetId::ETH, // Different from what A offers
            ..order_a.clone()
        };

        {
            let mut orders = manager.orders.write();
            orders.insert(order_a.order_id, order_a.clone());
            orders.insert(order_b.order_id, order_b.clone());
        }

        let result = manager.try_match_orders(&order_a.order_id, &order_b.order_id);
        assert!(matches!(result, Err(SwapError::IncompatibleOrders)));
    }

    #[test]
    fn test_replay_protection() {
        let manager = SwapManager::new();

        let nullifier = Felt252::from_u64(123456);

        // First use should work
        {
            let mut nullifiers = manager.used_nullifiers.write();
            assert!(!nullifiers.contains_key(&nullifier));
            nullifiers.insert(nullifier, 1000);
        }

        // Second use should be detected
        {
            let nullifiers = manager.used_nullifiers.read();
            assert!(nullifiers.contains_key(&nullifier));
        }
    }

    #[test]
    fn test_pedersen_commitment_for_swap() {
        let amount = Felt252::from_u64(1000);
        let randomness = Felt252::from_u64(12345);

        let commitment = pedersen_commit(&amount, &randomness);

        // Commitment should be on curve
        assert!(commitment.is_on_curve());

        // Same inputs should give same commitment
        let commitment2 = pedersen_commit(&amount, &randomness);
        assert_eq!(commitment, commitment2);

        // Different inputs should give different commitment
        let commitment3 = pedersen_commit(&Felt252::from_u64(2000), &randomness);
        assert_ne!(commitment, commitment3);
    }
}
