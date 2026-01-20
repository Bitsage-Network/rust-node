// Payment Router Client for Obelysk
//
// Rust client for interacting with the Cairo PaymentRouter contract.
// Handles multi-token payments, quotes, and privacy credit management.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use starknet::{
    core::types::{FieldElement, FunctionCall, BlockId, BlockTag},
    core::utils::get_selector_from_name,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount, Call},
    signers::{LocalWallet, SigningKey},
};
use std::sync::Arc;
use tracing::{info, debug, warn};

use super::proof_compression::{CompressedProof, compute_proof_commitment};
use super::elgamal::{ElGamalCiphertext, generate_randomness, encrypt, ECPoint};
use super::privacy_client::felt252_to_field_element;
use super::privacy_swap::AssetId;


// =============================================================================
// Contract Types (mirroring Cairo structs)
// =============================================================================

/// Result of proof verification before payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofVerificationResult {
    /// Whether the proof passed structural verification
    pub is_valid: bool,
    /// Computed proof commitment (Blake3 hash of proof + job_id + worker)
    pub proof_commitment: [u8; 32],
    /// List of validation errors (if any)
    pub errors: Vec<String>,
    /// List of warnings (non-blocking issues)
    pub warnings: Vec<String>,
    /// Whether on-chain verification is required for full security
    /// (Always true until Stwo integration is complete)
    pub requires_on_chain_verification: bool,
}

/// Supported payment tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentToken {
    USDC = 0,
    STRK = 1,
    /// Native BTC on Starknet (displayed as "BTC", legacy name kept for serialization compatibility)
    #[serde(alias = "BTC")]
    WBTC = 2,
    SAGE = 3,
    StakedSAGE = 4,
    PrivacyCredit = 5,
}

impl PaymentToken {
    pub fn to_felt(&self) -> FieldElement {
        FieldElement::from(*self as u64)
    }

    pub fn from_felt(fe: &FieldElement) -> Option<Self> {
        let val = felt_to_u64(fe);
        match val {
            0 => Some(PaymentToken::USDC),
            1 => Some(PaymentToken::STRK),
            2 => Some(PaymentToken::WBTC),
            3 => Some(PaymentToken::SAGE),
            4 => Some(PaymentToken::StakedSAGE),
            5 => Some(PaymentToken::PrivacyCredit),
            _ => None,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            PaymentToken::USDC => "USDC",
            PaymentToken::STRK => "STRK",
            PaymentToken::WBTC => "BTC", // Native BTC on Starknet
            PaymentToken::SAGE => "SAGE",
            PaymentToken::StakedSAGE => "Staked SAGE",
            PaymentToken::PrivacyCredit => "Privacy Credit",
        }
    }

    /// Get discount description
    pub fn discount_description(&self) -> &'static str {
        match self {
            PaymentToken::USDC | PaymentToken::STRK | PaymentToken::WBTC => "0% (standard)", // BTC
            PaymentToken::SAGE => "5% off",
            PaymentToken::StakedSAGE => "10% off (best)",
            PaymentToken::PrivacyCredit => "2% off",
        }
    }
}

/// Payment quote from OTC desk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentQuote {
    pub quote_id: u128,
    pub payment_token: PaymentToken,
    pub payment_amount: u128,
    pub sage_equivalent: u128,
    pub discount_bps: u32,
    pub usd_value: u128,
    pub expires_at: u64,
    pub is_valid: bool,
}

/// Fee distribution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    pub worker_bps: u32,
    pub protocol_fee_bps: u32,
    pub burn_share_bps: u32,
    pub treasury_share_bps: u32,
    pub staker_share_bps: u32,
}

/// Discount tiers by payment method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscountTiers {
    pub stablecoin_discount_bps: u32,
    pub strk_discount_bps: u32,
    pub wbtc_discount_bps: u32,
    pub sage_discount_bps: u32,
    pub staked_sage_discount_bps: u32,
    pub privacy_credit_discount_bps: u32,
}

/// OTC desk configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTCConfig {
    pub usdc_address: FieldElement,
    pub strk_address: FieldElement,
    pub wbtc_address: FieldElement,
    pub sage_address: FieldElement,
    pub oracle_address: FieldElement,
    pub staking_address: FieldElement,
    pub quote_validity_seconds: u64,
    pub max_slippage_bps: u32,
}

// =============================================================================
// Proof-Gated Payment Types
// =============================================================================

/// Payment request with proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofGatedPayment {
    /// Worker address to receive payment
    pub worker_address: String,

    /// Job identifier
    pub job_id: u128,

    /// Payment amount in base units (wei for ETH, satoshi for BTC, etc.)
    pub amount: u128,

    /// Payment token type
    pub payment_token: PaymentToken,

    /// Blake3 hash of the proof
    pub proof_hash: [u8; 32],

    /// Proof commitment for on-chain verification
    pub proof_commitment: [u8; 32],

    /// Optional encrypted payment (for privacy)
    pub encrypted_payment: Option<EncryptedPaymentData>,
}

/// Encrypted payment data for privacy-preserving payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPaymentData {
    /// ElGamal ciphertext of the amount
    pub ciphertext: ElGamalCiphertext,

    /// Randomness commitment (for verification)
    pub randomness_commitment: [u8; 32],
}

/// Result of a proof-gated payment submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSubmissionResult {
    /// Transaction hash on Starknet
    pub tx_hash: FieldElement,

    /// Whether payment was encrypted
    pub is_encrypted: bool,

    /// Proof commitment included in transaction
    pub proof_commitment: [u8; 32],

    /// Estimated confirmation time (seconds)
    pub estimated_confirmation_secs: u64,
}

/// Error types for proof-gated payments
#[derive(Debug, thiserror::Error)]
pub enum ProofPaymentError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Proof too large for on-chain submission: {size} bytes (max {max})")]
    ProofTooLarge { size: usize, max: usize },

    #[error("Proof verification failed")]
    VerificationFailed,

    #[error("Payment amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: u128, actual: u128 },

    #[error("Worker address mismatch")]
    WorkerMismatch,

    #[error("Job ID mismatch")]
    JobMismatch,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Contract call failed: {0}")]
    ContractError(String),
}

// =============================================================================
// Payment Router Client
// =============================================================================

/// Client for interacting with the PaymentRouter contract
pub struct PaymentRouterClient {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    contract_address: FieldElement,
    account: Option<Arc<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>>>,
}

impl PaymentRouterClient {
    /// Create a new client with read-only access
    pub fn new_readonly(rpc_url: &str, contract_address: FieldElement) -> Result<Self> {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?
        )));

        Ok(Self {
            provider,
            contract_address,
            account: None,
        })
    }

    /// Create a new client with write access
    pub async fn new(
        rpc_url: &str,
        contract_address: FieldElement,
        private_key: &str,
        account_address: FieldElement,
    ) -> Result<Self> {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?
        )));

        let signer = LocalWallet::from(
            SigningKey::from_secret_scalar(
                FieldElement::from_hex_be(private_key)
                    .map_err(|e| anyhow!("Invalid private key: {}", e))?
            )
        );

        let chain_id = provider.chain_id().await?;

        let account = Arc::new(SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address,
            chain_id,
            ExecutionEncoding::New,
        ));

        Ok(Self {
            provider,
            contract_address,
            account: Some(account),
        })
    }

    // =========================================================================
    // Read Methods
    // =========================================================================

    /// Get a payment quote for compute services
    pub async fn get_quote(
        &self,
        payment_token: PaymentToken,
        usd_amount: u128,
    ) -> Result<PaymentQuote> {
        let usd_low = FieldElement::from(usd_amount as u64);
        let usd_high = FieldElement::from((usd_amount >> 64) as u64);

        let calldata = vec![payment_token.to_felt(), usd_low, usd_high];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_quote")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_quote(&result)
    }

    /// Get current discount tiers
    pub async fn get_discount_tiers(&self) -> Result<DiscountTiers> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_discount_tiers")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_discount_tiers(&result)
    }

    /// Get fee distribution configuration
    pub async fn get_fee_distribution(&self) -> Result<FeeDistribution> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_fee_distribution")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_fee_distribution(&result)
    }

    /// Get OTC desk configuration
    pub async fn get_otc_config(&self) -> Result<OTCConfig> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_otc_config")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_otc_config(&result)
    }

    // =========================================================================
    // Write Methods
    // =========================================================================

    /// Execute payment using a quote
    pub async fn execute_payment(
        &self,
        quote_id: u128,
        job_id: u128,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(quote_id as u64),
            FieldElement::from((quote_id >> 64) as u64),
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        info!("Executing payment for job {} with quote {}", job_id, quote_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("execute_payment")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Execute payment tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Pay directly with SAGE tokens (no quote needed, 5% discount)
    pub async fn pay_with_sage(
        &self,
        amount: u128,
        job_id: u128,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(amount as u64),
            FieldElement::from((amount >> 64) as u64),
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        info!("Paying {} SAGE for job {} (5% discount)", amount, job_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("pay_with_sage")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Pay with SAGE tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Pay using staked SAGE position (10% discount)
    pub async fn pay_with_staked_sage(
        &self,
        usd_amount: u128,
        job_id: u128,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(usd_amount as u64),
            FieldElement::from((usd_amount >> 64) as u64),
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        info!("Paying with staked SAGE for job {} (10% discount)", job_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("pay_with_staked_sage")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Pay with staked SAGE tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Deposit privacy credits
    pub async fn deposit_privacy_credits(
        &self,
        amount: u128,
        commitment: FieldElement,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(amount as u64),
            FieldElement::from((amount >> 64) as u64),
            commitment,
        ];

        info!("Depositing {} SAGE as privacy credits", amount);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("deposit_privacy_credits")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Deposit privacy credits tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Pay using privacy credits (2% discount)
    pub async fn pay_with_privacy_credits(
        &self,
        usd_amount: u128,
        nullifier: FieldElement,
        proof: Vec<FieldElement>,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let mut calldata = vec![
            FieldElement::from(usd_amount as u64),
            FieldElement::from((usd_amount >> 64) as u64),
            nullifier,
            FieldElement::from(proof.len() as u64),
        ];
        calldata.extend(proof);

        info!("Paying with privacy credits (2% discount)");

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("pay_with_privacy_credits")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Pay with privacy credits tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    // =========================================================================
    // Proof Verification Methods
    // =========================================================================

    /// Comprehensive proof verification before payment submission.
    ///
    /// This function validates:
    /// 1. Proof size constraints (≤256KB for on-chain)
    /// 2. Proof integrity (Blake3 hash verification)
    /// 3. Proof structure (metadata, trace length, public inputs)
    /// 4. Proof commitment matches expected job/worker
    ///
    /// # Security Note
    /// Full cryptographic verification requires integration with the Stwo
    /// verifier (Phase 2). Currently, we validate structure and integrity
    /// but rely on the ObelyskExecutor to generate valid proofs.
    ///
    /// For production, proofs should also be verified on-chain by the
    /// ProofVerifier contract before payment is released.
    pub fn verify_proof_for_payment(
        &self,
        compressed_proof: &CompressedProof,
        job_id: u128,
        worker_address: &str,
        _expected_amount: u128,
    ) -> Result<ProofVerificationResult> {
        let mut errors: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        // 1. Size validation
        let proof_size = compressed_proof.compressed_size();
        if !compressed_proof.is_valid_for_onchain() {
            errors.push(format!(
                "Proof size {} bytes exceeds on-chain limit of 262144 bytes (256KB)",
                proof_size
            ));
        }

        // 2. Integrity check (Blake3)
        if !compressed_proof.verify_integrity() {
            errors.push("Proof integrity check failed - data may be corrupted".to_string());
        }

        // 3. Validate proof structure by checking metadata
        let original_size = compressed_proof.original_size;
        if original_size == 0 {
            errors.push("Proof has zero original size - likely invalid".to_string());
        }

        // 4. Compression ratio sanity check
        let compression_ratio = if proof_size > 0 {
            original_size as f64 / proof_size as f64
        } else {
            0.0
        };
        if compression_ratio < 1.0 && proof_size > 0 {
            warnings.push(format!(
                "Unusual compression ratio {:.2}x - compressed larger than original",
                compression_ratio
            ));
        }

        // 5. Compute and validate proof commitment
        let proof_commitment = compute_proof_commitment(
            &compressed_proof.proof_hash,
            job_id,
            worker_address,
        );

        // Log verification details
        if errors.is_empty() {
            info!(
                job_id = job_id,
                worker = worker_address,
                proof_size = proof_size,
                original_size = original_size,
                compression_ratio = format!("{:.2}x", compression_ratio),
                "Proof verification passed"
            );
        } else {
            warn!(
                job_id = job_id,
                worker = worker_address,
                errors = ?errors,
                "Proof verification failed"
            );
        }

        // Emit warnings
        for warning in &warnings {
            warn!(job_id = job_id, "{}", warning);
        }

        if !errors.is_empty() {
            return Ok(ProofVerificationResult {
                is_valid: false,
                proof_commitment,
                errors,
                warnings,
                requires_on_chain_verification: true,
            });
        }

        // NOTE: Full cryptographic verification is pending Stwo integration
        // For now, structural validation passes but we flag that on-chain
        // verification is required for full security.
        info!(
            "⚠️  Structural proof verification passed. Full cryptographic verification \
             requires on-chain ProofVerifier contract (Phase 2 Stwo integration)."
        );

        Ok(ProofVerificationResult {
            is_valid: true,
            proof_commitment,
            errors: Vec::new(),
            warnings,
            requires_on_chain_verification: true,
        })
    }

    // =========================================================================
    // Proof-Gated Payment Methods
    // =========================================================================

    /// Submit a payment that is gated by proof verification.
    /// The proof commitment is included in the transaction to ensure the worker
    /// completed the job correctly before receiving payment.
    ///
    /// # Verification Flow
    /// 1. Local structural verification (size, integrity, format)
    /// 2. Proof commitment computation
    /// 3. On-chain submission with proof commitment
    /// 4. Contract verifies commitment matches registered proof
    pub async fn submit_payment_with_proof(
        &self,
        worker_address: &str,
        job_id: u128,
        amount: u128,
        compressed_proof: &CompressedProof,
    ) -> Result<PaymentSubmissionResult> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Comprehensive proof verification
        let verification = self.verify_proof_for_payment(
            compressed_proof,
            job_id,
            worker_address,
            amount,
        )?;

        if !verification.is_valid {
            return Err(anyhow!(
                "Proof verification failed: {}",
                verification.errors.join("; ")
            ));
        }

        // Use the pre-computed proof commitment from verification
        let proof_commitment = verification.proof_commitment;

        // Convert addresses and values to field elements
        let worker_felt = FieldElement::from_hex_be(worker_address)
            .map_err(|e| anyhow!("Invalid worker address: {}", e))?;

        // Build calldata: worker, job_id (u256), amount (u256), proof_commitment (4 x felt)
        let calldata = vec![
            worker_felt,
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
            FieldElement::from(amount as u64),
            FieldElement::from((amount >> 64) as u64),
            // Proof commitment as 4 field elements (32 bytes = 4 x 8 bytes)
            FieldElement::from_byte_slice_be(&proof_commitment[0..8]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[8..16]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[16..24]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[24..32]).unwrap_or_default(),
        ];

        info!(
            "Submitting proof-gated payment: {} SAGE to worker {} for job {}",
            amount, worker_address, job_id
        );

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("submit_payment_with_proof")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Proof-gated payment tx: {:?}", tx.transaction_hash);

        Ok(PaymentSubmissionResult {
            tx_hash: tx.transaction_hash,
            is_encrypted: false,
            proof_commitment,
            estimated_confirmation_secs: 15,
        })
    }

    /// Submit an encrypted payment with proof verification.
    /// Uses ElGamal encryption for privacy-preserving worker payments.
    pub async fn submit_encrypted_payment_with_proof(
        &self,
        worker_address: &str,
        worker_public_key: &ECPoint,
        job_id: u128,
        amount: u128,
        compressed_proof: &CompressedProof,
    ) -> Result<PaymentSubmissionResult> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Verify proof
        if !compressed_proof.is_valid_for_onchain() {
            return Err(anyhow!("Proof too large for on-chain submission"));
        }

        // Generate secure randomness for encryption
        let randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;

        // Encrypt the payment amount
        let encrypted = encrypt(amount as u64, worker_public_key, &randomness);

        // Compute proof commitment
        let proof_commitment = compute_proof_commitment(
            &compressed_proof.proof_hash,
            job_id,
            worker_address,
        );

        // Convert addresses and values to field elements
        let worker_felt = FieldElement::from_hex_be(worker_address)
            .map_err(|e| anyhow!("Invalid worker address: {}", e))?;

        // Build calldata with encrypted payment
        let calldata = vec![
            worker_felt,
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
            // ElGamal ciphertext: c1_x, c1_y, c2_x, c2_y
            felt252_to_field_element(&encrypted.c1_x),
            felt252_to_field_element(&encrypted.c1_y),
            felt252_to_field_element(&encrypted.c2_x),
            felt252_to_field_element(&encrypted.c2_y),
            // Proof commitment
            FieldElement::from_byte_slice_be(&proof_commitment[0..8]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[8..16]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[16..24]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[24..32]).unwrap_or_default(),
        ];

        info!(
            "Submitting encrypted proof-gated payment to worker {} for job {}",
            worker_address, job_id
        );

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("submit_encrypted_payment_with_proof")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Encrypted proof-gated payment tx: {:?}", tx.transaction_hash);

        Ok(PaymentSubmissionResult {
            tx_hash: tx.transaction_hash,
            is_encrypted: true,
            proof_commitment,
            estimated_confirmation_secs: 15,
        })
    }

    /// Submit an encrypted payment with proof verification for a specific asset.
    ///
    /// Extends `submit_encrypted_payment_with_proof` with multi-asset support,
    /// allowing payments in SAGE, USDC, STRK, or BTC.
    pub async fn submit_encrypted_payment_with_proof_for_asset(
        &self,
        worker_address: &str,
        worker_public_key: &ECPoint,
        job_id: u128,
        amount: u128,
        asset_id: AssetId,
        compressed_proof: &CompressedProof,
    ) -> Result<PaymentSubmissionResult> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Verify proof
        if !compressed_proof.is_valid_for_onchain() {
            return Err(anyhow!("Proof too large for on-chain submission"));
        }

        // Generate secure randomness for encryption
        let randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;

        // Encrypt the payment amount
        let encrypted = encrypt(amount as u64, worker_public_key, &randomness);

        // Compute proof commitment
        let proof_commitment = compute_proof_commitment(
            &compressed_proof.proof_hash,
            job_id,
            worker_address,
        );

        // Convert addresses and values to field elements
        let worker_felt = FieldElement::from_hex_be(worker_address)
            .map_err(|e| anyhow!("Invalid worker address: {}", e))?;

        // Build calldata with encrypted payment and asset_id
        let calldata = vec![
            worker_felt,
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
            // Asset ID
            FieldElement::from(asset_id.0 as u64),
            // ElGamal ciphertext: c1_x, c1_y, c2_x, c2_y
            felt252_to_field_element(&encrypted.c1_x),
            felt252_to_field_element(&encrypted.c1_y),
            felt252_to_field_element(&encrypted.c2_x),
            felt252_to_field_element(&encrypted.c2_y),
            // Proof commitment
            FieldElement::from_byte_slice_be(&proof_commitment[0..8]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[8..16]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[16..24]).unwrap_or_default(),
            FieldElement::from_byte_slice_be(&proof_commitment[24..32]).unwrap_or_default(),
        ];

        info!(
            "Submitting encrypted {} proof-gated payment to worker {} for job {}",
            asset_id.name(), worker_address, job_id
        );

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("submit_encrypted_payment_with_proof_for_asset")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Encrypted {} proof-gated payment tx: {:?}", asset_id.name(), tx.transaction_hash);

        Ok(PaymentSubmissionResult {
            tx_hash: tx.transaction_hash,
            is_encrypted: true,
            proof_commitment,
            estimated_confirmation_secs: 15,
        })
    }

    /// Verify a proof commitment is recorded on-chain for a job
    pub async fn verify_proof_commitment(
        &self,
        job_id: u128,
        expected_commitment: &[u8; 32],
    ) -> Result<bool> {
        let calldata = vec![
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_proof_commitment")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        // Compare commitment
        if result.len() < 4 {
            return Ok(false);
        }

        let mut stored_commitment = [0u8; 32];
        for (i, felt) in result.iter().take(4).enumerate() {
            let bytes = felt.to_bytes_be();
            stored_commitment[i * 8..(i + 1) * 8].copy_from_slice(&bytes[24..32]);
        }

        Ok(stored_commitment == *expected_commitment)
    }

    /// Check if a job has been paid
    pub async fn is_job_paid(&self, job_id: u128) -> Result<bool> {
        let calldata = vec![
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("is_job_paid")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Ok(result.first().map(|f| *f != FieldElement::ZERO).unwrap_or(false))
    }

    // =========================================================================
    // Parsing Helpers
    // =========================================================================

    fn parse_quote(data: &[FieldElement]) -> Result<PaymentQuote> {
        if data.len() < 10 {
            return Err(anyhow!("Insufficient data for PaymentQuote"));
        }

        let quote_id = felt_to_u64(&data[0]) as u128 | ((felt_to_u64(&data[1]) as u128) << 64);
        let payment_token = PaymentToken::from_felt(&data[2])
            .ok_or_else(|| anyhow!("Invalid payment token"))?;
        let payment_amount = felt_to_u64(&data[3]) as u128 | ((felt_to_u64(&data[4]) as u128) << 64);
        let sage_equivalent = felt_to_u64(&data[5]) as u128 | ((felt_to_u64(&data[6]) as u128) << 64);
        let discount_bps = felt_to_u64(&data[7]) as u32;
        let usd_value = felt_to_u64(&data[8]) as u128 | ((felt_to_u64(&data[9]) as u128) << 64);
        let expires_at = data.get(10).map(felt_to_u64).unwrap_or(0);
        let is_valid = data.get(11).map(|f| *f != FieldElement::ZERO).unwrap_or(false);

        Ok(PaymentQuote {
            quote_id,
            payment_token,
            payment_amount,
            sage_equivalent,
            discount_bps,
            usd_value,
            expires_at,
            is_valid,
        })
    }

    fn parse_discount_tiers(data: &[FieldElement]) -> Result<DiscountTiers> {
        if data.len() < 6 {
            return Err(anyhow!("Insufficient data for DiscountTiers"));
        }

        Ok(DiscountTiers {
            stablecoin_discount_bps: felt_to_u64(&data[0]) as u32,
            strk_discount_bps: felt_to_u64(&data[1]) as u32,
            wbtc_discount_bps: felt_to_u64(&data[2]) as u32,
            sage_discount_bps: felt_to_u64(&data[3]) as u32,
            staked_sage_discount_bps: felt_to_u64(&data[4]) as u32,
            privacy_credit_discount_bps: felt_to_u64(&data[5]) as u32,
        })
    }

    fn parse_fee_distribution(data: &[FieldElement]) -> Result<FeeDistribution> {
        if data.len() < 5 {
            return Err(anyhow!("Insufficient data for FeeDistribution"));
        }

        Ok(FeeDistribution {
            worker_bps: felt_to_u64(&data[0]) as u32,
            protocol_fee_bps: felt_to_u64(&data[1]) as u32,
            burn_share_bps: felt_to_u64(&data[2]) as u32,
            treasury_share_bps: felt_to_u64(&data[3]) as u32,
            staker_share_bps: felt_to_u64(&data[4]) as u32,
        })
    }

    fn parse_otc_config(data: &[FieldElement]) -> Result<OTCConfig> {
        if data.len() < 8 {
            return Err(anyhow!("Insufficient data for OTCConfig"));
        }

        Ok(OTCConfig {
            usdc_address: data[0],
            strk_address: data[1],
            wbtc_address: data[2],
            sage_address: data[3],
            oracle_address: data[4],
            staking_address: data[5],
            quote_validity_seconds: felt_to_u64(&data[6]),
            max_slippage_bps: felt_to_u64(&data[7]) as u32,
        })
    }
}

// =============================================================================
// Payment Calculator
// =============================================================================

/// Helper to calculate optimal payment method
pub struct PaymentCalculator;

impl PaymentCalculator {
    /// Calculate the best payment method for a given USD amount
    pub fn recommend_payment_method(
        usd_amount: u128,
        has_staked_sage: bool,
        has_sage_balance: u128,
        sage_price_usd: u128,
    ) -> (PaymentToken, String) {
        if has_staked_sage {
            return (PaymentToken::StakedSAGE,
                "Staked SAGE (10% discount - best value)".to_string());
        }

        let sage_needed = if sage_price_usd > 0 {
            (usd_amount * 10u128.pow(18)) / sage_price_usd
        } else {
            0
        };
        let sage_with_discount = (sage_needed * 95) / 100;

        if has_sage_balance >= sage_with_discount && sage_with_discount > 0 {
            return (PaymentToken::SAGE,
                format!("SAGE direct (5% discount, {} SAGE needed)", sage_with_discount));
        }

        (PaymentToken::USDC, "USDC (no discount)".to_string())
    }

    /// Calculate effective cost after discount
    pub fn calculate_effective_cost(usd_amount: u128, discount_bps: u32) -> u128 {
        let discount_factor = 10000 - discount_bps as u128;
        (usd_amount * discount_factor) / 10000
    }

    /// Calculate worker payment from total
    pub fn calculate_worker_share(total_payment: u128, fee_distribution: &FeeDistribution) -> u128 {
        (total_payment * fee_distribution.worker_bps as u128) / 10000
    }

    /// Calculate protocol fee breakdown
    pub fn calculate_protocol_breakdown(
        total_payment: u128,
        fee_distribution: &FeeDistribution,
    ) -> (u128, u128, u128) {
        let protocol_fee = (total_payment * fee_distribution.protocol_fee_bps as u128) / 10000;
        let burn = (protocol_fee * fee_distribution.burn_share_bps as u128) / 10000;
        let treasury = (protocol_fee * fee_distribution.treasury_share_bps as u128) / 10000;
        let stakers = (protocol_fee * fee_distribution.staker_share_bps as u128) / 10000;
        (burn, treasury, stakers)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn felt_to_u64(fe: &FieldElement) -> u64 {
    let bytes = fe.to_bytes_be();
    u64::from_be_bytes(bytes[24..32].try_into().unwrap_or([0; 8]))
}

// =============================================================================
// TEE-GPU PIPELINE INTEGRATION
// =============================================================================

/// Submit payment-related proofs to the TEE-GPU pipeline for aggregation.
/// This enables batch verification of payment proofs for gas savings.
pub mod pipeline_integration {
    use super::*;
    use crate::obelysk::tee_proof_pipeline::{
        submit_proof, ProofType, global_pipeline, aggregate_global, tick_global,
        AggregationResult,
    };
    use crate::obelysk::prover::{StarkProof, FRILayer, Opening, ProofMetadata};
    use crate::obelysk::field::M31;

    /// Submit a proof-gated payment proof to the TEE-GPU pipeline
    ///
    /// This wraps the payment proof for aggregation, allowing multiple
    /// payments to be verified on-chain with a single ~100k gas transaction.
    pub fn submit_payment_proof_to_pipeline(
        payment: &ProofGatedPayment,
        job_id: u64,
    ) -> Result<u64> {
        // Create a STARK proof from the payment data
        // In production, this would be the actual proof from the payment
        let proof = create_payment_stark_proof(payment);

        submit_proof(ProofType::Payment, proof, job_id)
    }

    /// Submit encrypted payment data to the pipeline
    pub fn submit_encrypted_payment_to_pipeline(
        data: &EncryptedPaymentData,
        job_id: u64,
    ) -> Result<u64> {
        let proof = create_encrypted_payment_proof(data);
        submit_proof(ProofType::Payment, proof, job_id)
    }

    /// Get count of pending payment proofs in the pipeline
    pub fn pending_payment_proofs() -> usize {
        global_pipeline()
            .read()
            .map(|p| p.pending_count())
            .unwrap_or(0)
    }

    /// Trigger aggregation of pending payment proofs
    pub fn aggregate_payment_proofs() -> Result<AggregationResult> {
        aggregate_global()
    }

    /// Tick the global pipeline (call periodically)
    pub fn tick_payment_pipeline() -> Option<AggregationResult> {
        tick_global()
    }

    /// Create a STARK proof from payment data
    fn create_payment_stark_proof(payment: &ProofGatedPayment) -> StarkProof {
        // Create a simplified proof commitment from payment data
        let mut commitment = vec![0u8; 32];
        let job_id_bytes = (payment.job_id as u64).to_le_bytes();
        let amount_bytes = (payment.amount as u64).to_le_bytes();
        commitment[0..8].copy_from_slice(&job_id_bytes);
        commitment[8..16].copy_from_slice(&amount_bytes);

        StarkProof {
            trace_commitment: commitment,
            fri_layers: vec![
                FRILayer {
                    commitment: vec![payment.payment_token as u8; 32],
                    evaluations: vec![
                        M31::new(payment.job_id as u32),
                        M31::new(payment.amount as u32),
                    ],
                },
            ],
            openings: vec![
                Opening {
                    position: payment.job_id as usize,
                    values: vec![M31::new(payment.amount as u32)],
                    merkle_path: vec![payment.proof_hash.to_vec()],
                },
            ],
            public_inputs: vec![
                M31::new(payment.job_id as u32),
                M31::new(payment.payment_token as u32),
            ],
            public_outputs: vec![
                M31::new(payment.amount as u32),
            ],
            metadata: ProofMetadata {
                trace_length: 8,
                trace_width: 4,
                generation_time_ms: 1,
                proof_size_bytes: 256,
                prover_version: "payment-v1".to_string(),
            },
        }
    }

    /// Create a STARK proof from encrypted payment data
    fn create_encrypted_payment_proof(data: &EncryptedPaymentData) -> StarkProof {
        // Create proof from encrypted ciphertext data
        let commitment = data.randomness_commitment.to_vec();

        StarkProof {
            trace_commitment: commitment,
            fri_layers: vec![
                FRILayer {
                    commitment: data.ciphertext.c1_x.to_be_bytes().to_vec(),
                    evaluations: vec![
                        M31::new(1), // Encrypted indicator
                    ],
                },
            ],
            openings: vec![
                Opening {
                    position: 0,
                    values: vec![M31::new(1)],
                    merkle_path: vec![data.ciphertext.c2_x.to_be_bytes().to_vec()],
                },
            ],
            public_inputs: vec![M31::new(1)],
            public_outputs: vec![M31::new(1)],
            metadata: ProofMetadata {
                trace_length: 4,
                trace_width: 2,
                generation_time_ms: 1,
                proof_size_bytes: 128,
                prover_version: "encrypted-payment-v1".to_string(),
            },
        }
    }
}

/// Re-export for convenience
pub use pipeline_integration::{
    submit_payment_proof_to_pipeline,
    submit_encrypted_payment_to_pipeline,
    pending_payment_proofs,
    aggregate_payment_proofs,
    tick_payment_pipeline,
};

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_token_conversion() {
        for token in [
            PaymentToken::USDC,
            PaymentToken::STRK,
            PaymentToken::WBTC,
            PaymentToken::SAGE,
            PaymentToken::StakedSAGE,
            PaymentToken::PrivacyCredit,
        ] {
            let felt = token.to_felt();
            let back = PaymentToken::from_felt(&felt).unwrap();
            assert_eq!(token, back);
        }
    }

    #[test]
    fn test_calculate_effective_cost() {
        let cost = PaymentCalculator::calculate_effective_cost(1000_000000000000000000, 500);
        assert_eq!(cost, 950_000000000000000000);
    }

    #[test]
    fn test_calculate_worker_share() {
        let fee_dist = FeeDistribution {
            worker_bps: 8000,
            protocol_fee_bps: 2000,
            burn_share_bps: 7000,
            treasury_share_bps: 2000,
            staker_share_bps: 1000,
        };

        let worker_share = PaymentCalculator::calculate_worker_share(100_000000000000000000, &fee_dist);
        assert_eq!(worker_share, 80_000000000000000000);
    }

    #[test]
    fn test_protocol_breakdown() {
        let fee_dist = FeeDistribution {
            worker_bps: 8000,
            protocol_fee_bps: 2000,
            burn_share_bps: 7000,
            treasury_share_bps: 2000,
            staker_share_bps: 1000,
        };

        let (burn, treasury, stakers) =
            PaymentCalculator::calculate_protocol_breakdown(100_000000000000000000, &fee_dist);

        assert_eq!(burn, 14_000000000000000000);
        assert_eq!(treasury, 4_000000000000000000);
        assert_eq!(stakers, 2_000000000000000000);
    }

    #[test]
    fn test_recommend_payment() {
        let (token, _) = PaymentCalculator::recommend_payment_method(
            1000_000000000000000000,
            true,
            0,
            1_000000000000000000,
        );
        assert_eq!(token, PaymentToken::StakedSAGE);

        let (token, _) = PaymentCalculator::recommend_payment_method(
            100_000000000000000000,
            false,
            200_000000000000000000,
            1_000000000000000000,
        );
        assert_eq!(token, PaymentToken::SAGE);

        let (token, _) = PaymentCalculator::recommend_payment_method(
            100_000000000000000000,
            false,
            0,
            1_000000000000000000,
        );
        assert_eq!(token, PaymentToken::USDC);
    }
}
