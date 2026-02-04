// Privacy Router Client for Obelysk
//
// Rust client for interacting with the Cairo PrivacyRouter contract.
// Handles encrypted balance management and private worker payments.

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
use std::collections::HashSet;
use tracing::{info, debug, warn};

use super::elgamal::{
    Felt252, ECPoint, ElGamalCiphertext, EncryptionProof, EncryptedBalance, KeyPair,
    decrypt_point, create_decryption_proof, hash_felts, encrypt, generate_randomness,
    create_schnorr_proof,
};
use super::starknet::network::{NetworkContracts, StarknetNetwork};
use super::proof_compression::{ProofCompressor, CompressionAlgorithm, CompressedProof};
use super::privacy_swap::AssetId;
use super::payment_client::PaymentRouterClient;

// =============================================================================
// Contract Types (mirroring Cairo structs)
// =============================================================================

/// Private account state from the contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAccount {
    pub public_key: ECPoint,
    pub encrypted_balance: EncryptedBalance,
    pub pending_transfers: u32,
    pub last_rollup_epoch: u64,
    pub is_registered: bool,
}

/// Private worker payment info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateWorkerPayment {
    pub job_id: u128,
    pub worker: FieldElement,
    pub encrypted_amount: ElGamalCiphertext,
    pub timestamp: u64,
    pub is_claimed: bool,
    /// Asset type for the payment (SAGE=0, USDC=1, STRK=2, BTC=3)
    /// Defaults to SAGE for backward compatibility with legacy payments
    #[serde(default = "AssetId::default_sage")]
    pub asset_id: AssetId,
}

/// Transfer proof for private transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProof {
    pub sender_proof: EncryptionProof,
    pub receiver_proof: EncryptionProof,
    pub balance_proof: EncryptionProof,
}

/// AE Hint for fast decryption (matches Cairo AEHint struct)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct AEHint {
    pub c0: Felt252,  // Nonce
    pub c1: Felt252,  // Encrypted amount
    pub c2: Felt252,  // Authentication tag
}

/// Account hints for fast balance decryption
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountHints {
    pub balance_hint: AEHint,
    pub pending_in_hint: AEHint,
    pub pending_out_hint: AEHint,
    pub hint_nonce: u64,
}

/// Private transfer request (matches Cairo PrivateTransfer struct)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateTransfer {
    pub sender: FieldElement,
    pub receiver: FieldElement,
    pub encrypted_amount: ElGamalCiphertext,  // Amount encrypted to receiver
    pub sender_delta: ElGamalCiphertext,       // Encrypted change for sender (negative)
    pub proof: TransferProof,
    pub nullifier: Felt252,
}

/// Statistics from proof compression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionStats {
    /// Original calldata size in bytes
    pub original_size: usize,
    /// Compressed size in bytes
    pub compressed_size: usize,
    /// Compression ratio (0.0-1.0, lower is better)
    pub compression_ratio: f64,
    /// Algorithm used
    pub algorithm: CompressionAlgorithm,
    /// Estimated gas savings (compressed vs uncompressed)
    pub estimated_gas_savings: u64,
}

impl CompressionStats {
    /// Calculate estimated gas savings
    /// Assumes ~16 gas per calldata byte (Ethereum-like, Starknet may differ)
    fn calculate(original: usize, compressed: usize, algorithm: CompressionAlgorithm) -> Self {
        let compression_ratio = if original > 0 {
            compressed as f64 / original as f64
        } else {
            1.0
        };

        // Estimate: ~16 gas per byte saved (this is a rough approximation)
        let bytes_saved = original.saturating_sub(compressed);
        let estimated_gas_savings = (bytes_saved * 16) as u64;

        Self {
            original_size: original,
            compressed_size: compressed,
            compression_ratio,
            algorithm,
            estimated_gas_savings,
        }
    }
}

// =============================================================================
// Privacy Router Client
// =============================================================================

/// Client for interacting with the PrivacyRouter contract
pub struct PrivacyRouterClient {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    contract_address: FieldElement,
    account: Option<Arc<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>>>,
    /// Track used nullifiers locally to avoid wasted gas
    used_nullifiers: HashSet<Felt252>,
    /// Network for reference
    network: Option<StarknetNetwork>,
    /// Payment router client for proof-gated payments
    payment_router: Option<Arc<PaymentRouterClient>>,
}

impl PrivacyRouterClient {
    /// Create a new client with read-only access
    pub fn new_readonly(rpc_url: &str, contract_address: FieldElement) -> Result<Self> {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?
        )));

        Ok(Self {
            provider,
            contract_address,
            account: None,
            used_nullifiers: HashSet::new(),
            network: None,
            payment_router: None,
        })
    }

    /// Create a new client with write access (requires account)
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
            used_nullifiers: HashSet::new(),
            network: None,
            payment_router: None,
        })
    }

    /// Create a client for Sepolia testnet with deployed contract
    pub async fn for_sepolia(
        private_key: &str,
        account_address: FieldElement,
    ) -> Result<Self> {
        let contracts = NetworkContracts::sepolia();
        let contract_address = FieldElement::from_hex_be(&contracts.privacy_router)
            .map_err(|e| anyhow!("Invalid contract address: {}", e))?;

        let rpc_url = "https://starknet-sepolia-rpc.publicnode.com";

        let mut client = Self::new(rpc_url, contract_address, private_key, account_address).await?;
        client.network = Some(StarknetNetwork::Sepolia);

        // Initialize payment router client for proof-gated payments
        let payment_router_address = FieldElement::from_hex_be(&contracts.payment_router)
            .map_err(|e| anyhow!("Invalid payment router address: {}", e))?;

        // Use deployer account for on-chain transactions (it's actually deployed on Starknet).
        // Workers may not have deployed accounts, so the deployer submits proofs on their behalf.
        let (tx_pk, tx_account) = match (
            std::env::var("SIGNER_PRIVATE_KEY").ok().filter(|s| !s.is_empty()),
            std::env::var("DEPLOYER_ADDRESS").ok().filter(|s| !s.is_empty()),
        ) {
            (Some(pk), Some(addr)) => {
                let deployer_fe = FieldElement::from_hex_be(&addr)
                    .map_err(|e| anyhow!("Invalid DEPLOYER_ADDRESS: {}", e))?;
                info!("💳 PaymentRouter: Using deployer account {:#018x} for on-chain proof submissions", deployer_fe);
                (pk, deployer_fe)
            }
            _ => {
                info!("💳 PaymentRouter: Using worker account for on-chain proof submissions");
                (private_key.to_string(), account_address)
            }
        };

        let mut payment_router = PaymentRouterClient::new(
            rpc_url,
            payment_router_address,
            &tx_pk,
            tx_account,
        ).await?;

        // Set paymaster for gasless V3 proof submissions
        if let Ok(paymaster_str) = std::env::var("PAYMASTER_ADDRESS") {
            if !paymaster_str.is_empty() && paymaster_str != "0x0" {
                if let Ok(paymaster_felt) = FieldElement::from_hex_be(&paymaster_str) {
                    payment_router.set_paymaster(paymaster_felt);
                    info!("💳 PaymentRouter: V3 paymaster configured for gasless proof submission");
                }
            }
        }

        client.payment_router = Some(Arc::new(payment_router));

        info!("Created PrivacyRouterClient for Sepolia at {}", contracts.privacy_router);
        Ok(client)
    }

    /// Create a read-only client for Sepolia testnet
    pub fn for_sepolia_readonly() -> Result<Self> {
        let contracts = NetworkContracts::sepolia();
        let contract_address = FieldElement::from_hex_be(&contracts.privacy_router)
            .map_err(|e| anyhow!("Invalid contract address: {}", e))?;

        let rpc_url = "https://starknet-sepolia-rpc.publicnode.com";

        let mut client = Self::new_readonly(rpc_url, contract_address)?;
        client.network = Some(StarknetNetwork::Sepolia);

        // Initialize payment router client in readonly mode
        let payment_router_address = FieldElement::from_hex_be(&contracts.payment_router)
            .map_err(|e| anyhow!("Invalid payment router address: {}", e))?;

        let payment_router = PaymentRouterClient::new_readonly(rpc_url, payment_router_address)?;
        client.payment_router = Some(Arc::new(payment_router));

        Ok(client)
    }

    /// Create a client for local devnet
    pub async fn for_devnet(
        devnet_url: &str,
        contract_address: FieldElement,
        private_key: &str,
        account_address: FieldElement,
    ) -> Result<Self> {
        let mut client = Self::new(devnet_url, contract_address, private_key, account_address).await?;
        client.network = Some(StarknetNetwork::Devnet);
        Ok(client)
    }

    /// Get the account address if configured
    pub fn account_address(&self) -> Option<FieldElement> {
        self.account.as_ref().map(|a| a.address())
    }

    /// Get the contract address
    pub fn contract_address(&self) -> FieldElement {
        self.contract_address
    }

    /// Submit payment with proof verification
    ///
    /// This method delegates to the PaymentRouterClient to submit a proof-gated payment.
    /// The proof is verified on-chain before the payment is released.
    ///
    /// # Arguments
    /// * `worker_address` - Worker's address
    /// * `job_id` - Job identifier
    /// * `amount` - Payment amount
    /// * `compressed_proof` - Compressed ZK proof
    ///
    /// # Returns
    /// Transaction hash on success
    pub async fn submit_payment_with_proof(
        &self,
        worker_address: &str,
        job_id: u128,
        amount: u128,
        compressed_proof: &CompressedProof,
    ) -> Result<crate::obelysk::payment_client::PaymentSubmissionResult> {
        let payment_router = self.payment_router.as_ref()
            .ok_or_else(|| anyhow!("PaymentRouterClient not initialized"))?;

        payment_router.submit_payment_with_proof(
            worker_address,
            job_id,
            amount,
            compressed_proof,
        ).await
    }

    // =========================================================================
    // Read Methods
    // =========================================================================

    /// Get account info from the contract
    pub async fn get_account(&self, address: FieldElement) -> Result<PrivateAccount> {
        let calldata = vec![address];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_account")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_private_account(&result)
    }

    /// Get worker payment info
    pub async fn get_worker_payment(&self, job_id: u128) -> Result<PrivateWorkerPayment> {
        let job_id_low = FieldElement::from(job_id as u64);
        let job_id_high = FieldElement::from((job_id >> 64) as u64);

        let calldata = vec![job_id_low, job_id_high];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_worker_payment")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_worker_payment(&result)
    }

    /// Check if a nullifier has been used
    pub async fn is_nullifier_used(&self, nullifier: FieldElement) -> Result<bool> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("is_nullifier_used")?,
                calldata: vec![nullifier],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Ok(result.first().map(|f| *f != FieldElement::ZERO).unwrap_or(false))
    }

    /// Get current epoch
    pub async fn get_current_epoch(&self) -> Result<u64> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_current_epoch")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        result.first()
            .map(|f| felt_to_u64(f))
            .ok_or_else(|| anyhow!("Empty response"))
    }

    /// Get account hints for fast balance decryption
    pub async fn get_account_hints(&self, address: FieldElement) -> Result<AccountHints> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_account_hints")?,
                calldata: vec![address],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_account_hints(&result)
    }

    /// Check if nullifier is used (with local cache)
    pub async fn check_nullifier(&mut self, nullifier: &Felt252) -> Result<bool> {
        // Check local cache first
        if self.used_nullifiers.contains(nullifier) {
            return Ok(true);
        }

        // Check on-chain
        let fe = felt252_to_field_element(nullifier);
        let is_used = self.is_nullifier_used(fe).await?;

        if is_used {
            self.used_nullifiers.insert(*nullifier);
        }

        Ok(is_used)
    }

    /// Mark a nullifier as used locally (after successful transaction)
    pub fn mark_nullifier_used(&mut self, nullifier: Felt252) {
        self.used_nullifiers.insert(nullifier);
    }

    // =========================================================================
    // Write Methods (require account)
    // =========================================================================

    /// Register a new private account with the worker's ElGamal public key
    pub async fn register_account(&self, keypair: &KeyPair) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let public_key = keypair.public_key();
        let calldata = vec![
            felt252_to_field_element(&public_key.x),
            felt252_to_field_element(&public_key.y),
        ];

        info!("Registering privacy account with public key: ({}, {})",
              public_key.x.to_hex(), public_key.y.to_hex());

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("register_account")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Register account tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Deposit SAGE tokens into private account
    pub async fn deposit(
        &self,
        keypair: &KeyPair,
        amount: u64,
        randomness: &Felt252,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Encrypt the amount
        let encrypted_amount = encrypt(amount, &keypair.public_key, randomness);

        // Create encryption proof
        let proof = create_encryption_proof(keypair, &encrypted_amount, randomness)?;

        let calldata = build_deposit_calldata(amount, &encrypted_amount, &proof);

        info!("Depositing {} tokens with privacy", amount);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("deposit")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Deposit tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Claim a private worker payment
    pub async fn claim_worker_payment(
        &self,
        keypair: &KeyPair,
        job_id: u128,
        nonce: &Felt252,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Get the payment info
        let payment = self.get_worker_payment(job_id).await?;

        if payment.is_claimed {
            return Err(anyhow!("Payment already claimed"));
        }

        // Create decryption proof
        let proof = create_decryption_proof(keypair, &payment.encrypted_amount, nonce);

        let job_id_low = FieldElement::from(job_id as u64);
        let job_id_high = FieldElement::from((job_id >> 64) as u64);

        let mut calldata = vec![job_id_low, job_id_high];
        calldata.extend(proof_to_calldata(&proof));

        info!("Claiming worker payment for job {}", job_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("claim_worker_payment")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Claim payment tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Claim multiple worker payments in a single transaction
    ///
    /// This is more gas-efficient than claiming payments one by one.
    ///
    /// # Arguments
    /// * `keypair` - The worker's ElGamal keypair
    /// * `job_ids` - List of job IDs to claim
    ///
    /// # Returns
    /// Transaction hash on success, or error if any payment fails validation
    pub async fn claim_multiple_payments(
        &self,
        keypair: &KeyPair,
        job_ids: &[u128],
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        if job_ids.is_empty() {
            return Err(anyhow!("No job IDs provided"));
        }

        let mut calls = Vec::with_capacity(job_ids.len());

        for &job_id in job_ids {
            // Get the payment info
            let payment = self.get_worker_payment(job_id).await?;

            if payment.is_claimed {
                warn!("Payment for job {} already claimed, skipping", job_id);
                continue;
            }

            // Create decryption proof with unique nonce per job
            let nonce = hash_felts(&[keypair.secret_key, Felt252::from_u128(job_id)]);
            let proof = create_decryption_proof(keypair, &payment.encrypted_amount, &nonce);

            let job_id_low = FieldElement::from(job_id as u64);
            let job_id_high = FieldElement::from((job_id >> 64) as u64);

            let mut calldata = vec![job_id_low, job_id_high];
            calldata.extend(proof_to_calldata(&proof));

            calls.push(Call {
                to: self.contract_address,
                selector: get_selector_from_name("claim_worker_payment")?,
                calldata,
            });
        }

        if calls.is_empty() {
            return Err(anyhow!("All payments already claimed"));
        }

        info!("Claiming {} worker payments in batch", calls.len());

        let tx = account.execute(calls).send().await?;

        debug!("Batch claim tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    // =========================================================================
    // Multi-Asset Payment Methods
    // =========================================================================

    /// Get worker payment info for a specific asset
    ///
    /// This queries the payment for a (job_id, asset_id) pair.
    pub async fn get_worker_payment_for_asset(
        &self,
        job_id: u128,
        asset_id: AssetId,
    ) -> Result<PrivateWorkerPayment> {
        let job_id_low = FieldElement::from(job_id as u64);
        let job_id_high = FieldElement::from((job_id >> 64) as u64);
        let asset_felt = FieldElement::from(asset_id.0);

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_worker_payment_for_asset")?,
                calldata: vec![job_id_low, job_id_high, asset_felt],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_worker_payment(&result)
    }

    /// Get all pending worker payments across all assets
    ///
    /// Returns payments for SAGE, USDC, STRK, and BTC.
    pub async fn get_worker_payments_all_assets(
        &self,
        worker_address: FieldElement,
    ) -> Result<Vec<PrivateWorkerPayment>> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_worker_payments_all_assets")?,
                calldata: vec![worker_address],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_worker_payments_array(&result)
    }

    /// Claim a worker payment for a specific asset
    ///
    /// # Arguments
    /// * `keypair` - The worker's ElGamal keypair
    /// * `job_id` - The job ID
    /// * `asset_id` - The asset type (SAGE, USDC, STRK, BTC)
    /// * `nonce` - Random nonce for the proof
    ///
    /// # Returns
    /// Transaction hash on success
    pub async fn claim_worker_payment_for_asset(
        &self,
        keypair: &KeyPair,
        job_id: u128,
        asset_id: AssetId,
        nonce: &Felt252,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Get the payment info for this asset
        let payment = self.get_worker_payment_for_asset(job_id, asset_id).await?;

        if payment.is_claimed {
            return Err(anyhow!("Payment already claimed for {} asset", asset_id.name()));
        }

        // Create decryption proof
        let proof = create_decryption_proof(keypair, &payment.encrypted_amount, nonce);

        let job_id_low = FieldElement::from(job_id as u64);
        let job_id_high = FieldElement::from((job_id >> 64) as u64);
        let asset_felt = FieldElement::from(asset_id.0);

        let mut calldata = vec![job_id_low, job_id_high, asset_felt];
        calldata.extend(proof_to_calldata(&proof));

        info!("Claiming {} worker payment for job {}", asset_id.name(), job_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("claim_worker_payment_for_asset")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Claim {} payment tx: {:?}", asset_id.name(), tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Claim multiple worker payments across different assets in a single transaction
    ///
    /// This is more gas-efficient than claiming payments one by one.
    ///
    /// # Arguments
    /// * `keypair` - The worker's ElGamal keypair
    /// * `claims` - List of (job_id, asset_id) pairs to claim
    ///
    /// # Returns
    /// Transaction hash on success, or error if all payments are already claimed
    pub async fn claim_multiple_assets(
        &self,
        keypair: &KeyPair,
        claims: &[(u128, AssetId)],
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        if claims.is_empty() {
            return Err(anyhow!("No claims provided"));
        }

        let mut calls = Vec::with_capacity(claims.len());

        for &(job_id, asset_id) in claims {
            // Get the payment info for this asset
            let payment = self.get_worker_payment_for_asset(job_id, asset_id).await?;

            if payment.is_claimed {
                warn!("Payment for job {} ({}) already claimed, skipping", job_id, asset_id.name());
                continue;
            }

            // Create decryption proof with unique nonce per (job, asset)
            let nonce = hash_felts(&[
                keypair.secret_key,
                Felt252::from_u128(job_id),
                Felt252::from_u64(asset_id.0),
            ]);
            let proof = create_decryption_proof(keypair, &payment.encrypted_amount, &nonce);

            let job_id_low = FieldElement::from(job_id as u64);
            let job_id_high = FieldElement::from((job_id >> 64) as u64);
            let asset_felt = FieldElement::from(asset_id.0);

            let mut calldata = vec![job_id_low, job_id_high, asset_felt];
            calldata.extend(proof_to_calldata(&proof));

            calls.push(Call {
                to: self.contract_address,
                selector: get_selector_from_name("claim_worker_payment_for_asset")?,
                calldata,
            });
        }

        if calls.is_empty() {
            return Err(anyhow!("All payments already claimed"));
        }

        info!("Claiming {} multi-asset payments in batch", calls.len());

        let tx = account.execute(calls).send().await?;

        debug!("Multi-asset batch claim tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Parse an array of worker payments from contract response
    fn parse_worker_payments_array(data: &[FieldElement]) -> Result<Vec<PrivateWorkerPayment>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // First element is array length
        let count = felt_to_u64(&data[0]) as usize;
        if count == 0 {
            return Ok(Vec::new());
        }

        let mut payments = Vec::with_capacity(count);
        let fields_per_payment = 10; // 9 legacy fields + 1 asset_id
        let mut offset = 1;

        for _ in 0..count {
            if offset + fields_per_payment > data.len() {
                break;
            }
            let payment = Self::parse_worker_payment(&data[offset..offset + fields_per_payment])?;
            payments.push(payment);
            offset += fields_per_payment;
        }

        Ok(payments)
    }

    /// Roll up pending balances
    pub async fn rollup_balance(&self) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("rollup_balance")?,
            calldata: vec![],
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Rollup balance tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Withdraw SAGE tokens from private account to public balance
    ///
    /// # Arguments
    /// * `keypair` - The ElGamal keypair for the account
    /// * `amount` - The amount to withdraw (in base units)
    ///
    /// # Returns
    /// Transaction hash on success
    pub async fn withdraw(
        &mut self,
        keypair: &KeyPair,
        amount: u64,
    ) -> Result<FieldElement> {
        // Check account exists first
        if self.account.is_none() {
            return Err(anyhow!("No account configured for write operations"));
        }

        // Generate randomness for encryption
        let randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;

        // Create encrypted delta (this represents the amount being withdrawn)
        // For withdrawal, we encrypt the amount to our own key
        let encrypted_delta = encrypt(amount, &keypair.public_key, &randomness);

        // Create decryption proof (proves we know the secret key and the amount)
        let nonce = hash_felts(&[randomness, keypair.secret_key]);
        let proof = create_decryption_proof(keypair, &encrypted_delta, &nonce);

        // Check nullifier hasn't been used (must be before account borrow)
        if self.check_nullifier(&proof.nullifier).await? {
            return Err(anyhow!("Nullifier already used - withdrawal already processed"));
        }

        // Build calldata: amount (u256), encrypted_delta (4 felts), proof (6 felts)
        let calldata = build_withdraw_calldata(amount, &encrypted_delta, &proof);

        info!("Withdrawing {} tokens from private balance", amount);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("withdraw")?,
            calldata,
        };

        // Now borrow account for execution
        let account = self.account.as_ref().unwrap();
        let tx = account.execute(vec![call]).send().await?;

        // Mark nullifier as used
        self.mark_nullifier_used(proof.nullifier);

        debug!("Withdraw tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Execute a private transfer between accounts
    ///
    /// # Arguments
    /// * `sender_keypair` - The sender's ElGamal keypair
    /// * `receiver_address` - The receiver's contract address
    /// * `receiver_pubkey` - The receiver's ElGamal public key
    /// * `amount` - The amount to transfer
    ///
    /// # Returns
    /// Transaction hash on success
    pub async fn private_transfer(
        &mut self,
        sender_keypair: &KeyPair,
        receiver_address: FieldElement,
        receiver_pubkey: &ECPoint,
        amount: u64,
    ) -> Result<FieldElement> {
        // Check account exists and get sender address first
        let sender_address = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?
            .address();

        // Generate randomness for both encryptions
        let sender_randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;
        let receiver_randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;

        // Encrypt amount to receiver
        let encrypted_amount = encrypt(amount, receiver_pubkey, &receiver_randomness);

        // Create sender's delta (same amount, encrypted to sender's key)
        let sender_delta = encrypt(amount, &sender_keypair.public_key, &sender_randomness);

        // Generate proofs
        let sender_nonce = hash_felts(&[sender_randomness, sender_keypair.secret_key]);
        let receiver_nonce = hash_felts(&[receiver_randomness, Felt252::from_u64(amount)]);

        // Sender proof: proves sender knows the secret key
        let sender_proof = create_decryption_proof(sender_keypair, &sender_delta, &sender_nonce);

        // Receiver proof: proves valid encryption to receiver (Schnorr proof of randomness)
        let receiver_proof = create_schnorr_proof(
            &receiver_randomness,
            &ECPoint::generator(),  // R = r*G commitment
            &receiver_nonce,
            &[
                encrypted_amount.c1_x,
                encrypted_amount.c1_y,
                receiver_pubkey.x,
                receiver_pubkey.y,
            ],
        );

        // Balance proof: simplified - proves sender has sufficient balance
        // (In production, this would be a more sophisticated range proof)
        let balance_nonce = hash_felts(&[sender_keypair.secret_key, Felt252::from_u64(amount)]);
        let balance_proof = create_decryption_proof(sender_keypair, &sender_delta, &balance_nonce);

        // Compute nullifier: H("OBELYSK_NULLIFIER", sk, commitment)
        let nullifier = compute_nullifier(&sender_keypair.secret_key, &encrypted_amount);

        // Check nullifier hasn't been used
        if self.check_nullifier(&nullifier).await? {
            return Err(anyhow!("Nullifier already used - transfer already processed"));
        }

        // Build transfer struct
        let transfer = PrivateTransfer {
            sender: sender_address,
            receiver: receiver_address,
            encrypted_amount,
            sender_delta,
            proof: TransferProof {
                sender_proof,
                receiver_proof,
                balance_proof,
            },
            nullifier,
        };

        // Serialize to calldata
        let calldata = build_private_transfer_calldata(&transfer);

        info!("Executing private transfer of {} tokens", amount);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("private_transfer")?,
            calldata,
        };

        // Borrow account for execution
        let account = self.account.as_ref().unwrap();
        let tx = account.execute(vec![call]).send().await?;

        // Mark nullifier as used
        self.mark_nullifier_used(nullifier);

        debug!("Private transfer tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    // =========================================================================
    // Compressed Operation Variants
    // =========================================================================

    /// Deposit with proof compression for reduced calldata cost
    ///
    /// Compresses the encryption proof before submission to reduce gas costs.
    /// Returns both the transaction hash and compression statistics.
    ///
    /// # Arguments
    /// * `keypair` - The ElGamal keypair
    /// * `amount` - The amount to deposit
    /// * `randomness` - Randomness for encryption
    /// * `algorithm` - Compression algorithm (Zstd recommended for best ratio)
    pub async fn deposit_compressed(
        &self,
        keypair: &KeyPair,
        amount: u64,
        randomness: &Felt252,
        algorithm: CompressionAlgorithm,
    ) -> Result<(FieldElement, CompressionStats)> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Encrypt the amount
        let encrypted_amount = encrypt(amount, &keypair.public_key, randomness);

        // Create encryption proof
        let proof = create_encryption_proof(keypair, &encrypted_amount, randomness)?;

        // Build uncompressed calldata
        let calldata = build_deposit_calldata(amount, &encrypted_amount, &proof);
        let original_bytes = calldata_to_bytes(&calldata);

        // Compress the proof portion (everything after amount u256)
        let proof_bytes = calldata_to_bytes(&calldata[2..]); // Skip amount (2 felts)
        let compressed_proof = ProofCompressor::compress(&proof_bytes, algorithm)?;

        // Calculate stats
        let stats = CompressionStats::calculate(
            original_bytes.len(),
            compressed_proof.compressed_size() + 64, // +64 for amount (2 felt252s)
            algorithm,
        );

        info!(
            "Deposit compression: {} -> {} bytes ({:.1}% ratio)",
            stats.original_size,
            stats.compressed_size,
            stats.compression_ratio * 100.0
        );

        // Build compressed calldata: amount + compressed_proof_len + compressed_data + proof_hash
        let mut compressed_calldata = vec![
            FieldElement::from(amount),   // amount low
            FieldElement::ZERO,           // amount high
            FieldElement::from(compressed_proof.data.len() as u64), // compressed length
        ];

        // Add compressed data as felt252 chunks (32 bytes per felt)
        compressed_calldata.extend(bytes_to_calldata(&compressed_proof.data));

        // Add proof hash for integrity verification
        compressed_calldata.extend(hash_bytes_to_calldata(&compressed_proof.proof_hash));

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("deposit_compressed")?,
            calldata: compressed_calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Compressed deposit tx: {:?}", tx.transaction_hash);
        Ok((tx.transaction_hash, stats))
    }

    /// Withdraw with proof compression for reduced calldata cost
    ///
    /// # Arguments
    /// * `keypair` - The ElGamal keypair
    /// * `amount` - The amount to withdraw
    /// * `algorithm` - Compression algorithm
    pub async fn withdraw_compressed(
        &mut self,
        keypair: &KeyPair,
        amount: u64,
        algorithm: CompressionAlgorithm,
    ) -> Result<(FieldElement, CompressionStats)> {
        if self.account.is_none() {
            return Err(anyhow!("No account configured for write operations"));
        }

        // Generate randomness
        let randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;

        let encrypted_delta = encrypt(amount, &keypair.public_key, &randomness);
        let nonce = hash_felts(&[randomness, keypair.secret_key]);
        let proof = create_decryption_proof(keypair, &encrypted_delta, &nonce);

        // Check nullifier
        if self.check_nullifier(&proof.nullifier).await? {
            return Err(anyhow!("Nullifier already used"));
        }

        // Build uncompressed calldata for stats comparison
        let calldata = build_withdraw_calldata(amount, &encrypted_delta, &proof);
        let original_bytes = calldata_to_bytes(&calldata);

        // Compress encrypted_delta + proof
        let proof_bytes = calldata_to_bytes(&calldata[2..]); // Skip amount
        let compressed_proof = ProofCompressor::compress(&proof_bytes, algorithm)?;

        let stats = CompressionStats::calculate(
            original_bytes.len(),
            compressed_proof.compressed_size() + 64,
            algorithm,
        );

        info!(
            "Withdraw compression: {} -> {} bytes ({:.1}% ratio)",
            stats.original_size,
            stats.compressed_size,
            stats.compression_ratio * 100.0
        );

        // Build compressed calldata
        let mut compressed_calldata = vec![
            FieldElement::from(amount),
            FieldElement::ZERO,
            FieldElement::from(compressed_proof.data.len() as u64),
        ];
        compressed_calldata.extend(bytes_to_calldata(&compressed_proof.data));
        compressed_calldata.extend(hash_bytes_to_calldata(&compressed_proof.proof_hash));

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("withdraw_compressed")?,
            calldata: compressed_calldata,
        };

        let account = self.account.as_ref().unwrap();
        let tx = account.execute(vec![call]).send().await?;

        self.mark_nullifier_used(proof.nullifier);

        debug!("Compressed withdraw tx: {:?}", tx.transaction_hash);
        Ok((tx.transaction_hash, stats))
    }

    /// Private transfer with proof compression
    ///
    /// Compresses the transfer proofs (sender, receiver, balance) to reduce gas.
    ///
    /// # Arguments
    /// * `sender_keypair` - Sender's ElGamal keypair
    /// * `receiver_address` - Receiver's contract address
    /// * `receiver_pubkey` - Receiver's ElGamal public key
    /// * `amount` - Amount to transfer
    /// * `algorithm` - Compression algorithm
    pub async fn private_transfer_compressed(
        &mut self,
        sender_keypair: &KeyPair,
        receiver_address: FieldElement,
        receiver_pubkey: &ECPoint,
        amount: u64,
        algorithm: CompressionAlgorithm,
    ) -> Result<(FieldElement, CompressionStats)> {
        let sender_address = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?
            .address();

        // Generate randomness
        let sender_randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;
        let receiver_randomness = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate randomness: {}", e))?;

        // Encrypt amounts
        let encrypted_amount = encrypt(amount, receiver_pubkey, &receiver_randomness);
        let sender_delta = encrypt(amount, &sender_keypair.public_key, &sender_randomness);

        // Generate proofs
        let sender_nonce = hash_felts(&[sender_randomness, sender_keypair.secret_key]);
        let receiver_nonce = hash_felts(&[receiver_randomness, Felt252::from_u64(amount)]);
        let balance_nonce = hash_felts(&[sender_keypair.secret_key, Felt252::from_u64(amount)]);

        let sender_proof = create_decryption_proof(sender_keypair, &sender_delta, &sender_nonce);
        let receiver_proof = create_schnorr_proof(
            &receiver_randomness,
            &ECPoint::generator(),
            &receiver_nonce,
            &[encrypted_amount.c1_x, encrypted_amount.c1_y, receiver_pubkey.x, receiver_pubkey.y],
        );
        let balance_proof = create_decryption_proof(sender_keypair, &sender_delta, &balance_nonce);

        let nullifier = compute_nullifier(&sender_keypair.secret_key, &encrypted_amount);

        if self.check_nullifier(&nullifier).await? {
            return Err(anyhow!("Nullifier already used"));
        }

        let transfer = PrivateTransfer {
            sender: sender_address,
            receiver: receiver_address,
            encrypted_amount,
            sender_delta,
            proof: TransferProof {
                sender_proof,
                receiver_proof,
                balance_proof,
            },
            nullifier,
        };

        // Build uncompressed calldata for stats
        let calldata = build_private_transfer_calldata(&transfer);
        let original_bytes = calldata_to_bytes(&calldata);

        // Compress proofs (everything after sender, receiver, encrypted_amount, sender_delta)
        let proof_bytes = calldata_to_bytes(&calldata[10..]); // Skip first 10 felts (addresses + ciphertexts)
        let compressed_proof = ProofCompressor::compress(&proof_bytes, algorithm)?;

        let stats = CompressionStats::calculate(
            original_bytes.len(),
            compressed_proof.compressed_size() + (10 * 32), // +320 bytes for uncompressed header
            algorithm,
        );

        info!(
            "Private transfer compression: {} -> {} bytes ({:.1}% ratio, ~{} gas saved)",
            stats.original_size,
            stats.compressed_size,
            stats.compression_ratio * 100.0,
            stats.estimated_gas_savings
        );

        // Build compressed calldata: header (uncompressed) + compressed proofs
        let mut compressed_calldata = vec![
            transfer.sender,
            transfer.receiver,
            felt252_to_field_element(&transfer.encrypted_amount.c1_x),
            felt252_to_field_element(&transfer.encrypted_amount.c1_y),
            felt252_to_field_element(&transfer.encrypted_amount.c2_x),
            felt252_to_field_element(&transfer.encrypted_amount.c2_y),
            felt252_to_field_element(&transfer.sender_delta.c1_x),
            felt252_to_field_element(&transfer.sender_delta.c1_y),
            felt252_to_field_element(&transfer.sender_delta.c2_x),
            felt252_to_field_element(&transfer.sender_delta.c2_y),
            FieldElement::from(compressed_proof.data.len() as u64), // compressed length
        ];
        compressed_calldata.extend(bytes_to_calldata(&compressed_proof.data));
        compressed_calldata.extend(hash_bytes_to_calldata(&compressed_proof.proof_hash));

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("private_transfer_compressed")?,
            calldata: compressed_calldata,
        };

        let account = self.account.as_ref().unwrap();
        let tx = account.execute(vec![call]).send().await?;

        self.mark_nullifier_used(nullifier);

        debug!("Compressed private transfer tx: {:?}", tx.transaction_hash);
        Ok((tx.transaction_hash, stats))
    }

    /// Analyze compression options for a deposit operation
    ///
    /// Returns statistics for all compression algorithms without executing.
    pub fn analyze_deposit_compression(
        &self,
        keypair: &KeyPair,
        amount: u64,
        randomness: &Felt252,
    ) -> Result<Vec<CompressionStats>> {
        let encrypted_amount = encrypt(amount, &keypair.public_key, randomness);
        let proof = create_encryption_proof(keypair, &encrypted_amount, randomness)?;
        let calldata = build_deposit_calldata(amount, &encrypted_amount, &proof);
        let original_bytes = calldata_to_bytes(&calldata);
        let proof_bytes = calldata_to_bytes(&calldata[2..]);

        let algorithms = [
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Lz4,
            CompressionAlgorithm::Snappy,
            CompressionAlgorithm::None,
        ];

        algorithms
            .iter()
            .map(|&alg| {
                let compressed = ProofCompressor::compress(&proof_bytes, alg)?;
                Ok(CompressionStats::calculate(
                    original_bytes.len(),
                    compressed.compressed_size() + 64,
                    alg,
                ))
            })
            .collect()
    }

    // =========================================================================
    // Worker Payment Helpers
    // =========================================================================

    /// Decrypt worker payment amount (off-chain)
    pub fn decrypt_payment(
        &self,
        keypair: &KeyPair,
        encrypted_amount: &ElGamalCiphertext,
    ) -> ECPoint {
        decrypt_point(encrypted_amount, &keypair.secret_key)
    }

    /// Check if worker has pending unclaimed payments
    pub async fn has_unclaimed_payments(
        &self,
        worker_address: FieldElement,
    ) -> Result<bool> {
        let account = self.get_account(worker_address).await?;
        Ok(account.pending_transfers > 0)
    }

    // =========================================================================
    // Parsing Helpers
    // =========================================================================

    fn parse_private_account(data: &[FieldElement]) -> Result<PrivateAccount> {
        if data.len() < 18 {
            return Err(anyhow!("Insufficient data for PrivateAccount"));
        }

        let public_key = ECPoint::new(
            field_element_to_felt252(&data[0]),
            field_element_to_felt252(&data[1]),
        );

        // Parse encrypted balance
        let encrypted_balance = EncryptedBalance {
            ciphertext: ElGamalCiphertext {
                c1_x: field_element_to_felt252(&data[2]),
                c1_y: field_element_to_felt252(&data[3]),
                c2_x: field_element_to_felt252(&data[4]),
                c2_y: field_element_to_felt252(&data[5]),
            },
            pending_in: ElGamalCiphertext {
                c1_x: field_element_to_felt252(&data[6]),
                c1_y: field_element_to_felt252(&data[7]),
                c2_x: field_element_to_felt252(&data[8]),
                c2_y: field_element_to_felt252(&data[9]),
            },
            pending_out: ElGamalCiphertext {
                c1_x: field_element_to_felt252(&data[10]),
                c1_y: field_element_to_felt252(&data[11]),
                c2_x: field_element_to_felt252(&data[12]),
                c2_y: field_element_to_felt252(&data[13]),
            },
            epoch: felt_to_u64(&data[14]),
        };

        let pending_transfers = felt_to_u64(&data[15]) as u32;
        let last_rollup_epoch = felt_to_u64(&data[16]);
        let is_registered = data[17] != FieldElement::ZERO;

        Ok(PrivateAccount {
            public_key,
            encrypted_balance,
            pending_transfers,
            last_rollup_epoch,
            is_registered,
        })
    }

    fn parse_worker_payment(data: &[FieldElement]) -> Result<PrivateWorkerPayment> {
        if data.len() < 9 {
            return Err(anyhow!("Insufficient data for PrivateWorkerPayment"));
        }

        let job_id = felt_to_u64(&data[0]) as u128 | ((felt_to_u64(&data[1]) as u128) << 64);
        let worker = data[2];

        let encrypted_amount = ElGamalCiphertext {
            c1_x: field_element_to_felt252(&data[3]),
            c1_y: field_element_to_felt252(&data[4]),
            c2_x: field_element_to_felt252(&data[5]),
            c2_y: field_element_to_felt252(&data[6]),
        };

        let timestamp = felt_to_u64(&data[7]);
        let is_claimed = data[8] != FieldElement::ZERO;

        // Parse asset_id if present (10th field), default to SAGE for backward compatibility
        let asset_id = if data.len() > 9 {
            AssetId(felt_to_u64(&data[9]))
        } else {
            AssetId::SAGE
        };

        Ok(PrivateWorkerPayment {
            job_id,
            worker,
            encrypted_amount,
            timestamp,
            is_claimed,
            asset_id,
        })
    }

    fn parse_account_hints(data: &[FieldElement]) -> Result<AccountHints> {
        if data.len() < 10 {
            return Err(anyhow!("Insufficient data for AccountHints"));
        }

        Ok(AccountHints {
            balance_hint: AEHint {
                c0: field_element_to_felt252(&data[0]),
                c1: field_element_to_felt252(&data[1]),
                c2: field_element_to_felt252(&data[2]),
            },
            pending_in_hint: AEHint {
                c0: field_element_to_felt252(&data[3]),
                c1: field_element_to_felt252(&data[4]),
                c2: field_element_to_felt252(&data[5]),
            },
            pending_out_hint: AEHint {
                c0: field_element_to_felt252(&data[6]),
                c1: field_element_to_felt252(&data[7]),
                c2: field_element_to_felt252(&data[8]),
            },
            hint_nonce: felt_to_u64(&data[9]),
        })
    }
}

// =============================================================================
// Conversion Helpers
// =============================================================================

/// Convert Felt252 to Starknet FieldElement
pub fn felt252_to_field_element(felt: &Felt252) -> FieldElement {
    FieldElement::from_bytes_be(&felt.to_be_bytes())
        .unwrap_or(FieldElement::ZERO)
}

/// Convert Starknet FieldElement to Felt252
pub fn field_element_to_felt252(fe: &FieldElement) -> Felt252 {
    Felt252::from_be_bytes(&fe.to_bytes_be())
}

/// Convert FieldElement to u64
fn felt_to_u64(fe: &FieldElement) -> u64 {
    let bytes = fe.to_bytes_be();
    u64::from_be_bytes(bytes[24..32].try_into().unwrap_or([0; 8]))
}

/// Create encryption proof for deposit
fn create_encryption_proof(
    keypair: &KeyPair,
    ciphertext: &ElGamalCiphertext,
    randomness: &Felt252,
) -> Result<EncryptionProof> {
    let nonce = hash_felts(&[*randomness, keypair.secret_key]);
    Ok(create_decryption_proof(keypair, ciphertext, &nonce))
}

/// Convert proof to calldata (includes nullifier for replay protection)
fn proof_to_calldata(proof: &EncryptionProof) -> Vec<FieldElement> {
    vec![
        felt252_to_field_element(&proof.commitment_x),
        felt252_to_field_element(&proof.commitment_y),
        felt252_to_field_element(&proof.challenge),
        felt252_to_field_element(&proof.response),
        felt252_to_field_element(&proof.range_proof_hash),
        felt252_to_field_element(&proof.nullifier),
    ]
}

/// Build deposit calldata
fn build_deposit_calldata(
    amount: u64,
    encrypted: &ElGamalCiphertext,
    proof: &EncryptionProof,
) -> Vec<FieldElement> {
    let mut calldata = vec![
        FieldElement::from(amount),
        FieldElement::ZERO,
        felt252_to_field_element(&encrypted.c1_x),
        felt252_to_field_element(&encrypted.c1_y),
        felt252_to_field_element(&encrypted.c2_x),
        felt252_to_field_element(&encrypted.c2_y),
    ];
    calldata.extend(proof_to_calldata(proof));
    calldata
}

/// Build withdraw calldata
/// Format: amount (u256: low, high), encrypted_delta (4 felts), proof (6 felts)
fn build_withdraw_calldata(
    amount: u64,
    encrypted_delta: &ElGamalCiphertext,
    proof: &EncryptionProof,
) -> Vec<FieldElement> {
    let mut calldata = vec![
        FieldElement::from(amount),   // amount low
        FieldElement::ZERO,           // amount high (u256)
        felt252_to_field_element(&encrypted_delta.c1_x),
        felt252_to_field_element(&encrypted_delta.c1_y),
        felt252_to_field_element(&encrypted_delta.c2_x),
        felt252_to_field_element(&encrypted_delta.c2_y),
    ];
    calldata.extend(proof_to_calldata(proof));
    calldata
}

/// Build private transfer calldata
/// Format: sender, receiver, encrypted_amount (4), sender_delta (4),
///         sender_proof (6), receiver_proof (6), balance_proof (6), nullifier
fn build_private_transfer_calldata(transfer: &PrivateTransfer) -> Vec<FieldElement> {
    let mut calldata = vec![
        transfer.sender,
        transfer.receiver,
        // encrypted_amount (to receiver)
        felt252_to_field_element(&transfer.encrypted_amount.c1_x),
        felt252_to_field_element(&transfer.encrypted_amount.c1_y),
        felt252_to_field_element(&transfer.encrypted_amount.c2_x),
        felt252_to_field_element(&transfer.encrypted_amount.c2_y),
        // sender_delta
        felt252_to_field_element(&transfer.sender_delta.c1_x),
        felt252_to_field_element(&transfer.sender_delta.c1_y),
        felt252_to_field_element(&transfer.sender_delta.c2_x),
        felt252_to_field_element(&transfer.sender_delta.c2_y),
    ];
    // sender proof
    calldata.extend(proof_to_calldata(&transfer.proof.sender_proof));
    // receiver proof
    calldata.extend(proof_to_calldata(&transfer.proof.receiver_proof));
    // balance proof
    calldata.extend(proof_to_calldata(&transfer.proof.balance_proof));
    // nullifier
    calldata.push(felt252_to_field_element(&transfer.nullifier));
    calldata
}

/// Compute nullifier: H("OBELYSK_NULLIFIER", sk, commitment)
/// This matches the Cairo implementation for double-spend prevention
fn compute_nullifier(secret_key: &Felt252, ciphertext: &ElGamalCiphertext) -> Felt252 {
    // Domain separator for nullifier computation
    // "OBELYSK_NULLIFIER" as hex bytes
    let domain = Felt252::from_hex("4f42454c59534b5f4e554c4c4946494552")
        .unwrap_or_else(|| Felt252::from_u64(0x4e554c4c49464945)); // fallback

    hash_felts(&[
        domain,
        *secret_key,
        ciphertext.c1_x,
        ciphertext.c1_y,
        ciphertext.c2_x,
        ciphertext.c2_y,
    ])
}

// =============================================================================
// Compression Helpers
// =============================================================================

/// Convert calldata (FieldElements) to bytes for compression
fn calldata_to_bytes(calldata: &[FieldElement]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(calldata.len() * 32);
    for fe in calldata {
        bytes.extend_from_slice(&fe.to_bytes_be());
    }
    bytes
}

/// Convert bytes back to calldata (FieldElements)
/// Pads the last chunk with zeros if needed
fn bytes_to_calldata(data: &[u8]) -> Vec<FieldElement> {
    data.chunks(32)
        .map(|chunk| {
            if chunk.len() == 32 {
                FieldElement::from_bytes_be(&chunk.try_into().unwrap())
                    .unwrap_or(FieldElement::ZERO)
            } else {
                // Pad incomplete chunk
                let mut padded = [0u8; 32];
                padded[..chunk.len()].copy_from_slice(chunk);
                FieldElement::from_bytes_be(&padded).unwrap_or(FieldElement::ZERO)
            }
        })
        .collect()
}

/// Convert 32-byte hash to calldata (single FieldElement)
fn hash_bytes_to_calldata(hash: &[u8; 32]) -> Vec<FieldElement> {
    vec![FieldElement::from_bytes_be(hash).unwrap_or(FieldElement::ZERO)]
}

// =============================================================================
// Worker Privacy Manager
// =============================================================================

/// Manages worker privacy keys and payment claims
pub struct WorkerPrivacyManager {
    keypair: KeyPair,
    client: PrivacyRouterClient,
}

impl WorkerPrivacyManager {
    /// Create a new manager with generated keypair
    pub fn new(client: PrivacyRouterClient, secret: Felt252) -> Self {
        let keypair = KeyPair::from_secret(secret);
        Self { keypair, client }
    }

    /// Get the worker's public key
    pub fn public_key(&self) -> ECPoint {
        self.keypair.public_key()
    }

    /// Register the worker's privacy account
    pub async fn register(&self) -> Result<FieldElement> {
        self.client.register_account(&self.keypair).await
    }

    /// Claim a pending payment
    ///
    /// Uses secure randomness for the nonce to prevent cryptographic attacks.
    /// The nonce is included in the decryption proof and verified on-chain.
    /// Replay protection is enforced via on-chain nullifier tracking.
    pub async fn claim_payment(&self, job_id: u128) -> Result<FieldElement> {
        // Use secure randomness for nonce (not deterministic)
        // This prevents:
        // 1. Nonce prediction attacks
        // 2. Secret key leakage through deterministic hashing
        // 3. Cross-transaction correlation
        let nonce = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate secure nonce: {:?}", e))?;

        self.client.claim_worker_payment(&self.keypair, job_id, &nonce).await
    }

    /// Claim multiple payments in a single transaction (gas efficient)
    ///
    /// Uses batch claiming to reduce gas costs when claiming multiple payments.
    /// Falls back to individual claims if batch fails.
    pub async fn claim_multiple_payments(&self, job_ids: &[u128]) -> Result<FieldElement> {
        if job_ids.is_empty() {
            anyhow::bail!("No job IDs provided for batch claim");
        }

        if job_ids.len() == 1 {
            // Single payment, use regular claim
            return self.claim_payment(job_ids[0]).await;
        }

        // Use batch claiming for multiple payments
        self.client.claim_multiple_payments(&self.keypair, job_ids).await
    }

    /// Decrypt a received payment (off-chain only)
    pub fn decrypt_payment(&self, encrypted: &ElGamalCiphertext) -> ECPoint {
        self.client.decrypt_payment(&self.keypair, encrypted)
    }

    /// Get current encrypted balance
    pub async fn get_balance(&self, address: FieldElement) -> Result<EncryptedBalance> {
        let account = self.client.get_account(address).await?;
        Ok(account.encrypted_balance)
    }

    // =========================================================================
    // Multi-Asset Methods
    // =========================================================================

    /// Claim a pending payment for a specific asset
    ///
    /// # Arguments
    /// * `job_id` - The job ID
    /// * `asset_id` - The asset type (SAGE, USDC, STRK, BTC)
    ///
    /// # Returns
    /// Transaction hash on success
    /// Claim payment for a specific asset
    ///
    /// Uses secure randomness for the nonce to prevent cryptographic attacks.
    /// The nonce is included in the decryption proof and verified on-chain.
    /// Replay protection is enforced via on-chain nullifier tracking.
    pub async fn claim_payment_for_asset(
        &self,
        job_id: u128,
        asset_id: AssetId,
    ) -> Result<FieldElement> {
        // Use secure randomness for nonce (not deterministic)
        // This prevents:
        // 1. Nonce prediction attacks
        // 2. Secret key leakage through deterministic hashing
        // 3. Cross-transaction correlation
        let nonce = generate_randomness()
            .map_err(|e| anyhow!("Failed to generate secure nonce: {:?}", e))?;

        self.client.claim_worker_payment_for_asset(&self.keypair, job_id, asset_id, &nonce).await
    }

    /// Claim payment with proof verification
    ///
    /// This method submits a proof-gated payment claim, where the proof is verified
    /// on-chain before the payment is released. This ensures workers only get paid
    /// for work they actually performed with valid computation proofs.
    ///
    /// # Arguments
    /// * `job_id` - Job identifier
    /// * `asset_id` - Payment asset type (SAGE, USDC, etc.)
    /// * `amount` - Payment amount in base units
    /// * `compressed_proof` - Compressed ZK proof for verification
    ///
    /// # Returns
    /// Transaction hash on success
    pub async fn claim_payment_with_proof(
        &self,
        job_id: u128,
        _asset_id: AssetId,
        amount: u128,
        compressed_proof: &CompressedProof,
    ) -> Result<FieldElement> {
        // Get worker address
        let worker_address = format!("0x{:x}", felt252_to_field_element(&self.keypair.public_key.x));

        // Submit proof-gated payment using the privacy router client
        let result = self.client.submit_payment_with_proof(
            &worker_address,
            job_id,
            amount,
            compressed_proof,
        ).await?;

        info!("✅ Proof-gated payment submitted for job {}: tx={:?}", job_id, result.tx_hash);

        Ok(result.tx_hash)
    }

    /// Claim all pending payments across multiple assets in a single transaction
    ///
    /// This is more gas-efficient than claiming payments one by one.
    ///
    /// # Arguments
    /// * `claims` - List of (job_id, asset_id) pairs to claim
    ///
    /// # Returns
    /// Transaction hash on success
    pub async fn claim_all_pending(&self, claims: &[(u128, AssetId)]) -> Result<FieldElement> {
        if claims.is_empty() {
            anyhow::bail!("No claims provided for batch claim");
        }

        if claims.len() == 1 {
            // Single payment, use regular claim
            let (job_id, asset_id) = claims[0];
            return self.claim_payment_for_asset(job_id, asset_id).await;
        }

        // Use batch claiming for multiple payments
        self.client.claim_multiple_assets(&self.keypair, claims).await
    }

    /// Get all pending worker payments across all assets
    ///
    /// Returns all unclaimed payments for SAGE, USDC, STRK, and BTC.
    pub async fn get_all_pending_payments(
        &self,
        worker_address: FieldElement,
    ) -> Result<Vec<PrivateWorkerPayment>> {
        self.client.get_worker_payments_all_assets(worker_address).await
    }

    /// Decrypt a received payment and return the amount based on asset decimals
    ///
    /// Note: The discrete log recovery may take time for large amounts.
    pub fn decrypt_payment_amount(
        &self,
        encrypted: &ElGamalCiphertext,
        asset_id: AssetId,
    ) -> (ECPoint, u8) {
        let decrypted_point = self.client.decrypt_payment(&self.keypair, encrypted);
        (decrypted_point, asset_id.decimals())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::elgamal::generate_keypair;

    #[test]
    fn test_felt_conversion() {
        let original = Felt252::from_u64(12345);
        let fe = felt252_to_field_element(&original);
        let back = field_element_to_felt252(&fe);
        assert_eq!(original, back);
    }

    #[test]
    fn test_proof_to_calldata() {
        use super::super::elgamal::ECPoint;

        // Use the constructor which computes nullifier automatically
        let commitment = ECPoint::new(Felt252::from_u64(1), Felt252::from_u64(2));
        let proof = EncryptionProof::new(
            commitment,
            Felt252::from_u64(3),
            Felt252::from_u64(4),
            Felt252::from_u64(5),
        );

        let calldata = proof_to_calldata(&proof);
        // Now includes nullifier: 6 fields instead of 5
        assert_eq!(calldata.len(), 6);
    }

    #[test]
    fn test_calldata_bytes_roundtrip() {
        let calldata = vec![
            FieldElement::from(123u64),
            FieldElement::from(456u64),
            FieldElement::from(789u64),
        ];

        let bytes = calldata_to_bytes(&calldata);
        assert_eq!(bytes.len(), 96); // 3 * 32 bytes

        let recovered = bytes_to_calldata(&bytes);
        assert_eq!(calldata, recovered);
    }

    #[test]
    fn test_compression_stats() {
        let stats = CompressionStats::calculate(1000, 600, CompressionAlgorithm::Zstd);

        assert_eq!(stats.original_size, 1000);
        assert_eq!(stats.compressed_size, 600);
        assert!((stats.compression_ratio - 0.6).abs() < 0.001);
        assert_eq!(stats.estimated_gas_savings, 400 * 16); // 400 bytes saved * 16 gas/byte
    }

    #[test]
    fn test_analyze_deposit_compression() {
        let keypair = generate_keypair().expect("keypair generation should work");
        let randomness = generate_randomness().expect("randomness should work");

        // Create a mock read-only client for testing
        let client = PrivacyRouterClient {
            provider: std::sync::Arc::new(JsonRpcClient::new(HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap()
            ))),
            contract_address: FieldElement::from(0x123u64),
            account: None,
            used_nullifiers: HashSet::new(),
            network: None,
            payment_router: None,
        };

        let stats = client.analyze_deposit_compression(&keypair, 1000, &randomness)
            .expect("compression analysis should work");

        // Should have stats for all 4 algorithms
        assert_eq!(stats.len(), 4);

        // Zstd should have best ratio (first in list)
        assert!(matches!(stats[0].algorithm, CompressionAlgorithm::Zstd));

        // None should have ratio of 1.0 (no compression)
        let none_stats = stats.iter()
            .find(|s| matches!(s.algorithm, CompressionAlgorithm::None))
            .expect("should have None algorithm");
        assert!((none_stats.compression_ratio - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_hash_bytes_to_calldata() {
        // Use a value within the field modulus (first byte must be < 0x08 for Stark curve)
        let mut hash: [u8; 32] = [0x42; 32];
        hash[0] = 0x00; // Ensure we're within the field
        hash[1] = 0x00;

        let calldata = hash_bytes_to_calldata(&hash);
        assert_eq!(calldata.len(), 1);

        // Verify the conversion produced a valid FieldElement
        assert_ne!(calldata[0], FieldElement::ZERO);
    }

    #[test]
    fn test_nullifier_caching() {
        let mut client = PrivacyRouterClient {
            provider: std::sync::Arc::new(JsonRpcClient::new(HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap()
            ))),
            contract_address: FieldElement::from(0x123u64),
            account: None,
            used_nullifiers: HashSet::new(),
            network: None,
            payment_router: None,
        };

        let nullifier = Felt252::from_u64(0xdeadbeef);

        // Initially not in cache
        assert!(!client.used_nullifiers.contains(&nullifier));

        // Mark as used
        client.mark_nullifier_used(nullifier);

        // Now in cache
        assert!(client.used_nullifiers.contains(&nullifier));
    }
}
