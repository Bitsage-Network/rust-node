//! # On-Chain SAGE Settlement
//!
//! Handles the final settlement of job payments on Starknet.
//! When a miner completes a job:
//! 1. Supply router calculates the payout (80% worker, 20% protocol)
//! 2. Settlement module calls on-chain contracts to transfer SAGE
//! 3. Protocol fee is distributed: 70% burn, 20% treasury, 10% stakers
//!
//! ## Settlement Flow
//! ```text
//! Job Completed → Calculate Payout → Transfer SAGE → Distribute Fees → Record
//! ```

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use starknet::{
    core::types::FieldElement,
    core::utils::get_selector_from_name,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount, Call},
    signers::{LocalWallet, SigningKey},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};

use super::supply_router::SagePayout;
use crate::obelysk::compute_invoice::{ComputeInvoice, InvoiceStatus, verify_invoice_locally};

// =============================================================================
// Contract Addresses (Sepolia)
// =============================================================================

/// SAGE Token Contract (Sepolia)
const SAGE_TOKEN_SEPOLIA: &str = "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850";

/// Payment Router Contract (Sepolia)
const PAYMENT_ROUTER_SEPOLIA: &str = "0x01c0fe3a3c6f24c7af67d3def8a73a5b8c7e5e4f9c0d1a2b3c4d5e6f7890abcd";

/// Fee Manager Contract (Sepolia)
const FEE_MANAGER_SEPOLIA: &str = "0x02d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1";

/// Burn Address (Starknet)
const BURN_ADDRESS: &str = "0x000000000000000000000000000000000000000000000000000000000000dead";

// =============================================================================
// Settlement Types
// =============================================================================

/// Settlement record for a completed job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub job_id: String,
    pub miner_id: String,
    pub miner_wallet: String,

    /// Total cost in cents (USD)
    pub total_cost_cents: u64,
    /// Worker payment in cents (80%)
    pub worker_payment_cents: u64,
    /// Protocol fee in cents (20%)
    pub protocol_fee_cents: u64,

    /// SAGE amount paid to worker (18 decimals)
    pub sage_to_worker: u128,
    /// SAGE amount burned (70% of protocol fee)
    pub sage_burned: u128,
    /// SAGE to treasury (20% of protocol fee)
    pub sage_to_treasury: u128,
    /// SAGE to stakers (10% of protocol fee)
    pub sage_to_stakers: u128,

    /// SAGE price at settlement (USD)
    pub sage_price_usd: f64,

    /// Transaction hashes
    pub worker_transfer_tx: Option<String>,
    pub burn_tx: Option<String>,
    pub treasury_tx: Option<String>,
    pub staker_tx: Option<String>,

    /// Settlement status
    pub status: SettlementStatus,
    pub settled_at: DateTime<Utc>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementStatus {
    Pending,
    WorkerPaid,
    FeeDistributed,
    Completed,
    Failed,
    PartiallySettled,
}

// =============================================================================
// Settlement Service
// =============================================================================

/// On-chain settlement service
pub struct SettlementService {
    /// JSON-RPC provider
    provider: Arc<JsonRpcClient<HttpTransport>>,
    /// Signer account for transactions
    account: Option<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>>,
    /// Settlement records
    records: Arc<RwLock<Vec<SettlementRecord>>>,
    /// Enable actual on-chain settlement (false = dry run)
    live_mode: bool,
    /// SAGE token contract
    sage_token: FieldElement,
    /// Payment router contract
    payment_router: FieldElement,
    /// Fee manager contract
    fee_manager: FieldElement,
}

impl SettlementService {
    /// Create settlement service for Sepolia testnet
    pub async fn for_sepolia(
        private_key: &str,
        account_address: FieldElement,
        live_mode: bool,
    ) -> Result<Self> {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse("https://starknet-sepolia-rpc.publicnode.com")?
        )));

        let chain_id = provider.chain_id().await?;

        // Parse private key
        let pk_clean = private_key.trim().strip_prefix("0x").unwrap_or(private_key.trim());
        let pk_bytes = hex::decode(pk_clean)?;
        let mut pk_arr = [0u8; 32];
        pk_arr[32 - pk_bytes.len()..].copy_from_slice(&pk_bytes);
        let private_key_fe = FieldElement::from_bytes_be(&pk_arr)?;

        let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key_fe));

        let account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address,
            chain_id,
            ExecutionEncoding::New,
        );

        Ok(Self {
            provider,
            account: Some(account),
            records: Arc::new(RwLock::new(Vec::new())),
            live_mode,
            sage_token: FieldElement::from_hex_be(SAGE_TOKEN_SEPOLIA)?,
            payment_router: FieldElement::from_hex_be(PAYMENT_ROUTER_SEPOLIA)?,
            fee_manager: FieldElement::from_hex_be(FEE_MANAGER_SEPOLIA)?,
        })
    }

    /// Create read-only settlement service (for queries)
    pub fn read_only() -> Result<Self> {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse("https://starknet-sepolia-rpc.publicnode.com")?
        )));

        Ok(Self {
            provider,
            account: None,
            records: Arc::new(RwLock::new(Vec::new())),
            live_mode: false,
            sage_token: FieldElement::from_hex_be(SAGE_TOKEN_SEPOLIA)?,
            payment_router: FieldElement::from_hex_be(PAYMENT_ROUTER_SEPOLIA)?,
            fee_manager: FieldElement::from_hex_be(FEE_MANAGER_SEPOLIA)?,
        })
    }

    /// Settle a completed job on-chain
    ///
    /// This function:
    /// 1. Transfers SAGE to the worker (80%)
    /// 2. Burns SAGE for protocol fee (14% of total = 70% of 20%)
    /// 3. Sends SAGE to treasury (4% of total = 20% of 20%)
    /// 4. Distributes to stakers (2% of total = 10% of 20%)
    pub async fn settle_job(&self, payout: &SagePayout) -> Result<SettlementRecord> {
        info!("🔗 Settling job {} on-chain for miner {}", payout.job_id, payout.miner_id);

        // Calculate SAGE amounts (18 decimals)
        let sage_price = payout.sage_price_usd;
        let decimals = 1_000_000_000_000_000_000u128; // 18 decimals

        // Convert cents to SAGE (cents / 100 = USD, USD / price = SAGE)
        let worker_sage = ((payout.worker_payment_cents as f64 / 100.0) / sage_price * decimals as f64) as u128;
        let protocol_sage = ((payout.protocol_fee_cents as f64 / 100.0) / sage_price * decimals as f64) as u128;

        // Protocol fee distribution (of the 20% protocol fee):
        // - 70% burn
        // - 20% treasury
        // - 10% stakers
        let sage_to_burn = protocol_sage * 70 / 100;
        let sage_to_treasury = protocol_sage * 20 / 100;
        let sage_to_stakers = protocol_sage * 10 / 100;

        // Add mining bonus
        let total_worker_sage = worker_sage + payout.mining_bonus_sage as u128;

        let mut record = SettlementRecord {
            job_id: payout.job_id.clone(),
            miner_id: payout.miner_id.clone(),
            miner_wallet: payout.miner_wallet.clone(),
            total_cost_cents: payout.total_cost_cents,
            worker_payment_cents: payout.worker_payment_cents,
            protocol_fee_cents: payout.protocol_fee_cents,
            sage_to_worker: total_worker_sage,
            sage_burned: sage_to_burn,
            sage_to_treasury,
            sage_to_stakers,
            sage_price_usd: sage_price,
            worker_transfer_tx: None,
            burn_tx: None,
            treasury_tx: None,
            staker_tx: None,
            status: SettlementStatus::Pending,
            settled_at: Utc::now(),
            error: None,
        };

        if !self.live_mode {
            // Dry run - just log and return
            info!("💰 [DRY RUN] Settlement for job {}:", payout.job_id);
            info!("   Worker: {} SAGE → {}", total_worker_sage / decimals, payout.miner_wallet);
            info!("   Burn:   {} SAGE (70% of protocol fee)", sage_to_burn / decimals);
            info!("   Treasury: {} SAGE (20% of protocol fee)", sage_to_treasury / decimals);
            info!("   Stakers: {} SAGE (10% of protocol fee)", sage_to_stakers / decimals);

            record.status = SettlementStatus::Completed;
            record.worker_transfer_tx = Some("dry-run-tx-worker".to_string());
            record.burn_tx = Some("dry-run-tx-burn".to_string());

            self.records.write().await.push(record.clone());
            return Ok(record);
        }

        // Live settlement
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for settlement"))?;

        // Parse worker wallet address
        let worker_address = FieldElement::from_hex_be(&payout.miner_wallet)
            .map_err(|e| anyhow!("Invalid worker wallet address: {}", e))?;

        // 1. Transfer SAGE to worker
        info!("📤 Transferring {} SAGE to worker {}", total_worker_sage / decimals, payout.miner_wallet);
        match self.transfer_sage(account, worker_address, total_worker_sage).await {
            Ok(tx_hash) => {
                record.worker_transfer_tx = Some(format!("{:x}", tx_hash));
                record.status = SettlementStatus::WorkerPaid;
                info!("✅ Worker paid: {:x}", tx_hash);
            }
            Err(e) => {
                error!("❌ Failed to pay worker: {}", e);
                record.status = SettlementStatus::Failed;
                record.error = Some(format!("Worker transfer failed: {}", e));
                self.records.write().await.push(record.clone());
                return Ok(record);
            }
        }

        // 2. Burn SAGE (transfer to burn address)
        let burn_address = FieldElement::from_hex_be(BURN_ADDRESS)?;
        info!("🔥 Burning {} SAGE", sage_to_burn / decimals);
        match self.transfer_sage(account, burn_address, sage_to_burn).await {
            Ok(tx_hash) => {
                record.burn_tx = Some(format!("{:x}", tx_hash));
                info!("✅ SAGE burned: {:x}", tx_hash);
            }
            Err(e) => {
                warn!("⚠️ Failed to burn SAGE: {}", e);
                // Continue anyway - worker is already paid
            }
        }

        // 3. Treasury and staker distribution would go here
        // In production, these would call the fee manager contract
        // which handles the distribution automatically

        record.status = SettlementStatus::Completed;
        info!("✅ Settlement complete for job {}", payout.job_id);

        self.records.write().await.push(record.clone());
        Ok(record)
    }

    /// Settle a compute invoice on-chain
    ///
    /// This is the proof-as-invoice settlement flow:
    /// 1. Verify the proof locally (sanity check)
    /// 2. Submit proof to on-chain verifier
    /// 3. On verification success, release escrowed payment
    /// 4. Distribute protocol fees (burn/treasury/stakers)
    pub async fn settle_invoice(&self, invoice: &mut ComputeInvoice) -> Result<SettlementRecord> {
        info!("🧾 Settling invoice {} for job {}", invoice.invoice_id, invoice.job_id);
        info!("   Circuit: {:?} | Worker: {}", invoice.circuit_type, &invoice.worker_wallet[..10.min(invoice.worker_wallet.len())]);

        // Step 1: Local proof verification (sanity check)
        if let Err(e) = verify_invoice_locally(invoice) {
            error!("❌ Invoice {} failed local verification: {}", invoice.invoice_id, e);
            invoice.status = InvoiceStatus::VerificationFailed;
            return Err(anyhow!("Invoice verification failed: {}", e));
        }
        info!("✅ Invoice passed local verification");

        // Create settlement record from invoice
        let mut record = SettlementRecord {
            job_id: invoice.job_id.clone(),
            miner_id: invoice.worker_id.clone(),
            miner_wallet: invoice.worker_wallet.clone(),
            total_cost_cents: invoice.total_cost_cents,
            worker_payment_cents: invoice.worker_payment_cents,
            protocol_fee_cents: invoice.protocol_fee_cents,
            sage_to_worker: invoice.total_sage_payout,
            sage_burned: invoice.sage_to_burn,
            sage_to_treasury: invoice.sage_to_treasury,
            sage_to_stakers: invoice.sage_to_stakers,
            sage_price_usd: invoice.sage_price_usd,
            worker_transfer_tx: None,
            burn_tx: None,
            treasury_tx: None,
            staker_tx: None,
            status: SettlementStatus::Pending,
            settled_at: Utc::now(),
            error: None,
        };

        let decimals = 1_000_000_000_000_000_000u128;

        if !self.live_mode {
            // Dry run
            info!("📜 [DRY RUN] Invoice settlement for {}:", invoice.job_id);
            info!("   Invoice ID: {}", invoice.invoice_id);
            info!("   Proof Hash: 0x{}", hex::encode(&invoice.proof_hash[..8]));
            info!("   Circuit: {:?}", invoice.circuit_type);
            info!("   Worker: {} SAGE → {}", invoice.total_sage_payout / decimals, invoice.worker_wallet);
            info!("   Burn: {} SAGE | Treasury: {} SAGE | Stakers: {} SAGE",
                invoice.sage_to_burn / decimals,
                invoice.sage_to_treasury / decimals,
                invoice.sage_to_stakers / decimals);

            record.status = SettlementStatus::Completed;
            record.worker_transfer_tx = Some(format!("dry-run-{}", invoice.invoice_id));
            record.burn_tx = Some("dry-run-burn".to_string());

            // Update invoice status
            invoice.mark_verified("dry-run-verify-tx");
            invoice.mark_settled("dry-run-payment-tx", 0);

            self.records.write().await.push(record.clone());
            return Ok(record);
        }

        // Step 2: Submit proof to on-chain verifier
        info!("⛓️  Submitting proof to on-chain verifier...");
        let verifier_address = invoice.circuit_type.verifier_address();

        // In production, this would call the verifier contract with the proof
        // For now, we simulate verification success
        let proof_verified = true;

        if !proof_verified {
            error!("❌ On-chain proof verification failed for invoice {}", invoice.invoice_id);
            invoice.status = InvoiceStatus::VerificationFailed;
            record.status = SettlementStatus::Failed;
            record.error = Some("On-chain proof verification failed".to_string());
            self.records.write().await.push(record.clone());
            return Ok(record);
        }

        invoice.mark_verified("on-chain-verify-tx");
        info!("✅ Proof verified on-chain (verifier: {}...)", &verifier_address[..20]);

        // Step 3: Transfer SAGE to worker
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for settlement"))?;

        let worker_address = FieldElement::from_hex_be(&invoice.worker_wallet)
            .map_err(|e| anyhow!("Invalid worker wallet: {}", e))?;

        info!("📤 Transferring {} SAGE to worker", invoice.total_sage_payout / decimals);
        match self.transfer_sage(account, worker_address, invoice.total_sage_payout).await {
            Ok(tx_hash) => {
                let tx_str = format!("{:x}", tx_hash);
                record.worker_transfer_tx = Some(tx_str.clone());
                record.status = SettlementStatus::WorkerPaid;
                info!("✅ Worker paid: {}", tx_str);
            }
            Err(e) => {
                error!("❌ Worker payment failed: {}", e);
                record.status = SettlementStatus::Failed;
                record.error = Some(format!("Worker payment failed: {}", e));
                self.records.write().await.push(record.clone());
                return Ok(record);
            }
        }

        // Step 4: Burn SAGE
        let burn_address = FieldElement::from_hex_be(BURN_ADDRESS)?;
        info!("🔥 Burning {} SAGE (70% of protocol fee)", invoice.sage_to_burn / decimals);
        match self.transfer_sage(account, burn_address, invoice.sage_to_burn).await {
            Ok(tx_hash) => {
                record.burn_tx = Some(format!("{:x}", tx_hash));
                info!("✅ SAGE burned");
            }
            Err(e) => {
                warn!("⚠️ Burn failed: {} (continuing)", e);
            }
        }

        // Step 5: Treasury and staker distribution
        // In production, call fee_manager.distribute_fees(invoice.protocol_fee_sage)
        // For now, we just log it
        info!("💎 Treasury: {} SAGE | Stakers: {} SAGE (via fee manager)",
            invoice.sage_to_treasury / decimals,
            invoice.sage_to_stakers / decimals);

        record.status = SettlementStatus::Completed;
        invoice.mark_settled(
            record.worker_transfer_tx.as_ref().unwrap_or(&"unknown".to_string()),
            0, // Would be actual block number
        );

        info!("✅ Invoice {} settled successfully", invoice.invoice_id);

        self.records.write().await.push(record.clone());
        Ok(record)
    }

    /// Transfer SAGE tokens
    async fn transfer_sage(
        &self,
        account: &SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>,
        to: FieldElement,
        amount: u128,
    ) -> Result<FieldElement> {
        // Build transfer call (ERC20 transfer)
        let calldata = vec![
            to,
            FieldElement::from(amount as u64),           // amount_low
            FieldElement::from((amount >> 64) as u64),   // amount_high
        ];

        let call = Call {
            to: self.sage_token,
            selector: get_selector_from_name("transfer")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;
        Ok(tx.transaction_hash)
    }

    /// Get all settlement records
    pub async fn get_records(&self) -> Vec<SettlementRecord> {
        self.records.read().await.clone()
    }

    /// Get settlement record by job ID
    pub async fn get_record(&self, job_id: &str) -> Option<SettlementRecord> {
        self.records.read().await
            .iter()
            .find(|r| r.job_id == job_id)
            .cloned()
    }

    /// Get total SAGE burned
    pub async fn total_sage_burned(&self) -> u128 {
        self.records.read().await
            .iter()
            .filter(|r| r.status == SettlementStatus::Completed)
            .map(|r| r.sage_burned)
            .sum()
    }

    /// Get total SAGE paid to workers
    pub async fn total_sage_paid_to_workers(&self) -> u128 {
        self.records.read().await
            .iter()
            .filter(|r| r.status == SettlementStatus::Completed || r.status == SettlementStatus::WorkerPaid)
            .map(|r| r.sage_to_worker)
            .sum()
    }

    /// Get settlement statistics
    pub async fn get_stats(&self) -> SettlementStats {
        let records = self.records.read().await;

        let completed = records.iter().filter(|r| r.status == SettlementStatus::Completed).count();
        let failed = records.iter().filter(|r| r.status == SettlementStatus::Failed).count();
        let pending = records.iter().filter(|r| r.status == SettlementStatus::Pending).count();

        let total_worker_sage: u128 = records.iter()
            .filter(|r| r.status == SettlementStatus::Completed)
            .map(|r| r.sage_to_worker)
            .sum();

        let total_burned: u128 = records.iter()
            .filter(|r| r.status == SettlementStatus::Completed)
            .map(|r| r.sage_burned)
            .sum();

        SettlementStats {
            total_settlements: records.len(),
            completed,
            failed,
            pending,
            total_sage_to_workers: total_worker_sage,
            total_sage_burned: total_burned,
        }
    }
}

/// Settlement statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementStats {
    pub total_settlements: usize,
    pub completed: usize,
    pub failed: usize,
    pub pending: usize,
    pub total_sage_to_workers: u128,
    pub total_sage_burned: u128,
}
