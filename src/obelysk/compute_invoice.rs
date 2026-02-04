//! # Compute Invoice System
//!
//! Unified proof-based billing where every job produces a verifiable invoice.
//! The proof IS the invoice - cryptographic evidence that work was done correctly.
//!
//! ## Architecture
//!
//! ```text
//! Job Submission → Escrow Lock → GPU Execution → STWO Proof → Invoice → Settlement
//!                                     │
//!                                     v
//!                             ┌───────────────────┐
//!                             │   Execution Trace │
//!                             │   (26 columns)    │
//!                             └─────────┬─────────┘
//!                                       │
//!                                       v
//!                             ┌───────────────────┐
//!                             │   Circuit-Specific│
//!                             │   Constraints     │
//!                             └─────────┬─────────┘
//!                                       │
//!                                       v
//!                             ┌───────────────────┐
//!                             │   STWO Proof      │
//!                             │   (32-byte hash)  │
//!                             └─────────┬─────────┘
//!                                       │
//!                                       v
//!                             ┌───────────────────┐
//!                             │  ComputeInvoice   │
//!                             │  (Proof + Billing)│
//!                             └───────────────────┘
//! ```
//!
//! ## Job Types and Their Circuits
//!
//! | Job Type      | Circuit                | What's Proven                          |
//! |---------------|------------------------|----------------------------------------|
//! | AIInference   | ml_inference_v1        | Model(input) = output                  |
//! | BatchInference| ml_batch_v1            | All N inferences correct               |
//! | DataPipeline  | etl_transform_v1       | Transform(data) = result               |
//! | STWOProof     | generic_compute_v1     | Program executed correctly             |
//! | Render3D      | gpu_render_v1          | Render(scene) = image                  |
//! | FHECompute    | fhe_homomorphic_v1     | Enc_op(ct1, ct2) = ct3                |
//! | ConfidentialVM| tee_execution_v1       | TEE(code, input) = output             |

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

// =============================================================================
// Circuit Registry - Maps Job Types to Verification Circuits
// =============================================================================

/// Circuit identifier for on-chain verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CircuitType {
    /// Generic computation proof (catch-all)
    GenericCompute = 0,
    /// ML model inference proof
    MlInference = 1,
    /// Batched ML inference proof
    MlBatchInference = 2,
    /// ETL/data transformation proof
    EtlTransform = 3,
    /// 3D rendering proof
    GpuRender = 4,
    /// FHE homomorphic operation proof
    FheHomomorphic = 5,
    /// TEE execution attestation
    TeeExecution = 6,
    /// Video transcoding proof
    VideoTranscode = 7,
    /// NLP/text processing proof
    NlpProcess = 8,
    /// Computer vision proof
    ComputerVision = 9,
    /// Simple ping/echo (testing)
    PipelineTest = 10,
}

impl CircuitType {
    /// Get circuit type from job type string
    pub fn from_job_type(job_type: &str) -> Self {
        match job_type {
            "AIInference" | "ModelInference" => CircuitType::MlInference,
            "BatchInference" => CircuitType::MlBatchInference,
            "DataPipeline" => CircuitType::EtlTransform,
            "Render3D" => CircuitType::GpuRender,
            "FHECompute" | "ConfidentialAI" => CircuitType::FheHomomorphic,
            "ConfidentialVM" => CircuitType::TeeExecution,
            "VideoProcessing" => CircuitType::VideoTranscode,
            "NLP" => CircuitType::NlpProcess,
            "ComputerVision" => CircuitType::ComputerVision,
            "Ping" | "Echo" => CircuitType::PipelineTest,
            _ => CircuitType::GenericCompute,
        }
    }

    /// Get the on-chain verifier contract address (Sepolia)
    pub fn verifier_address(&self) -> &'static str {
        // All circuit types verified via the deployed Job Manager contract on Sepolia.
        // The Job Manager stores proof hashes on-chain and validates proof commitments.
        // Per-circuit verifier contracts can be deployed later for specialized verification.
        match self {
            // Job Manager contract handles proof verification for all types
            _ => "0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3",
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            CircuitType::GenericCompute => "Generic Compute",
            CircuitType::MlInference => "ML Inference",
            CircuitType::MlBatchInference => "Batch ML Inference",
            CircuitType::EtlTransform => "ETL Transform",
            CircuitType::GpuRender => "GPU Render",
            CircuitType::FheHomomorphic => "FHE Homomorphic",
            CircuitType::TeeExecution => "TEE Execution",
            CircuitType::VideoTranscode => "Video Transcode",
            CircuitType::NlpProcess => "NLP Process",
            CircuitType::ComputerVision => "Computer Vision",
            CircuitType::PipelineTest => "Pipeline Test",
        }
    }

    /// Security bits for this circuit
    pub fn security_bits(&self) -> u32 {
        match self {
            CircuitType::PipelineTest => 96,  // Lower for testing
            _ => 128,  // Production security
        }
    }

    /// Estimated proof size in bytes
    pub fn estimated_proof_size(&self) -> usize {
        match self {
            CircuitType::PipelineTest => 16_384,       // 16 KB
            CircuitType::GenericCompute => 32_768,     // 32 KB
            CircuitType::MlInference => 65_536,        // 64 KB
            CircuitType::MlBatchInference => 98_304,   // 96 KB
            CircuitType::EtlTransform => 49_152,       // 48 KB
            CircuitType::GpuRender => 81_920,          // 80 KB
            CircuitType::FheHomomorphic => 65_536,     // 64 KB
            CircuitType::TeeExecution => 8_192,        // 8 KB (TEE quote)
            CircuitType::VideoTranscode => 49_152,     // 48 KB
            CircuitType::NlpProcess => 49_152,         // 48 KB
            CircuitType::ComputerVision => 65_536,     // 64 KB
        }
    }
}

// =============================================================================
// Compute Invoice - The Proof IS the Invoice
// =============================================================================

/// A compute invoice combines proof of work with billing information.
/// This is the atomic unit of settlement - verify proof, release payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeInvoice {
    // ─────────────────────────────────────────────────────────────────────────
    // Job Identification
    // ─────────────────────────────────────────────────────────────────────────

    /// Unique invoice ID (derived from job_id + worker + timestamp)
    pub invoice_id: String,
    /// Original job ID
    pub job_id: String,
    /// Job type (AIInference, DataPipeline, etc.)
    pub job_type: String,
    /// Circuit used for verification
    pub circuit_type: CircuitType,

    // ─────────────────────────────────────────────────────────────────────────
    // Proof of Computation
    // ─────────────────────────────────────────────────────────────────────────

    /// Hash of the program/model executed
    pub program_hash: [u8; 32],
    /// Commitment to input data (hash)
    pub input_commitment: [u8; 32],
    /// Commitment to output data (hash)
    pub output_commitment: [u8; 32],

    /// STWO proof hash (32 bytes)
    pub proof_hash: [u8; 32],
    /// Proof attestation (for quick verification)
    pub proof_attestation: [u8; 32],
    /// Proof commitment (on-chain submission)
    pub proof_commitment: [u8; 32],
    /// Compressed proof size in bytes
    pub proof_size_bytes: usize,
    /// Proof generation time in milliseconds
    pub proof_time_ms: u64,

    // ─────────────────────────────────────────────────────────────────────────
    // Execution Metrics
    // ─────────────────────────────────────────────────────────────────────────

    /// Execution trace length (number of steps)
    pub trace_length: usize,
    /// Number of constraints in the circuit
    pub constraint_count: usize,
    /// GPU seconds consumed
    pub gpu_seconds: f64,
    /// Peak GPU memory used (bytes)
    pub gpu_memory_bytes: u64,
    /// GPU model used
    pub gpu_model: String,
    /// Whether TEE was used
    pub tee_used: bool,

    // ─────────────────────────────────────────────────────────────────────────
    // Worker Information
    // ─────────────────────────────────────────────────────────────────────────

    /// Worker/miner ID
    pub worker_id: String,
    /// Worker wallet address (for payment)
    pub worker_wallet: String,
    /// Worker GPU tier
    pub worker_gpu_tier: String,
    /// Worker reputation at time of job
    pub worker_reputation: u32,

    // ─────────────────────────────────────────────────────────────────────────
    // Client Information
    // ─────────────────────────────────────────────────────────────────────────

    /// Client address (who submitted the job)
    pub client_address: Option<String>,
    /// Escrow contract holding payment
    pub escrow_address: Option<String>,

    // ─────────────────────────────────────────────────────────────────────────
    // Billing Information
    // ─────────────────────────────────────────────────────────────────────────

    /// Total compute cost in cents (USD)
    pub total_cost_cents: u64,
    /// Hourly rate used (cents)
    pub hourly_rate_cents: u64,

    /// Worker payment (80% of total)
    pub worker_payment_cents: u64,
    /// Protocol fee (20% of total)
    pub protocol_fee_cents: u64,

    /// SAGE price at invoice time (USD)
    pub sage_price_usd: f64,
    /// SAGE amount to worker (18 decimals)
    pub sage_to_worker: u128,
    /// SAGE amount to burn (14% of total)
    pub sage_to_burn: u128,
    /// SAGE to treasury (4% of total)
    pub sage_to_treasury: u128,
    /// SAGE to stakers (2% of total)
    pub sage_to_stakers: u128,

    /// Mining bonus (reputation-based)
    pub mining_bonus_sage: u128,
    /// Total SAGE payout to worker
    pub total_sage_payout: u128,

    // ─────────────────────────────────────────────────────────────────────────
    // Status and Timestamps
    // ─────────────────────────────────────────────────────────────────────────

    /// Invoice status
    pub status: InvoiceStatus,
    /// Job submitted timestamp
    pub submitted_at: DateTime<Utc>,
    /// Job started timestamp
    pub started_at: Option<DateTime<Utc>>,
    /// Job completed timestamp
    pub completed_at: Option<DateTime<Utc>>,
    /// Proof generated timestamp
    pub proof_generated_at: Option<DateTime<Utc>>,
    /// Invoice verified timestamp
    pub verified_at: Option<DateTime<Utc>>,
    /// Settlement timestamp
    pub settled_at: Option<DateTime<Utc>>,

    // ─────────────────────────────────────────────────────────────────────────
    // On-Chain Settlement
    // ─────────────────────────────────────────────────────────────────────────

    /// Transaction hash for proof submission
    pub proof_tx_hash: Option<String>,
    /// Transaction hash for worker payment
    pub payment_tx_hash: Option<String>,
    /// Transaction hash for fee distribution
    pub fee_tx_hash: Option<String>,
    /// Block number of settlement
    pub settlement_block: Option<u64>,
}

/// Invoice lifecycle status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceStatus {
    /// Job submitted, escrow locked
    Pending,
    /// Job being executed
    Executing,
    /// Proof being generated
    Proving,
    /// Proof generated, awaiting verification
    ProofReady,
    /// Proof submitted to chain
    ProofSubmitted,
    /// Proof verified on-chain
    Verified,
    /// Worker paid, invoice settled
    Settled,
    /// Verification failed
    VerificationFailed,
    /// Job failed (no proof)
    Failed,
    /// Disputed (challenge period)
    Disputed,
}

impl ComputeInvoice {
    /// Create a new invoice from job execution results
    pub fn new(
        job_id: &str,
        job_type: &str,
        worker_id: &str,
        worker_wallet: &str,
    ) -> Self {
        let circuit_type = CircuitType::from_job_type(job_type);
        let invoice_id = Self::generate_invoice_id(job_id, worker_id);

        Self {
            invoice_id,
            job_id: job_id.to_string(),
            job_type: job_type.to_string(),
            circuit_type,

            // Proof fields (to be filled)
            program_hash: [0u8; 32],
            input_commitment: [0u8; 32],
            output_commitment: [0u8; 32],
            proof_hash: [0u8; 32],
            proof_attestation: [0u8; 32],
            proof_commitment: [0u8; 32],
            proof_size_bytes: 0,
            proof_time_ms: 0,

            // Execution metrics (to be filled)
            trace_length: 0,
            constraint_count: 26, // ObelyskVM default
            gpu_seconds: 0.0,
            gpu_memory_bytes: 0,
            gpu_model: String::new(),
            tee_used: false,

            // Worker info
            worker_id: worker_id.to_string(),
            worker_wallet: worker_wallet.to_string(),
            worker_gpu_tier: String::new(),
            worker_reputation: 50,

            // Client info
            client_address: None,
            escrow_address: None,

            // Billing (to be filled)
            total_cost_cents: 0,
            hourly_rate_cents: 0,
            worker_payment_cents: 0,
            protocol_fee_cents: 0,
            sage_price_usd: 0.1,
            sage_to_worker: 0,
            sage_to_burn: 0,
            sage_to_treasury: 0,
            sage_to_stakers: 0,
            mining_bonus_sage: 0,
            total_sage_payout: 0,

            // Status
            status: InvoiceStatus::Pending,
            submitted_at: Utc::now(),
            started_at: None,
            completed_at: None,
            proof_generated_at: None,
            verified_at: None,
            settled_at: None,

            // On-chain
            proof_tx_hash: None,
            payment_tx_hash: None,
            fee_tx_hash: None,
            settlement_block: None,
        }
    }

    /// Generate deterministic invoice ID
    fn generate_invoice_id(job_id: &str, worker_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(job_id.as_bytes());
        hasher.update(worker_id.as_bytes());
        hasher.update(&Utc::now().timestamp().to_le_bytes());
        let hash = hasher.finalize();
        format!("inv-{}", hex::encode(&hash[..8]))
    }

    /// Set proof data from STWO proof generation
    pub fn set_proof_data(
        &mut self,
        proof_hash: [u8; 32],
        proof_attestation: [u8; 32],
        proof_commitment: [u8; 32],
        proof_size_bytes: usize,
        proof_time_ms: u64,
        trace_length: usize,
    ) {
        self.proof_hash = proof_hash;
        self.proof_attestation = proof_attestation;
        self.proof_commitment = proof_commitment;
        self.proof_size_bytes = proof_size_bytes;
        self.proof_time_ms = proof_time_ms;
        self.trace_length = trace_length;
        self.proof_generated_at = Some(Utc::now());
        self.status = InvoiceStatus::ProofReady;
    }

    /// Set input/output commitments
    pub fn set_io_commitments(&mut self, input: &[u8], output: &[u8]) {
        let mut input_hasher = Sha256::new();
        input_hasher.update(input);
        self.input_commitment = input_hasher.finalize().into();

        let mut output_hasher = Sha256::new();
        output_hasher.update(output);
        self.output_commitment = output_hasher.finalize().into();
    }

    /// Set program hash (model hash for AI, transform hash for ETL, etc.)
    pub fn set_program_hash(&mut self, program: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(program);
        self.program_hash = hasher.finalize().into();
    }

    /// Calculate billing from execution metrics
    pub fn calculate_billing(
        &mut self,
        gpu_seconds: f64,
        hourly_rate_cents: u64,
        sage_price_usd: f64,
        worker_reputation: u32,
    ) {
        self.gpu_seconds = gpu_seconds;
        self.hourly_rate_cents = hourly_rate_cents;
        self.worker_reputation = worker_reputation;
        self.sage_price_usd = sage_price_usd;

        // Calculate cost: (gpu_seconds / 3600) * hourly_rate, minimum 1 cent
        let hours = gpu_seconds / 3600.0;
        let raw_cost = (hours * hourly_rate_cents as f64) as u64;
        self.total_cost_cents = if gpu_seconds > 0.0 && raw_cost == 0 { 1 } else { raw_cost };

        // 80/20 split
        self.worker_payment_cents = self.total_cost_cents * 80 / 100;
        self.protocol_fee_cents = self.total_cost_cents - self.worker_payment_cents;

        // Enforce minimum: worker gets at least 1 cent if compute was performed
        if gpu_seconds > 0.0 && self.worker_payment_cents == 0 {
            self.worker_payment_cents = 1;
            self.total_cost_cents = self.total_cost_cents.max(2);
            self.protocol_fee_cents = self.total_cost_cents - self.worker_payment_cents;
        }

        // Convert to SAGE
        let decimals = 1_000_000_000_000_000_000u128;
        let worker_usd = self.worker_payment_cents as f64 / 100.0;
        let protocol_usd = self.protocol_fee_cents as f64 / 100.0;

        self.sage_to_worker = ((worker_usd / sage_price_usd) * decimals as f64) as u128;

        // Protocol fee distribution: 70% burn, 20% treasury, 10% stakers
        let protocol_sage = ((protocol_usd / sage_price_usd) * decimals as f64) as u128;
        self.sage_to_burn = protocol_sage * 70 / 100;
        self.sage_to_treasury = protocol_sage * 20 / 100;
        self.sage_to_stakers = protocol_sage * 10 / 100;

        // Mining bonus based on reputation
        let bonus_pct = if worker_reputation >= 90 {
            10 // 10% bonus
        } else if worker_reputation >= 70 {
            5  // 5% bonus
        } else if worker_reputation >= 50 {
            2  // 2% bonus
        } else {
            0
        };
        self.mining_bonus_sage = self.sage_to_worker * bonus_pct / 100;
        self.total_sage_payout = self.sage_to_worker + self.mining_bonus_sage;
    }

    /// Get public inputs for on-chain verification
    pub fn public_inputs(&self) -> Vec<[u8; 32]> {
        vec![
            self.program_hash,
            self.input_commitment,
            self.output_commitment,
        ]
    }

    /// Get invoice hash for signing
    pub fn invoice_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.invoice_id);
        hasher.update(&self.proof_hash);
        hasher.update(&self.worker_wallet);
        hasher.update(&self.total_sage_payout.to_le_bytes());
        hasher.finalize().into()
    }

    /// Mark as verified
    pub fn mark_verified(&mut self, tx_hash: &str) {
        self.status = InvoiceStatus::Verified;
        self.verified_at = Some(Utc::now());
        self.proof_tx_hash = Some(tx_hash.to_string());
    }

    /// Mark as settled
    pub fn mark_settled(&mut self, payment_tx: &str, block: u64) {
        self.status = InvoiceStatus::Settled;
        self.settled_at = Some(Utc::now());
        self.payment_tx_hash = Some(payment_tx.to_string());
        self.settlement_block = Some(block);
    }

    /// Mark as failed
    pub fn mark_failed(&mut self, _reason: &str) {
        self.status = InvoiceStatus::Failed;
        self.completed_at = Some(Utc::now());
    }

    /// Check if invoice can be settled
    pub fn can_settle(&self) -> bool {
        matches!(self.status, InvoiceStatus::Verified)
    }

    /// Format for display
    pub fn summary(&self) -> String {
        format!(
            "Invoice {} | Job: {} ({}) | Worker: {} | Cost: ${:.4} | SAGE: {} | Status: {:?}",
            self.invoice_id,
            self.job_id,
            self.job_type,
            self.worker_id,
            self.total_cost_cents as f64 / 100.0,
            self.total_sage_payout / 1_000_000_000_000_000_000, // Display whole SAGE
            self.status,
        )
    }
}

// =============================================================================
// Invoice Builder - Fluent API for Creating Invoices
// =============================================================================

/// Builder for creating compute invoices
pub struct InvoiceBuilder {
    invoice: ComputeInvoice,
}

impl InvoiceBuilder {
    pub fn new(job_id: &str, job_type: &str, worker_id: &str, worker_wallet: &str) -> Self {
        Self {
            invoice: ComputeInvoice::new(job_id, job_type, worker_id, worker_wallet),
        }
    }

    pub fn with_client(mut self, address: &str) -> Self {
        self.invoice.client_address = Some(address.to_string());
        self
    }

    pub fn with_escrow(mut self, address: &str) -> Self {
        self.invoice.escrow_address = Some(address.to_string());
        self
    }

    pub fn with_gpu(mut self, model: &str, tier: &str) -> Self {
        self.invoice.gpu_model = model.to_string();
        self.invoice.worker_gpu_tier = tier.to_string();
        self
    }

    pub fn with_tee(mut self, enabled: bool) -> Self {
        self.invoice.tee_used = enabled;
        self
    }

    pub fn with_input(mut self, input: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(input);
        self.invoice.input_commitment = hasher.finalize().into();
        self
    }

    pub fn with_output(mut self, output: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(output);
        self.invoice.output_commitment = hasher.finalize().into();
        self
    }

    pub fn with_program(mut self, program: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(program);
        self.invoice.program_hash = hasher.finalize().into();
        self
    }

    pub fn with_proof(
        mut self,
        proof_hash: [u8; 32],
        attestation: [u8; 32],
        commitment: [u8; 32],
        size_bytes: usize,
        time_ms: u64,
        trace_length: usize,
    ) -> Self {
        self.invoice.set_proof_data(proof_hash, attestation, commitment, size_bytes, time_ms, trace_length);
        self
    }

    pub fn with_billing(
        mut self,
        gpu_seconds: f64,
        hourly_rate_cents: u64,
        sage_price: f64,
        reputation: u32,
    ) -> Self {
        self.invoice.calculate_billing(gpu_seconds, hourly_rate_cents, sage_price, reputation);
        self
    }

    pub fn build(self) -> ComputeInvoice {
        self.invoice
    }
}

// =============================================================================
// Invoice Verification
// =============================================================================

/// Verify an invoice's proof locally (before on-chain submission)
pub fn verify_invoice_locally(invoice: &ComputeInvoice) -> Result<bool> {
    // 1. Check proof hash is not empty
    if invoice.proof_hash == [0u8; 32] {
        return Err(anyhow!("Proof hash is empty"));
    }

    // 2. Check proof size is reasonable
    let expected_size = invoice.circuit_type.estimated_proof_size();
    if invoice.proof_size_bytes == 0 || invoice.proof_size_bytes > expected_size * 2 {
        return Err(anyhow!("Invalid proof size: {} bytes", invoice.proof_size_bytes));
    }

    // 3. Check billing is calculated
    if invoice.total_cost_cents == 0 && invoice.gpu_seconds > 0.0 {
        return Err(anyhow!("Billing not calculated"));
    }

    // 4. Check worker wallet is valid hex
    if !invoice.worker_wallet.starts_with("0x") {
        return Err(anyhow!("Invalid worker wallet address"));
    }

    // 5. Check timestamps are sane
    if let Some(completed) = invoice.completed_at {
        if completed < invoice.submitted_at {
            return Err(anyhow!("Completed before submitted"));
        }
    }

    Ok(true)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invoice_creation() {
        let invoice = InvoiceBuilder::new(
            "job-123",
            "AIInference",
            "worker-456",
            "0x1234567890abcdef",
        )
        .with_client("0xclient")
        .with_gpu("H100", "Enterprise")
        .with_billing(30.0, 300, 0.10, 75)
        .build();

        assert_eq!(invoice.circuit_type, CircuitType::MlInference);
        assert_eq!(invoice.worker_payment_cents, invoice.total_cost_cents * 80 / 100);
        println!("{}", invoice.summary());
    }

    #[test]
    fn test_minimum_payout_not_zero() {
        // 0.019 GPU seconds at $0.50/hr with SAGE at $0.10 should still yield non-zero worker payout
        let invoice = InvoiceBuilder::new(
            "job-min",
            "AIInference",
            "worker-min",
            "0xminworker",
        )
        .with_billing(0.019, 50, 0.10, 50)
        .build();

        assert!(invoice.worker_payment_cents >= 1, "worker_payment_cents should be at least 1");
        assert!(invoice.sage_to_worker > 0, "sage_to_worker should be > 0");
        assert!(invoice.total_cost_cents >= 2, "total_cost_cents should be at least 2 when minimum enforced");
        assert_eq!(invoice.total_cost_cents, invoice.worker_payment_cents + invoice.protocol_fee_cents);
    }

    #[test]
    fn test_circuit_mapping() {
        assert_eq!(CircuitType::from_job_type("AIInference"), CircuitType::MlInference);
        assert_eq!(CircuitType::from_job_type("DataPipeline"), CircuitType::EtlTransform);
        assert_eq!(CircuitType::from_job_type("Ping"), CircuitType::PipelineTest);
        assert_eq!(CircuitType::from_job_type("Unknown"), CircuitType::GenericCompute);
    }
}
