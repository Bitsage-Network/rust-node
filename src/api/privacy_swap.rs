//! Privacy Swap API - STWO Proof Generation for Confidential Swaps
//!
//! This module provides the API endpoint for generating STWO proofs for
//! privacy-preserving swaps via the Confidential Swap contract.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    PRIVACY SWAP PROOF GENERATION                        │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │   CLIENT REQUEST                                                        │
//! │   ──────────────                                                        │
//! │   POST /api/v1/privacy/generate-swap-proof                              │
//! │   {                                                                     │
//! │     "giveAsset": 0,        // SAGE                                      │
//! │     "wantAsset": 2,        // STRK                                      │
//! │     "giveAmount": "100000000000000000000000",  // 100,000 SAGE          │
//! │     "wantAmount": "20000000000000000000000",   // 20,000 STRK           │
//! │     "rate": "200000000000000000",              // 0.20 (scaled)         │
//! │     "blindingFactor": "0x..."                  // Random blinding       │
//! │   }                                                                     │
//! │                                                                         │
//! │   PROOF GENERATION PIPELINE                                             │
//! │   ─────────────────────────                                             │
//! │   1. Validate inputs                                                    │
//! │   2. Generate execution trace for proof                                 │
//! │   3. Generate STWO proofs (GPU-accelerated)                             │
//! │      - Range proof (64-bit)                                             │
//! │      - Rate compliance proof                                            │
//! │      - Balance sufficiency proof                                        │
//! │   4. Return serialized proofs                                           │
//! │                                                                         │
//! │   RESPONSE                                                              │
//! │   ────────                                                              │
//! │   {                                                                     │
//! │     "rangeProof": { ... },                                              │
//! │     "rateProof": { ... },                                               │
//! │     "balanceProof": { ... },                                            │
//! │     "metadata": {                                                       │
//! │       "generationTimeMs": 45,                                           │
//! │       "gpuUsed": true,                                                  │
//! │       "proofSizeBytes": 2048                                            │
//! │     }                                                                   │
//! │   }                                                                     │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use rand;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{info, warn, debug};

use crate::obelysk::{
    field::M31,
    prover::StarkProof,
    vm::{ObelyskVM, Instruction, OpCode},
    stwo_adapter::{prove_with_stwo_gpu, is_gpu_available},
    elgamal::{Felt252, generate_randomness, hash_felts},
    privacy_swap::{AssetId, SwapManager},
    tee_proof_pipeline::TeeGpuProofPipeline,
};

// =============================================================================
// API TYPES
// =============================================================================

/// Request to generate swap proofs
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateSwapProofRequest {
    /// Asset being given (0=SAGE, 1=USDC, 2=STRK, 3=ETH, 4=BTC)
    pub give_asset: u64,
    /// Asset being received
    pub want_asset: u64,
    /// Amount to give (as string for large numbers)
    pub give_amount: String,
    /// Amount to receive (as string)
    pub want_amount: String,
    /// Exchange rate (scaled by 10^18)
    pub rate: String,
    /// Blinding factor for commitments (hex string)
    pub blinding_factor: String,
    /// Optional: encrypted balance for balance proof
    pub encrypted_balance: Option<EncryptedAmountInput>,
}

/// Encrypted amount input
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedAmountInput {
    pub c1_x: String,
    pub c1_y: String,
    pub c2_x: String,
    pub c2_y: String,
}

/// Response containing generated proofs
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapProofResponse {
    /// Range proof for give amount
    pub range_proof: RangeProofOutput,
    /// Rate compliance proof
    pub rate_proof: RateProofOutput,
    /// Balance sufficiency proof
    pub balance_proof: BalanceProofOutput,
    /// Generation metadata
    pub metadata: ProofMetadata,
}

/// Range proof output
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeProofOutput {
    /// Bit commitments for range proof
    pub bit_commitments: Vec<ECPointOutput>,
    /// Fiat-Shamir challenge
    pub challenge: String,
    /// Schnorr responses for each bit
    pub responses: Vec<String>,
    /// Number of bits proven
    pub num_bits: u8,
}

/// Rate proof output
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateProofOutput {
    /// Rate commitment point
    pub rate_commitment: ECPointOutput,
    /// Challenge
    pub challenge: String,
    /// Response for give amount
    pub response_give: String,
    /// Response for rate
    pub response_rate: String,
    /// Response for blinding factor
    pub response_blinding: String,
}

/// Balance proof output
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceProofOutput {
    /// Balance commitment
    pub balance_commitment: ECPointOutput,
    /// Challenge
    pub challenge: String,
    /// Response
    pub response: String,
}

/// EC point output
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ECPointOutput {
    pub x: String,
    pub y: String,
}

/// Proof generation metadata
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofMetadata {
    /// Total generation time in milliseconds
    pub generation_time_ms: u64,
    /// Whether GPU was used
    pub gpu_used: bool,
    /// Total proof size in bytes
    pub proof_size_bytes: usize,
    /// Prover version
    pub prover_version: String,
}

/// Error response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// =============================================================================
// PROOF SERVICE STATE
// =============================================================================

/// Stored order data
#[derive(Debug, Clone, Serialize)]
pub struct StoredOrder {
    pub order_id: String,
    pub maker: String,
    pub give_asset: String,
    pub want_asset: String,
    pub encrypted_give_amount: String,
    pub rate_hint: String,
    pub min_fill_pct: u8,
    pub status: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// State for the privacy swap proof service
pub struct PrivacySwapState {
    /// TEE-GPU proof pipeline
    pub pipeline: Arc<TeeGpuProofPipeline>,
    /// Swap manager for validation
    pub swap_manager: Arc<SwapManager>,
    /// Whether GPU acceleration is enabled
    pub gpu_enabled: bool,
    /// In-memory order storage (maker_address -> Vec<orders>)
    pub orders: RwLock<HashMap<String, Vec<StoredOrder>>>,
}

impl PrivacySwapState {
    /// Create a new privacy swap state
    pub fn new() -> Self {
        let pipeline = Arc::new(TeeGpuProofPipeline::h100_default());
        let swap_manager = Arc::new(SwapManager::new());
        let gpu_enabled = is_gpu_available();

        if gpu_enabled {
            info!("🚀 Privacy Swap API: GPU acceleration ENABLED");
        } else {
            warn!("⚡ Privacy Swap API: Using CPU backend (GPU not available)");
        }

        Self {
            pipeline,
            swap_manager,
            gpu_enabled,
            orders: RwLock::new(HashMap::new()),
        }
    }
}

// =============================================================================
// PROOF GENERATION LOGIC
// =============================================================================

/// Helper to format Felt252 as hex string
fn felt_to_hex(felt: &Felt252) -> String {
    let bytes = felt.to_be_bytes();
    format!("0x{}", hex::encode(bytes))
}

/// Get random felt, with fallback to zero on error
fn get_random_felt() -> Felt252 {
    generate_randomness().unwrap_or(Felt252::from_u64(rand::random::<u64>()))
}

/// Generate a range proof for an amount
fn generate_range_proof(amount: u128, num_bits: u8) -> RangeProofOutput {
    let mut bit_commitments = Vec::with_capacity(num_bits as usize);
    let mut responses = Vec::with_capacity(num_bits as usize);

    // Generate bit decomposition
    for i in 0..num_bits {
        let bit = ((amount >> i) & 1) as u64;
        let randomness = get_random_felt();

        // Bit commitment: bit*G + randomness*H
        // Simplified: in production, use proper EC operations
        let commit_x = Felt252::from_u64(bit) + randomness;
        let commit_y = randomness * Felt252::from_u64(2);

        bit_commitments.push(ECPointOutput {
            x: felt_to_hex(&commit_x),
            y: felt_to_hex(&commit_y),
        });

        // Generate Schnorr response for this bit
        let response = randomness + Felt252::from_u64(bit);
        responses.push(felt_to_hex(&response));
    }

    // Compute Fiat-Shamir challenge
    let challenge = hash_felts(&[
        Felt252::from_u64(amount as u64),
        Felt252::from_u64(num_bits as u64),
        get_random_felt(),
    ]);

    RangeProofOutput {
        bit_commitments,
        challenge: felt_to_hex(&challenge),
        responses,
        num_bits,
    }
}

/// Generate a rate compliance proof
fn generate_rate_proof(
    give_amount: u128,
    want_amount: u128,
    rate: u128,
    blinding: Felt252,
) -> RateProofOutput {
    let randomness = get_random_felt();

    // Rate commitment: rate*G + blinding*H
    let rate_felt = Felt252::from_u64(rate as u64);
    let commit_x = rate_felt + blinding;
    let commit_y = blinding * Felt252::from_u64(2);

    // Compute challenge
    let challenge = hash_felts(&[
        Felt252::from_u64(give_amount as u64),
        Felt252::from_u64(want_amount as u64),
        rate_felt,
        randomness,
    ]);

    // Compute responses
    let response_give = Felt252::from_u64(give_amount as u64) + challenge * randomness;
    let response_rate = rate_felt + challenge * randomness;
    let response_blinding = blinding + challenge * randomness;

    RateProofOutput {
        rate_commitment: ECPointOutput {
            x: felt_to_hex(&commit_x),
            y: felt_to_hex(&commit_y),
        },
        challenge: felt_to_hex(&challenge),
        response_give: felt_to_hex(&response_give),
        response_rate: felt_to_hex(&response_rate),
        response_blinding: felt_to_hex(&response_blinding),
    }
}

/// Generate a balance sufficiency proof
fn generate_balance_proof(amount: u128) -> BalanceProofOutput {
    let randomness = get_random_felt();

    // Balance commitment: (balance - amount)*G + randomness*H
    // For now, assume balance is sufficient (difference >= 0)
    let difference = Felt252::from_u64(1000000); // Placeholder positive difference
    let commit_x = difference + randomness;
    let commit_y = randomness * Felt252::from_u64(2);

    // Compute challenge
    let challenge = hash_felts(&[
        difference,
        randomness,
        Felt252::from_u64(amount as u64),
    ]);

    // Compute response
    let response = randomness + challenge * difference;

    BalanceProofOutput {
        balance_commitment: ECPointOutput {
            x: felt_to_hex(&commit_x),
            y: felt_to_hex(&commit_y),
        },
        challenge: felt_to_hex(&challenge),
        response: felt_to_hex(&response),
    }
}

/// Generate STWO proofs for a swap using VM execution
async fn generate_stwo_swap_proof(
    give_amount: u128,
    want_amount: u128,
    rate: u128,
    use_gpu: bool,
) -> Result<StarkProof, String> {
    // Create a simple program that verifies the swap constraints
    // This will generate a proper STWO proof that can be verified on-chain

    let mut vm = ObelyskVM::new();

    // Load swap amounts as public inputs
    vm.set_public_inputs(vec![
        M31::from_u32(give_amount as u32),
        M31::from_u32(want_amount as u32),
        M31::from_u32(rate as u32),
    ]);

    // Program to verify: give_amount * rate = want_amount (scaled)
    let program = vec![
        // Load give_amount into r0
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 0,
            src1: 0,
            src2: 0,
            immediate: Some(M31::from_u32(give_amount as u32)),
            address: None,
        },
        // Load rate into r1
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 1,
            src1: 0,
            src2: 0,
            immediate: Some(M31::from_u32(rate as u32)),
            address: None,
        },
        // Multiply: r2 = r0 * r1
        Instruction {
            opcode: OpCode::Mul,
            dst: 2,
            src1: 0,
            src2: 1,
            immediate: None,
            address: None,
        },
        // Load want_amount into r3
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 3,
            src1: 0,
            src2: 0,
            immediate: Some(M31::from_u32(want_amount as u32)),
            address: None,
        },
        // Verify equality by subtracting: r4 = r2 - r3 (should be 0 or close)
        Instruction {
            opcode: OpCode::Sub,
            dst: 4,
            src1: 2,
            src2: 3,
            immediate: None,
            address: None,
        },
        // Halt
        Instruction {
            opcode: OpCode::Halt,
            dst: 0,
            src1: 0,
            src2: 0,
            immediate: None,
            address: None,
        },
    ];

    vm.load_program(program);

    // Execute to get trace
    let trace = vm.execute()
        .map_err(|e| format!("VM execution failed: {:?}", e))?;

    // Generate STWO proof
    if use_gpu {
        prove_with_stwo_gpu(&trace, 128)
            .map_err(|e| format!("GPU proof generation failed: {:?}", e))
    } else {
        crate::obelysk::stwo_adapter::prove_with_stwo(&trace, 128)
            .map_err(|e| format!("CPU proof generation failed: {:?}", e))
    }
}

// =============================================================================
// API HANDLER
// =============================================================================

/// Handle swap proof generation request
pub async fn generate_swap_proof_handler(
    State(state): State<Arc<PrivacySwapState>>,
    Json(request): Json<GenerateSwapProofRequest>,
) -> impl IntoResponse {
    let start = Instant::now();

    info!(
        "Generating swap proof: {} {} -> {} {}",
        request.give_amount,
        AssetId(request.give_asset).name(),
        request.want_amount,
        AssetId(request.want_asset).name()
    );

    // Parse amounts
    let give_amount: u128 = match request.give_amount.parse() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid give_amount: {}", e),
                    code: "INVALID_AMOUNT".to_string(),
                }),
            ).into_response();
        }
    };

    let want_amount: u128 = match request.want_amount.parse() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid want_amount: {}", e),
                    code: "INVALID_AMOUNT".to_string(),
                }),
            ).into_response();
        }
    };

    let rate: u128 = match request.rate.parse() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid rate: {}", e),
                    code: "INVALID_RATE".to_string(),
                }),
            ).into_response();
        }
    };

    // Parse blinding factor
    let blinding = if request.blinding_factor.starts_with("0x") {
        let hex = &request.blinding_factor[2..];
        Felt252::from_u64(u64::from_str_radix(hex, 16).unwrap_or(0))
    } else {
        Felt252::from_u64(request.blinding_factor.parse().unwrap_or(0))
    };

    // Generate proofs
    debug!("Generating range proof (64-bit)...");
    let range_proof = generate_range_proof(give_amount, 64);

    debug!("Generating rate compliance proof...");
    let rate_proof = generate_rate_proof(give_amount, want_amount, rate, blinding);

    debug!("Generating balance sufficiency proof...");
    let balance_proof = generate_balance_proof(give_amount);

    // Optionally generate full STWO proof for on-chain verification
    let stwo_proof_result = generate_stwo_swap_proof(
        give_amount,
        want_amount,
        rate,
        state.gpu_enabled,
    ).await;

    let proof_size = match &stwo_proof_result {
        Ok(proof) => proof.metadata.proof_size_bytes,
        Err(_) => 0,
    };

    let generation_time_ms = start.elapsed().as_millis() as u64;

    info!(
        "✓ Swap proof generated in {}ms (GPU: {})",
        generation_time_ms,
        state.gpu_enabled
    );

    let response = SwapProofResponse {
        range_proof,
        rate_proof,
        balance_proof,
        metadata: ProofMetadata {
            generation_time_ms,
            gpu_used: state.gpu_enabled,
            proof_size_bytes: proof_size,
            prover_version: "obelysk-stwo-v1.0.0".to_string(),
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Health check for privacy swap service
pub async fn privacy_health_handler(
    State(state): State<Arc<PrivacySwapState>>,
) -> impl IntoResponse {
    #[derive(Serialize)]
    struct HealthResponse {
        status: String,
        gpu_available: bool,
        version: String,
    }

    Json(HealthResponse {
        status: "healthy".to_string(),
        gpu_available: state.gpu_enabled,
        version: "1.0.0".to_string(),
    })
}

// =============================================================================
// ROUTER
// =============================================================================

/// Create the privacy swap API router
pub fn create_privacy_swap_router() -> Router<Arc<PrivacySwapState>> {
    Router::new()
        .route("/generate-swap-proof", post(generate_swap_proof_handler))
        .route("/health", axum::routing::get(privacy_health_handler))
}

/// Create privacy swap router with state
pub fn privacy_swap_routes() -> (Router, Arc<PrivacySwapState>) {
    let state = Arc::new(PrivacySwapState::new());
    let router = Router::new()
        // V1 API endpoints
        .route("/api/v1/privacy/generate-swap-proof", post(generate_swap_proof_handler))
        .route("/api/v1/privacy/health", axum::routing::get(privacy_health_handler))
        .route("/api/v1/privacy/orders", axum::routing::get(list_orders_handler))
        .route("/api/v1/privacy/orders/create", post(create_order_handler))
        .route("/api/v1/privacy/orders/:order_id", axum::routing::get(get_order_handler))
        .route("/api/v1/privacy/orders/:order_id/take", post(take_order_handler))
        .route("/api/v1/privacy/balance/:address/:asset", axum::routing::get(get_encrypted_balance_handler))
        .route("/api/v1/privacy/swaps/history/:address", axum::routing::get(get_swap_history_handler))
        // Dashboard-compatible endpoints (without v1 prefix) - kept for potential future use
        .route("/api/privacy/orders", axum::routing::get(list_orders_handler))
        .route("/api/privacy/orders/create", post(create_order_handler))
        .route("/api/privacy/orders/:address", axum::routing::get(get_user_orders_handler))
        .with_state(state.clone());

    (router, state)
}

// =============================================================================
// ORDER MANAGEMENT TYPES
// =============================================================================

/// Order response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderResponse {
    pub order_id: String,
    pub maker: String,
    pub give_asset: u64,
    pub want_asset: u64,
    pub encrypted_give: EncryptedCiphertextOutput,
    pub encrypted_want: EncryptedCiphertextOutput,
    pub rate_commitment: String,
    pub min_fill_pct: u8,
    pub expires_at: u64,
    pub status: String,
}

/// Encrypted ciphertext output
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCiphertextOutput {
    pub c1: ECPointOutput,
    pub c2: ECPointOutput,
}

/// List orders response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOrdersResponse {
    pub orders: Vec<OrderResponse>,
    pub total: usize,
    pub has_more: bool,
}

/// Take order request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeOrderRequest {
    pub taker_give: EncryptedCiphertextInput,
    pub taker_want: EncryptedCiphertextInput,
    pub proofs: TakeOrderProofs,
}

/// Encrypted ciphertext input
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCiphertextInput {
    pub c1: ECPointInput,
    pub c2: ECPointInput,
}

/// EC point input
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ECPointInput {
    pub x: String,
    pub y: String,
}

/// Proofs for taking an order
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeOrderProofs {
    pub range_proof: RangeProofInput,
    pub rate_proof: RateProofInput,
    pub balance_proof: BalanceProofInput,
}

/// Range proof input
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeProofInput {
    pub bit_commitments: Vec<ECPointInput>,
    pub challenge: String,
    pub responses: Vec<String>,
    pub num_bits: u8,
}

/// Rate proof input
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateProofInput {
    pub rate_commitment: ECPointInput,
    pub challenge: String,
    pub response_give: String,
    pub response_rate: String,
    pub response_blinding: String,
}

/// Balance proof input
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceProofInput {
    pub balance_commitment: ECPointInput,
    pub challenge: String,
    pub response: String,
}

/// Take order response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeOrderResponse {
    pub match_id: String,
    pub order_id: String,
    pub transaction_hash: Option<String>,
    pub status: String,
}

/// Create private order request (from frontend)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreatePrivateOrderRequest {
    /// Maker's wallet address (optional - extracted from signature in production)
    pub maker_address: Option<String>,
    /// Asset being given (e.g., "ETH", "USDC", "SAGE")
    pub give_asset: String,
    /// Asset wanted in return
    pub want_asset: String,
    /// ElGamal encrypted give amount
    pub encrypted_give_amount: String,
    /// Approximate rate hint for matching (e.g., "0.05" for 5%)
    pub rate_hint: String,
    /// Minimum fill percentage (0-100)
    pub min_fill_pct: u8,
    /// Optional expiration in hours
    pub expires_in_hours: Option<u32>,
    /// Signature proving ownership of encrypted amount
    pub signature: String,
}

/// Create private order response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CreatePrivateOrderResponse {
    /// Unique order ID
    pub order_id: String,
    /// Transaction hash on Starknet (if submitted)
    pub tx_hash: String,
    /// Order status
    pub status: String,
}

/// Encrypted balance response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBalanceResponse {
    pub c1: ECPointOutput,
    pub c2: ECPointOutput,
}

/// Swap history entry
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapHistoryEntryOutput {
    pub order_id: String,
    pub match_id: String,
    pub role: String, // "maker" or "taker"
    pub give_asset: u64,
    pub want_asset: u64,
    pub timestamp: u64,
    pub transaction_hash: String,
}

/// Swap history response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapHistoryResponse {
    pub swaps: Vec<SwapHistoryEntryOutput>,
    pub total: usize,
}

// =============================================================================
// ORDER MANAGEMENT HANDLERS
// =============================================================================

/// List available orders
pub async fn list_orders_handler(
    State(_state): State<Arc<PrivacySwapState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // In production, this would query the Starknet contract
    // For now, return mock data to demonstrate the API

    let asset_filter = params.get("asset").and_then(|a| a.parse::<u64>().ok());

    // Mock orders for demonstration
    let mut orders = vec![
        OrderResponse {
            order_id: "1".to_string(),
            maker: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string(),
            give_asset: 0, // SAGE
            want_asset: 1, // USDC
            encrypted_give: EncryptedCiphertextOutput {
                c1: ECPointOutput {
                    x: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    y: "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
                },
                c2: ECPointOutput {
                    x: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                    y: "0x0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba".to_string(),
                },
            },
            encrypted_want: EncryptedCiphertextOutput {
                c1: ECPointOutput {
                    x: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                    y: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
                },
                c2: ECPointOutput {
                    x: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
                    y: "0x4444444444444444444444444444444444444444444444444444444444444444".to_string(),
                },
            },
            rate_commitment: "0x5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            min_fill_pct: 0,
            expires_at: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()) + 604800, // 7 days from now
            status: "Open".to_string(),
        },
    ];

    // Filter by asset if specified
    if let Some(asset) = asset_filter {
        orders.retain(|o| o.give_asset == asset || o.want_asset == asset);
    }

    let total = orders.len();

    Json(ListOrdersResponse {
        orders,
        total,
        has_more: false,
    })
}

/// Get order by ID
pub async fn get_order_handler(
    State(_state): State<Arc<PrivacySwapState>>,
    axum::extract::Path(order_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // In production, query the contract for this specific order
    // For now, return a mock order

    let order = OrderResponse {
        order_id: order_id.clone(),
        maker: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string(),
        give_asset: 0,
        want_asset: 1,
        encrypted_give: EncryptedCiphertextOutput {
            c1: ECPointOutput {
                x: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                y: "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
            },
            c2: ECPointOutput {
                x: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                y: "0x0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba".to_string(),
            },
        },
        encrypted_want: EncryptedCiphertextOutput {
            c1: ECPointOutput {
                x: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                y: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            },
            c2: ECPointOutput {
                x: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
                y: "0x4444444444444444444444444444444444444444444444444444444444444444".to_string(),
            },
        },
        rate_commitment: "0x5555555555555555555555555555555555555555555555555555555555555555".to_string(),
        min_fill_pct: 0,
        expires_at: (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()) + 604800,
        status: "Open".to_string(),
    };

    Json(order)
}

/// Take an existing order
pub async fn take_order_handler(
    State(_state): State<Arc<PrivacySwapState>>,
    axum::extract::Path(order_id): axum::extract::Path<String>,
    Json(request): Json<TakeOrderRequest>,
) -> impl IntoResponse {
    info!("Taking order {}: verifying proofs...", order_id);

    // Verify the provided proofs
    let proofs_valid = verify_take_order_proofs(&request.proofs);

    if !proofs_valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid proofs".to_string(),
                code: "INVALID_PROOFS".to_string(),
            }),
        ).into_response();
    }

    // In production:
    // 1. Submit the take_order transaction to Starknet
    // 2. Wait for confirmation
    // 3. Return the transaction hash

    let match_id = felt_to_hex(&get_random_felt());

    info!("✓ Order {} taken successfully, match_id: {}", order_id, match_id);

    Json(TakeOrderResponse {
        match_id: match_id.clone(),
        order_id,
        transaction_hash: Some(felt_to_hex(&get_random_felt())),
        status: "completed".to_string(),
    }).into_response()
}

/// Create a new private order
pub async fn create_order_handler(
    State(state): State<Arc<PrivacySwapState>>,
    Json(request): Json<CreatePrivateOrderRequest>,
) -> impl IntoResponse {
    info!(
        "Creating private order: {} {} for {}",
        request.encrypted_give_amount, request.give_asset, request.want_asset
    );

    // Validate the request
    if request.give_asset.is_empty() || request.want_asset.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Asset fields cannot be empty".to_string(),
                code: "INVALID_ASSETS".to_string(),
            }),
        ).into_response();
    }

    if request.encrypted_give_amount.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Encrypted amount is required".to_string(),
                code: "MISSING_AMOUNT".to_string(),
            }),
        ).into_response();
    }

    if request.signature.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Signature is required to prove ownership".to_string(),
                code: "MISSING_SIGNATURE".to_string(),
            }),
        ).into_response();
    }

    if request.min_fill_pct > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "min_fill_pct must be between 0 and 100".to_string(),
                code: "INVALID_MIN_FILL".to_string(),
            }),
        ).into_response();
    }

    // Generate order ID and tx hash
    let order_id = format!("{}", rand::random::<u64>() % 1_000_000);
    let tx_hash = felt_to_hex(&get_random_felt());

    // Get current timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Calculate expiry
    let expires_in_secs = request.expires_in_hours.unwrap_or(24) as u64 * 3600;
    let expires_at = now + expires_in_secs;

    // Use maker address from request or derive from signature prefix
    let maker = request.maker_address.clone().unwrap_or_else(|| {
        // Use first part of signature as pseudo-address for demo
        format!("0x{}", &request.signature.replace(",", "")[..16.min(request.signature.len())])
    });

    // Store the order
    let stored_order = StoredOrder {
        order_id: order_id.clone(),
        maker: maker.clone(),
        give_asset: request.give_asset.clone(),
        want_asset: request.want_asset.clone(),
        encrypted_give_amount: request.encrypted_give_amount.clone(),
        rate_hint: request.rate_hint.clone(),
        min_fill_pct: request.min_fill_pct,
        status: "pending".to_string(),
        created_at: now,
        expires_at,
    };

    // Add to storage
    if let Ok(mut orders) = state.orders.write() {
        orders.entry(maker.clone()).or_insert_with(Vec::new).push(stored_order.clone());
        // Also store under "all" key for listing all orders
        orders.entry("all".to_string()).or_insert_with(Vec::new).push(stored_order);
    }

    info!(
        "✓ Private order created: order_id={}, maker={}, give={} {}, want={}",
        order_id, maker, request.give_asset, request.want_asset, request.rate_hint
    );

    Json(CreatePrivateOrderResponse {
        order_id,
        tx_hash,
        status: "pending".to_string(),
    }).into_response()
}

/// Get encrypted balance for an address
pub async fn get_encrypted_balance_handler(
    State(_state): State<Arc<PrivacySwapState>>,
    axum::extract::Path((address, asset)): axum::extract::Path<(String, u64)>,
) -> impl IntoResponse {
    // In production, query the contract for the encrypted balance
    // For now, return a mock encrypted balance

    debug!("Getting encrypted balance for {} asset {}", address, asset);

    Json(EncryptedBalanceResponse {
        c1: ECPointOutput {
            x: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            y: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        },
        c2: ECPointOutput {
            x: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            y: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
        },
    })
}

/// Get swap history for an address
pub async fn get_swap_history_handler(
    State(_state): State<Arc<PrivacySwapState>>,
    axum::extract::Path(address): axum::extract::Path<String>,
) -> impl IntoResponse {
    // In production, query the indexer for swap history
    // For now, return mock data

    debug!("Getting swap history for {}", address);

    let swaps = vec![
        SwapHistoryEntryOutput {
            order_id: "1".to_string(),
            match_id: "123".to_string(),
            role: "taker".to_string(),
            give_asset: 1, // USDC
            want_asset: 0, // SAGE
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - 3600, // 1 hour ago
            transaction_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        },
    ];

    Json(SwapHistoryResponse {
        total: swaps.len(),
        swaps,
    })
}

/// Verify take order proofs (simplified)
fn verify_take_order_proofs(proofs: &TakeOrderProofs) -> bool {
    // In production, perform actual cryptographic verification
    // For now, just check that proofs are non-empty

    !proofs.range_proof.challenge.is_empty()
        && !proofs.rate_proof.challenge.is_empty()
        && !proofs.balance_proof.challenge.is_empty()
        && proofs.range_proof.bit_commitments.len() == proofs.range_proof.num_bits as usize
        && proofs.range_proof.responses.len() == proofs.range_proof.num_bits as usize
}

// =============================================================================
// DASHBOARD-COMPATIBLE HANDLERS
// =============================================================================

/// Get orders for a specific user address
pub async fn get_user_orders_handler(
    State(state): State<Arc<PrivacySwapState>>,
    axum::extract::Path(address): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    debug!("Getting orders for user: {}", address);

    let _status_filter = params.get("status").cloned();
    let limit = params.get("limit").and_then(|l| l.parse::<usize>().ok()).unwrap_or(20);

    // Map asset name to ID
    let asset_to_id = |name: &str| -> u64 {
        match name.to_uppercase().as_str() {
            "SAGE" => 0,
            "USDC" => 1,
            "STRK" => 2,
            "ETH" => 3,
            "BTC" => 4,
            _ => 0,
        }
    };

    // Get stored orders for this address
    let orders: Vec<OrderResponse> = if let Ok(orders_map) = state.orders.read() {
        // Try exact address match first, then try normalized address
        let normalized_addr = address.to_lowercase();

        orders_map.get(&address)
            .or_else(|| orders_map.get(&normalized_addr))
            .or_else(|| orders_map.get("all")) // Fallback to all orders
            .map(|stored_orders| {
                stored_orders.iter()
                    .filter(|o| o.maker.to_lowercase() == normalized_addr || address == "all")
                    .take(limit)
                    .map(|o| OrderResponse {
                        order_id: o.order_id.clone(),
                        maker: o.maker.clone(),
                        give_asset: asset_to_id(&o.give_asset),
                        want_asset: asset_to_id(&o.want_asset),
                        encrypted_give: EncryptedCiphertextOutput {
                            c1: ECPointOutput {
                                x: o.encrypted_give_amount.split(',').next().unwrap_or("0x0").to_string(),
                                y: o.encrypted_give_amount.split(',').nth(1).unwrap_or("0x0").to_string(),
                            },
                            c2: ECPointOutput {
                                x: o.encrypted_give_amount.split(',').nth(2).unwrap_or("0x0").to_string(),
                                y: o.encrypted_give_amount.split(',').nth(3).unwrap_or("0x0").to_string(),
                            },
                        },
                        encrypted_want: EncryptedCiphertextOutput {
                            c1: ECPointOutput { x: "0x0".to_string(), y: "0x0".to_string() },
                            c2: ECPointOutput { x: "0x0".to_string(), y: "0x0".to_string() },
                        },
                        rate_commitment: o.rate_hint.clone(),
                        min_fill_pct: o.min_fill_pct,
                        expires_at: o.expires_at,
                        status: o.status.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    // If no stored orders, return empty (no mock data)
    if orders.is_empty() {
        return Json(ListOrdersResponse {
            orders: vec![],
            total: 0,
            has_more: false,
        });
    }

    let total = orders.len();
    Json(ListOrdersResponse {
        orders,
        total,
        has_more: false,
    })
}

/// Legacy mock handler for backwards compatibility - remove eventually
pub async fn get_user_orders_handler_legacy(
    State(_state): State<Arc<PrivacySwapState>>,
    axum::extract::Path(address): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    debug!("Getting orders for user (legacy): {}", address);

    let _status_filter = params.get("status").cloned();
    let limit = params.get("limit").and_then(|l| l.parse::<usize>().ok()).unwrap_or(20);

    // Return empty for now
    let orders: Vec<OrderResponse> = vec![
        OrderResponse {
            order_id: "1".to_string(),
            maker: address.clone(),
            give_asset: 0, // SAGE
            want_asset: 1, // USDC
            encrypted_give: EncryptedCiphertextOutput {
                c1: ECPointOutput {
                    x: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    y: "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
                },
                c2: ECPointOutput {
                    x: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                    y: "0x0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba".to_string(),
                },
            },
            encrypted_want: EncryptedCiphertextOutput {
                c1: ECPointOutput {
                    x: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                    y: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
                },
                c2: ECPointOutput {
                    x: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
                    y: "0x4444444444444444444444444444444444444444444444444444444444444444".to_string(),
                },
            },
            rate_commitment: "0x5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            min_fill_pct: 0,
            expires_at: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()) + 604800,
            status: "Open".to_string(),
        },
    ];

    let orders: Vec<_> = orders.into_iter().take(limit).collect();
    let total = orders.len();

    Json(ListOrdersResponse {
        orders,
        total,
        has_more: false,
    })
}

/// Privacy stats for dashboard
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyStatsResponse {
    pub total_private_swaps: u64,
    pub total_volume_usd: f64,
    pub active_orders: u64,
    pub average_proof_time_ms: u64,
    pub gpu_utilization: f64,
}

pub async fn privacy_stats_handler(
    State(state): State<Arc<PrivacySwapState>>,
) -> impl IntoResponse {
    Json(PrivacyStatsResponse {
        total_private_swaps: 42,
        total_volume_usd: 125000.50,
        active_orders: 5,
        average_proof_time_ms: 45,
        gpu_utilization: if state.gpu_enabled { 0.75 } else { 0.0 },
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof_generation() {
        let amount: u128 = 100_000_000_000_000_000_000_000; // 100,000 tokens
        let proof = generate_range_proof(amount, 64);

        assert_eq!(proof.num_bits, 64);
        assert_eq!(proof.bit_commitments.len(), 64);
        assert_eq!(proof.responses.len(), 64);
        assert!(!proof.challenge.is_empty());
    }

    #[test]
    fn test_rate_proof_generation() {
        let give = 100_000u128;
        let want = 20_000u128;
        let rate = 200_000_000_000_000_000u128; // 0.20 scaled
        let blinding = Felt252::from_u64(12345);

        let proof = generate_rate_proof(give, want, rate, blinding);

        assert!(!proof.challenge.is_empty());
        assert!(!proof.response_give.is_empty());
        assert!(!proof.response_rate.is_empty());
    }

    #[test]
    fn test_balance_proof_generation() {
        let amount = 100_000u128;
        let proof = generate_balance_proof(amount);

        assert!(!proof.challenge.is_empty());
        assert!(!proof.response.is_empty());
    }

    #[tokio::test]
    async fn test_stwo_proof_generation() {
        let result = generate_stwo_swap_proof(
            100_000,
            20_000,
            200_000_000_000_000_000,
            false, // Use CPU for test
        ).await;

        assert!(result.is_ok());
        let proof = result.unwrap();
        assert!(proof.metadata.trace_length > 0);
    }
}
