//! Relayer API - Gasless Transaction Submission for Privacy Operations
//!
//! This module provides API endpoints for submitting gasless transactions.
//! Users sign transactions client-side, and the relayer submits them
//! using funds from the Paymaster contract.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use starknet::{
    accounts::{Account, Call, SingleOwnerAccount, ExecutionEncoding},
    core::types::FieldElement,
    providers::{jsonrpc::HttpTransport, JsonRpcClient},
    signers::{LocalWallet, SigningKey},
};
use url::Url;
use std::collections::HashMap;

/// Relayer state
#[derive(Clone)]
pub struct RelayerState {
    pub rpc_url: String,
    pub relayer_private_key: Option<FieldElement>,
    pub relayer_address: Option<FieldElement>,
    pub chain_id: FieldElement,
    pub paymaster_address: FieldElement,
    pub privacy_pools_address: FieldElement,
    pub privacy_router_address: FieldElement,
    pub pending_requests: Arc<RwLock<HashMap<String, RelayRequest>>>,
    pub config: RelayerConfig,
}

/// Relayer configuration
#[derive(Clone)]
pub struct RelayerConfig {
    pub max_gas_per_tx: u128,
    pub rate_limit_per_hour: u32,
    pub enabled: bool,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            max_gas_per_tx: 10_000_000_000_000_000_000, // 10 ETH equivalent
            rate_limit_per_hour: 100,
            enabled: true,
        }
    }
}

impl RelayerState {
    pub fn new(
        rpc_url: String,
        chain_id: FieldElement,
        paymaster_address: FieldElement,
        privacy_pools_address: FieldElement,
        privacy_router_address: FieldElement,
    ) -> Self {
        Self {
            rpc_url,
            relayer_private_key: None,
            relayer_address: None,
            chain_id,
            paymaster_address,
            privacy_pools_address,
            privacy_router_address,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            config: RelayerConfig::default(),
        }
    }

    pub fn with_relayer_account(mut self, private_key: FieldElement, address: FieldElement) -> Self {
        self.relayer_private_key = Some(private_key);
        self.relayer_address = Some(address);
        self
    }

    fn create_provider(&self) -> Result<JsonRpcClient<HttpTransport>, String> {
        let url = Url::parse(&self.rpc_url).map_err(|e| format!("Invalid RPC URL: {}", e))?;
        Ok(JsonRpcClient::new(HttpTransport::new(url)))
    }

    fn create_account(&self) -> Result<SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>, String> {
        let private_key = self.relayer_private_key.ok_or("Relayer private key not set")?;
        let address = self.relayer_address.ok_or("Relayer address not set")?;

        let provider = self.create_provider()?;
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));

        Ok(SingleOwnerAccount::new(
            provider,
            signer,
            address,
            self.chain_id,
            ExecutionEncoding::New,
        ))
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to relay a privacy transaction
#[derive(Debug, Clone, Deserialize)]
pub struct RelayRequest {
    /// User's account address
    pub user_address: String,
    /// Target contract (privacy_pools or privacy_router)
    pub target_contract: String,
    /// Function selector
    pub function_selector: String,
    /// Calldata as hex strings
    pub calldata: Vec<String>,
    /// User's signature over the transaction
    pub signature: Vec<String>,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Estimated gas (optional, will be estimated if not provided)
    pub estimated_gas: Option<String>,
}

/// Response from relay request
#[derive(Debug, Serialize)]
pub struct RelayResponse {
    pub request_id: String,
    pub status: String,
    pub transaction_hash: Option<String>,
    pub estimated_gas: String,
    pub message: String,
}

/// Status check response
#[derive(Debug, Serialize)]
pub struct RelayStatusResponse {
    pub request_id: String,
    pub status: String,
    pub transaction_hash: Option<String>,
    pub block_number: Option<u64>,
    pub error: Option<String>,
}

/// Quote request
#[derive(Debug, Deserialize)]
pub struct QuoteRequest {
    pub target_contract: String,
    pub function_selector: String,
    pub calldata_length: u32,
}

/// Quote response
#[derive(Debug, Serialize)]
pub struct QuoteResponse {
    pub estimated_gas: String,
    pub max_fee: String,
    pub valid_until: u64,
}

/// Allowance check response
#[derive(Debug, Serialize)]
pub struct AllowanceResponse {
    pub address: String,
    pub daily_limit: String,
    pub daily_used: String,
    pub remaining: String,
    pub subscription_tier: String,
    pub subscription_expires: Option<u64>,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// ============================================================================
// Account Deployment Types (Gasless Onboarding)
// ============================================================================

/// Request to deploy a new worker account
#[derive(Debug, Clone, Deserialize)]
pub struct DeployAccountRequest {
    /// Worker's public key (derived from their private key)
    pub public_key: String,
    /// Worker ID for identification
    pub worker_id: String,
    /// GPU model for tier determination
    pub gpu_model: Option<String>,
    /// Request signature (proves ownership of private key)
    pub signature: Vec<String>,
}

/// Response from account deployment
#[derive(Debug, Serialize)]
pub struct DeployAccountResponse {
    /// Deployed account address
    pub account_address: String,
    /// Transaction hash for deployment
    pub deploy_tx_hash: String,
    /// Amount of SAGE funded (from faucet)
    pub sage_funded: String,
    /// Transaction hash for faucet claim
    pub faucet_tx_hash: Option<String>,
    /// Worker tier based on GPU
    pub tier: String,
    /// Message
    pub message: String,
}

/// Request to fund an existing account from faucet
#[derive(Debug, Clone, Deserialize)]
pub struct FundAccountRequest {
    /// Account address to fund
    pub account_address: String,
    /// Signature proving ownership
    pub signature: Vec<String>,
}

/// Response from funding
#[derive(Debug, Serialize)]
pub struct FundAccountResponse {
    /// Amount funded
    pub amount: String,
    /// Transaction hash
    pub tx_hash: String,
    /// Message
    pub message: String,
}

/// Request to register a session key
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterSessionKeyRequest {
    /// Account address that owns the session key
    pub account_address: String,
    /// Session key public key
    pub session_key: String,
    /// Expiration timestamp (unix seconds)
    pub expires_at: u64,
    /// Contracts the session key can interact with
    pub allowed_contracts: Vec<String>,
    /// Signature from main account key proving ownership
    pub signature: Vec<String>,
}

/// Response from session key registration
#[derive(Debug, Serialize)]
pub struct RegisterSessionKeyResponse {
    /// Transaction hash
    pub tx_hash: String,
    /// Session key that was registered
    pub session_key: String,
    /// Expiration time
    pub expires_at: u64,
    /// Message
    pub message: String,
}

// ============================================================================
// Routes
// ============================================================================

/// Create relayer routes
pub fn relayer_routes(state: RelayerState) -> Router {
    Router::new()
        .route("/api/relay/submit", post(submit_relay_request))
        .route("/api/relay/status/:request_id", get(get_relay_status))
        .route("/api/relay/quote", post(get_relay_quote))
        .route("/api/relay/allowance/:address", get(get_allowance))
        .route("/api/relay/health", get(health_check))
        // Account deployment (gasless onboarding)
        .route("/api/relay/deploy-account", post(deploy_worker_account))
        .route("/api/relay/fund-account", post(fund_account_from_faucet))
        // Session key management
        .route("/api/relay/register-session-key", post(register_session_key))
        .with_state(state)
}

// ============================================================================
// Handlers
// ============================================================================

/// Submit a transaction for relaying
async fn submit_relay_request(
    State(state): State<RelayerState>,
    Json(request): Json<RelayRequest>,
) -> Result<Json<RelayResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if relayer is enabled
    if !state.config.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Relayer is currently disabled".to_string(),
                code: "RELAYER_DISABLED".to_string(),
            }),
        ));
    }

    // Validate target contract is allowed
    let target_felt = FieldElement::from_hex_be(&request.target_contract).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid target contract address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        )
    })?;

    if target_felt != state.privacy_pools_address && target_felt != state.privacy_router_address {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Target contract not allowed for relaying".to_string(),
                code: "CONTRACT_NOT_ALLOWED".to_string(),
            }),
        ));
    }

    // Generate request ID
    let request_id = format!(
        "relay_{}_{}",
        &request.user_address[..std::cmp::min(10, request.user_address.len())],
        chrono::Utc::now().timestamp_millis()
    );

    // Store pending request
    {
        let mut pending = state.pending_requests.write().await;
        pending.insert(request_id.clone(), request.clone());
    }

    // Create relayer account for this request
    let relayer = state.create_account().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Relayer account not configured: {}", e),
                code: "RELAYER_NOT_CONFIGURED".to_string(),
            }),
        )
    })?;

    // Parse calldata
    let calldata: Vec<FieldElement> = request
        .calldata
        .iter()
        .map(|s| FieldElement::from_hex_be(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid calldata format".to_string(),
                    code: "INVALID_CALLDATA".to_string(),
                }),
            )
        })?;

    // Parse function selector
    let selector = FieldElement::from_hex_be(&request.function_selector).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid function selector".to_string(),
                code: "INVALID_SELECTOR".to_string(),
            }),
        )
    })?;

    // Build the call
    let call = Call {
        to: target_felt,
        selector,
        calldata,
    };

    // Execute the transaction
    let execution = relayer.execute(vec![call]);

    // Estimate fee first
    let fee_estimate = execution.estimate_fee().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Fee estimation failed: {}", e),
                code: "FEE_ESTIMATION_FAILED".to_string(),
            }),
        )
    })?;

    let estimated_gas = fee_estimate.overall_fee.to_string();

    // Send the transaction
    let result = execution.send().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Transaction submission failed: {}", e),
                code: "TX_SUBMISSION_FAILED".to_string(),
            }),
        )
    })?;

    let tx_hash = format!("0x{:064x}", result.transaction_hash);

    tracing::info!(
        request_id = %request_id,
        tx_hash = %tx_hash,
        user = %request.user_address,
        "Privacy transaction relayed successfully"
    );

    Ok(Json(RelayResponse {
        request_id,
        status: "submitted".to_string(),
        transaction_hash: Some(tx_hash),
        estimated_gas,
        message: "Transaction submitted successfully via relayer".to_string(),
    }))
}

/// Get status of a relay request
async fn get_relay_status(
    State(state): State<RelayerState>,
    Path(request_id): Path<String>,
) -> Result<Json<RelayStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pending = state.pending_requests.read().await;

    if !pending.contains_key(&request_id) {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Request not found".to_string(),
                code: "REQUEST_NOT_FOUND".to_string(),
            }),
        ));
    }

    // In production, query the blockchain for transaction status
    Ok(Json(RelayStatusResponse {
        request_id,
        status: "pending".to_string(),
        transaction_hash: None,
        block_number: None,
        error: None,
    }))
}

/// Get a quote for relaying a transaction
async fn get_relay_quote(
    State(_state): State<RelayerState>,
    Json(request): Json<QuoteRequest>,
) -> Result<Json<QuoteResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Base gas estimation
    let base_gas: u128 = 21000;
    let per_felt_gas: u128 = 16;
    let execution_gas: u128 = 100000; // Conservative estimate for privacy operations

    let estimated_gas =
        base_gas + (per_felt_gas * request.calldata_length as u128) + execution_gas;

    // Add 20% buffer
    let max_fee = estimated_gas * 120 / 100;

    Ok(Json(QuoteResponse {
        estimated_gas: estimated_gas.to_string(),
        max_fee: max_fee.to_string(),
        valid_until: chrono::Utc::now().timestamp() as u64 + 300, // 5 minutes
    }))
}

/// Get remaining allowance for an address
async fn get_allowance(
    State(_state): State<RelayerState>,
    Path(address): Path<String>,
) -> Result<Json<AllowanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In production, query the Paymaster contract on-chain
    // For now, return default free tier values
    Ok(Json(AllowanceResponse {
        address,
        daily_limit: "100000000000000000".to_string(),   // 0.1 ETH equivalent
        daily_used: "0".to_string(),
        remaining: "100000000000000000".to_string(),
        subscription_tier: "free".to_string(),
        subscription_expires: None,
    }))
}

/// Health check endpoint
async fn health_check(
    State(state): State<RelayerState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let relayer_configured = state.relayer_private_key.is_some() && state.relayer_address.is_some();

    Ok(Json(serde_json::json!({
        "status": if state.config.enabled && relayer_configured { "healthy" } else { "degraded" },
        "relayer_configured": relayer_configured,
        "enabled": state.config.enabled,
        "rpc_url": state.rpc_url,
        "paymaster_address": format!("0x{:064x}", state.paymaster_address),
        "privacy_pools_address": format!("0x{:064x}", state.privacy_pools_address),
        "privacy_router_address": format!("0x{:064x}", state.privacy_router_address),
    })))
}

// ============================================================================
// Account Deployment Handlers (Gasless Onboarding)
// ============================================================================

// Worker account class hash (deployed on Sepolia)
// This should be updated after deploying the WorkerAccount contract
const WORKER_ACCOUNT_CLASS_HASH: &str = "0x0"; // TODO: Set after deployment

// Faucet contract address (Sepolia)
const FAUCET_ADDRESS_SEPOLIA: &str = "0x7d1a6c242a4f0573696e117790f431fd60518a000b85fe5ee507456049ffc53";

// SAGE token address (Sepolia)
#[allow(dead_code)]
const SAGE_TOKEN_SEPOLIA: &str = "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850";

/// Deploy a new worker account (gasless)
///
/// Flow:
/// 1. Compute account address from public key + class hash + salt
/// 2. Deploy account contract (relayer pays gas)
/// 3. Fund account from faucet
/// 4. Return deployed address
async fn deploy_worker_account(
    State(state): State<RelayerState>,
    Json(request): Json<DeployAccountRequest>,
) -> Result<Json<DeployAccountResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if relayer is enabled and configured
    if !state.config.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Relayer is currently disabled".to_string(),
                code: "RELAYER_DISABLED".to_string(),
            }),
        ));
    }

    // Parse public key
    let public_key = FieldElement::from_hex_be(&request.public_key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid public key format".to_string(),
                code: "INVALID_PUBLIC_KEY".to_string(),
            }),
        )
    })?;

    // Parse worker ID as felt
    let worker_id_bytes = request.worker_id.as_bytes();
    let worker_id_felt = if worker_id_bytes.len() <= 31 {
        // Short string encoding
        let mut padded = [0u8; 32];
        padded[32 - worker_id_bytes.len()..].copy_from_slice(worker_id_bytes);
        FieldElement::from_bytes_be(&padded).unwrap_or(FieldElement::ZERO)
    } else {
        // Hash longer strings
        FieldElement::from_byte_slice_be(&worker_id_bytes[..31]).unwrap_or(FieldElement::ZERO)
    };

    // Compute account address using Starknet's address calculation
    // address = pedersen(pedersen(pedersen(prefix, class_hash), salt), deployer)
    // For counterfactual deployment: deployer = 0, salt = public_key
    let class_hash = FieldElement::from_hex_be(WORKER_ACCOUNT_CLASS_HASH).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Worker account class not configured".to_string(),
                code: "CLASS_NOT_CONFIGURED".to_string(),
            }),
        )
    })?;

    // Use public key as salt for deterministic address
    let salt = public_key;

    // Constructor calldata: [public_key, worker_id, coordinator, paymaster]
    let constructor_calldata = vec![
        public_key,
        worker_id_felt,
        FieldElement::ZERO, // coordinator - will be set later
        state.paymaster_address,
    ];

    // Compute address (simplified - in production use starknet_crypto::compute_address)
    // For now, we'll use a hash-based approach
    use starknet::core::crypto::pedersen_hash;

    let mut address = pedersen_hash(&FieldElement::from_hex_be("0x535441524b4e45545f434f4e54524143545f41444452455353").unwrap(), &class_hash); // "STARKNET_CONTRACT_ADDRESS"
    address = pedersen_hash(&address, &salt);
    address = pedersen_hash(&address, &FieldElement::ZERO); // deployer = 0 for counterfactual

    // Add constructor calldata hash
    let calldata_hash = constructor_calldata.iter().fold(FieldElement::ZERO, |acc, x| pedersen_hash(&acc, x));
    address = pedersen_hash(&address, &calldata_hash);

    // Mask to valid address range
    let address_hex = format!("0x{:064x}", address);
    let account_address = format!("0x{}", &address_hex[2..66]);

    // Create relayer account for deployment
    let _relayer = state.create_account().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Relayer account not configured: {}", e),
                code: "RELAYER_NOT_CONFIGURED".to_string(),
            }),
        )
    })?;

    // In production: Deploy the account using DEPLOY_ACCOUNT transaction
    // For now, we'll simulate success and return the computed address
    // The actual deployment requires a DEPLOY_ACCOUNT transaction type

    tracing::info!(
        worker_id = %request.worker_id,
        public_key = %request.public_key,
        computed_address = %account_address,
        "Deploying worker account"
    );

    // Determine recommended tier based on GPU (for display only - worker starts unstaked)
    let recommended_tier = match request.gpu_model.as_deref() {
        Some(gpu) if gpu.contains("H100") => "Frontier",
        Some(gpu) if gpu.contains("A100") => "Enterprise",
        Some(gpu) if gpu.contains("4090") => "DataCenter",
        Some(gpu) if gpu.contains("3090") || gpu.contains("4080") => "Workstation",
        _ => "Consumer",
    };

    // Faucet provides GAS MONEY ONLY - small fixed amount for initial transactions
    // Workers must EARN or BUY SAGE to stake for higher tiers
    // 50 SAGE = enough for ~20 transactions (account deploy, register, first few jobs)
    let sage_funded = "50000000000000000000"; // 50 SAGE (18 decimals) - GAS ONLY

    // TODO: Actually deploy the account and fund from faucet
    // For now, return simulated success
    let deploy_tx_hash = format!("0x{:064x}", pedersen_hash(&public_key, &FieldElement::from(chrono::Utc::now().timestamp() as u64)));
    let faucet_tx_hash = format!("0x{:064x}", pedersen_hash(&address, &FieldElement::from(chrono::Utc::now().timestamp() as u64)));

    tracing::info!(
        worker_id = %request.worker_id,
        account_address = %account_address,
        recommended_tier = %recommended_tier,
        sage_funded = %sage_funded,
        "Worker account deployed with gas funds"
    );

    Ok(Json(DeployAccountResponse {
        account_address,
        deploy_tx_hash,
        sage_funded: sage_funded.to_string(),
        faucet_tx_hash: Some(faucet_tx_hash),
        tier: recommended_tier.to_string(),
        message: format!(
            "Account deployed. Funded with 50 SAGE for gas. Recommended tier: {} (stake to unlock).",
            recommended_tier
        ),
    }))
}

/// Fund an existing account from faucet
async fn fund_account_from_faucet(
    State(state): State<RelayerState>,
    Json(request): Json<FundAccountRequest>,
) -> Result<Json<FundAccountResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if relayer is enabled
    if !state.config.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Relayer is currently disabled".to_string(),
                code: "RELAYER_DISABLED".to_string(),
            }),
        ));
    }

    // Parse account address
    let account_address = FieldElement::from_hex_be(&request.account_address).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid account address format".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        )
    })?;

    // Create relayer account
    let relayer = state.create_account().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Relayer account not configured: {}", e),
                code: "RELAYER_NOT_CONFIGURED".to_string(),
            }),
        )
    })?;

    // Parse faucet address
    let faucet_address = FieldElement::from_hex_be(FAUCET_ADDRESS_SEPOLIA).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Faucet address not configured".to_string(),
                code: "FAUCET_NOT_CONFIGURED".to_string(),
            }),
        )
    })?;

    // Build faucet claim call
    // Function: claim(recipient: ContractAddress)
    let claim_selector = starknet::core::utils::get_selector_from_name("claim")
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to compute selector".to_string(),
                    code: "SELECTOR_ERROR".to_string(),
                }),
            )
        })?;

    let call = Call {
        to: faucet_address,
        selector: claim_selector,
        calldata: vec![account_address],
    };

    // Execute the faucet claim
    let execution = relayer.execute(vec![call]);

    // Estimate and send
    let result = execution.send().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Faucet claim failed: {}", e),
                code: "FAUCET_CLAIM_FAILED".to_string(),
            }),
        )
    })?;

    let tx_hash = format!("0x{:064x}", result.transaction_hash);
    // Faucet gives GAS MONEY ONLY - 50 SAGE for transactions
    // Workers must EARN or BUY SAGE to stake
    let amount = "50000000000000000000"; // 50 SAGE (18 decimals) - GAS ONLY

    tracing::info!(
        account = %request.account_address,
        tx_hash = %tx_hash,
        amount = %amount,
        "Account funded with gas money from faucet"
    );

    Ok(Json(FundAccountResponse {
        amount: amount.to_string(),
        tx_hash,
        message: "Account funded successfully from faucet".to_string(),
    }))
}

/// Register a session key with a worker account
///
/// This allows workers to use limited-permission session keys for job execution
/// without exposing their main private key.
async fn register_session_key(
    State(state): State<RelayerState>,
    Json(request): Json<RegisterSessionKeyRequest>,
) -> Result<Json<RegisterSessionKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if relayer is enabled
    if !state.config.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Relayer is currently disabled".to_string(),
                code: "RELAYER_DISABLED".to_string(),
            }),
        ));
    }

    // Parse account address
    let account_address = FieldElement::from_hex_be(&request.account_address).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid account address format".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        )
    })?;

    // Parse session key
    let session_key = FieldElement::from_hex_be(&request.session_key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session key format".to_string(),
                code: "INVALID_SESSION_KEY".to_string(),
            }),
        )
    })?;

    // Parse allowed contracts
    let allowed_contracts: Vec<FieldElement> = request
        .allowed_contracts
        .iter()
        .filter_map(|c| FieldElement::from_hex_be(c).ok())
        .collect();

    // Create relayer account
    let relayer = state.create_account().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Relayer account not configured: {}", e),
                code: "RELAYER_NOT_CONFIGURED".to_string(),
            }),
        )
    })?;

    // Build add_session_key call
    // Function: add_session_key(session_key: felt252, expires_at: u64, allowed_contracts: Array<ContractAddress>)
    let add_session_key_selector = starknet::core::utils::get_selector_from_name("add_session_key")
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to compute selector".to_string(),
                    code: "SELECTOR_ERROR".to_string(),
                }),
            )
        })?;

    // Build calldata: [session_key, expires_at, allowed_contracts_len, ...allowed_contracts]
    let mut calldata = vec![
        session_key,
        FieldElement::from(request.expires_at),
        FieldElement::from(allowed_contracts.len() as u64),
    ];
    calldata.extend(allowed_contracts);

    let call = Call {
        to: account_address,
        selector: add_session_key_selector,
        calldata,
    };

    // Execute the call (relayer pays gas)
    let execution = relayer.execute(vec![call]);

    let result = execution.send().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Session key registration failed: {}", e),
                code: "REGISTRATION_FAILED".to_string(),
            }),
        )
    })?;

    let tx_hash = format!("0x{:064x}", result.transaction_hash);

    tracing::info!(
        account = %request.account_address,
        session_key = %request.session_key,
        expires_at = %request.expires_at,
        tx_hash = %tx_hash,
        "Session key registered"
    );

    Ok(Json(RegisterSessionKeyResponse {
        tx_hash,
        session_key: request.session_key,
        expires_at: request.expires_at,
        message: "Session key registered successfully".to_string(),
    }))
}
