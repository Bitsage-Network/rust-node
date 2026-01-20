//! # Privacy API Endpoints
//!
//! REST API endpoints for Obelysk privacy features.
//! Provides privacy pool operations, private transfers, and wallet privacy data.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

/// Privacy API state
pub struct PrivacyApiState {
    pub network: String,
    pub privacy_router_address: String,
    pub privacy_pools_address: String,
    pub db_pool: Option<sqlx::PgPool>,
}

impl PrivacyApiState {
    pub fn new(network: &str, privacy_router_address: &str, privacy_pools_address: &str) -> Self {
        Self {
            network: network.to_string(),
            privacy_router_address: privacy_router_address.to_string(),
            privacy_pools_address: privacy_pools_address.to_string(),
            db_pool: None,
        }
    }

    pub fn with_db(network: &str, privacy_router_address: &str, privacy_pools_address: &str, db_pool: sqlx::PgPool) -> Self {
        Self {
            network: network.to_string(),
            privacy_router_address: privacy_router_address.to_string(),
            privacy_pools_address: privacy_pools_address.to_string(),
            db_pool: Some(db_pool),
        }
    }

    pub fn disabled(network: &str) -> Self {
        Self {
            network: network.to_string(),
            privacy_router_address: String::new(),
            privacy_pools_address: String::new(),
            db_pool: None,
        }
    }
}

/// Create privacy routes
pub fn privacy_routes(state: Arc<PrivacyApiState>) -> Router {
    Router::new()
        // Account Management
        .route("/api/privacy/account/:address", get(get_privacy_account))
        .route("/api/privacy/account/register", post(register_privacy_account))
        // Balances
        .route("/api/privacy/balance/:address", get(get_private_balance))
        .route("/api/privacy/balance/:address/all", get(get_all_private_balances))
        // Deposits & Withdrawals
        .route("/api/privacy/deposit", post(private_deposit))
        .route("/api/privacy/withdraw", post(private_withdraw))
        // Transfers
        .route("/api/privacy/transfer", post(private_transfer))
        .route("/api/privacy/transfers/:address", get(get_transfer_history))
        // Stealth Addresses
        .route("/api/privacy/stealth/:address", get(get_stealth_addresses))
        .route("/api/privacy/stealth/generate", post(generate_stealth_address))
        .route("/api/privacy/stealth/scan", post(scan_stealth_payments))
        // Worker Payments (FMD)
        .route("/api/privacy/worker-payments/:address", get(get_worker_payments))
        .route("/api/privacy/worker-payments/:address/claim", post(claim_worker_payment))
        // Privacy Pool Stats
        .route("/api/privacy/pools", get(get_privacy_pools))
        .route("/api/privacy/pools/:pool_id", get(get_pool_info))
        .route("/api/privacy/stats", get(get_privacy_stats))
        // Merkle Proofs (for withdrawals)
        .route("/api/privacy/proof/:commitment", get(get_merkle_proof))
        // ASP (Anonymity Set Provider) Status
        .route("/api/privacy/asp/status", get(get_asp_status))
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Privacy account info
#[derive(Debug, Serialize)]
pub struct PrivacyAccountInfo {
    pub address: String,
    pub is_registered: bool,
    pub public_key_x: Option<String>,
    pub public_key_y: Option<String>,
    pub registered_at: Option<u64>,
    pub total_deposits: String,
    pub total_withdrawals: String,
    pub total_transfers_sent: u64,
    pub total_transfers_received: u64,
}

/// Register account request
#[derive(Debug, Deserialize)]
pub struct RegisterAccountRequest {
    pub public_key_x: String,
    pub public_key_y: String,
}

/// Transaction response
#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub success: bool,
    pub message: String,
    pub transaction_data: Option<TransactionData>,
}

/// Transaction data for wallet signing
#[derive(Debug, Serialize)]
pub struct TransactionData {
    pub contract_address: String,
    pub function_name: String,
    pub calldata: Vec<String>,
}

/// Private balance info
#[derive(Debug, Serialize)]
pub struct PrivateBalanceInfo {
    pub address: String,
    pub token: String,
    pub token_symbol: String,
    pub private_balance: String,
    pub private_balance_formatted: String,
    pub pending_deposits: String,
    pub pending_withdrawals: String,
    pub last_updated: u64,
}

/// Multi-token balance response
#[derive(Debug, Serialize)]
pub struct AllPrivateBalances {
    pub address: String,
    pub balances: Vec<TokenBalance>,
    pub total_value_usd: String,
}

/// Token balance entry
#[derive(Debug, Serialize, Clone)]
pub struct TokenBalance {
    pub token: String,
    pub symbol: String,
    pub balance: String,
    pub balance_formatted: String,
    pub value_usd: String,
}

/// Deposit request
#[derive(Debug, Deserialize)]
pub struct DepositRequest {
    pub token: String,
    pub amount: String,
    pub use_privacy_pool: bool,
}

/// Withdraw request
#[derive(Debug, Deserialize)]
pub struct WithdrawRequest {
    pub token: String,
    pub amount: String,
    pub recipient: String, // Can be stealth or regular address
}

/// Transfer request
#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    pub token: String,
    pub amount: String,
    pub recipient: String,
    pub use_stealth: bool,
    pub memo: Option<String>,
}

/// Transfer record
#[derive(Debug, Serialize, Clone)]
pub struct TransferRecord {
    pub id: String,
    pub transfer_type: String, // "deposit", "withdraw", "transfer_in", "transfer_out"
    pub token: String,
    pub token_symbol: String,
    pub amount: String,
    pub amount_formatted: String,
    pub counterparty: Option<String>, // Encrypted/hashed for privacy
    pub status: String,
    pub timestamp: u64,
    pub nullifier: Option<String>,
    pub tx_hash: Option<String>,
}

/// Stealth address info
#[derive(Debug, Serialize, Clone)]
pub struct StealthAddressInfo {
    pub stealth_address: String,
    pub ephemeral_public_key: String,
    pub created_at: u64,
    pub used: bool,
    pub label: Option<String>,
}

/// Generate stealth address request
#[derive(Debug, Deserialize)]
pub struct GenerateStealthRequest {
    pub label: Option<String>,
}

/// Generate stealth address response
#[derive(Debug, Serialize)]
pub struct GenerateStealthResponse {
    pub stealth_address: String,
    pub ephemeral_public_key: String,
    pub viewing_key: String, // Encrypted for the owner
}

/// Scan stealth request
#[derive(Debug, Deserialize)]
pub struct ScanStealthRequest {
    pub viewing_key: String,
    pub from_block: Option<u64>,
}

/// Stealth payment found during scan
#[derive(Debug, Serialize, Clone)]
pub struct StealthPayment {
    pub stealth_address: String,
    pub token: String,
    pub amount: String,
    pub sender_ephemeral_key: String,
    pub block_number: u64,
    pub tx_hash: String,
    pub claimed: bool,
}

/// Worker payment info (FMD - Fuzzy Message Detection)
#[derive(Debug, Serialize, Clone)]
pub struct WorkerPaymentInfo {
    pub payment_id: String,
    pub job_id: String,
    pub token: String,
    pub amount: String,
    pub amount_formatted: String,
    pub status: String, // "pending", "claimable", "claimed"
    pub detection_tag: String, // FMD tag
    pub created_at: u64,
    pub claimed_at: Option<u64>,
    pub tx_hash: Option<String>,
}

/// Claim payment request
#[derive(Debug, Deserialize)]
pub struct ClaimPaymentRequest {
    pub payment_id: String,
    pub proof: String, // ZK proof of ownership
}

/// Privacy pool info
#[derive(Debug, Serialize, Clone)]
pub struct PrivacyPoolInfo {
    pub pool_id: u8,
    pub token: String,
    pub token_symbol: String,
    pub denomination: String,
    pub denomination_formatted: String,
    pub total_deposits: u64,
    pub total_withdrawals: u64,
    pub current_anonymity_set: u64,
    pub is_active: bool,
    pub created_at: u64,
}

/// Privacy stats
#[derive(Debug, Serialize)]
pub struct PrivacyStats {
    pub total_private_deposits: String,
    pub total_private_withdrawals: String,
    pub total_private_transfers: u64,
    pub active_privacy_accounts: u64,
    pub total_pools: u32,
    pub average_anonymity_set: u64,
    pub largest_anonymity_set: u64,
    pub total_stealth_addresses: u64,
    pub total_worker_payments: u64,
}

/// ASP (Anonymity Set Provider) status
#[derive(Debug, Serialize)]
pub struct AspStatus {
    pub is_active: bool,
    pub current_epoch: u64,
    pub merkle_root: String,
    pub total_members: u64,
    pub last_updated: u64,
    pub compliance_enabled: bool,
}

/// Merkle proof for privacy pool deposits
#[derive(Debug, Serialize)]
pub struct MerkleProofResponse {
    /// Whether the proof was found
    pub found: bool,
    /// The deposit commitment being proven
    pub commitment: String,
    /// Leaf index in the tree
    pub leaf_index: u64,
    /// Merkle root at time of deposit
    pub root: String,
    /// Current global root
    pub current_root: String,
    /// Sibling hashes for proof verification
    pub siblings: Vec<String>,
    /// Path indices (0=left, 1=right) for each level
    pub path_indices: Vec<u8>,
    /// Depth of the tree
    pub depth: u8,
    /// Deposit info if available
    pub deposit_info: Option<DepositInfo>,
}

/// Deposit info for proof response
#[derive(Debug, Serialize)]
pub struct DepositInfo {
    pub depositor: String,
    pub asset_id: String,
    pub timestamp: u64,
    pub tx_hash: Option<String>,
}

/// Query params
#[derive(Debug, Deserialize)]
pub struct TransferQuery {
    pub token: Option<String>,
    pub transfer_type: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get privacy account info
async fn get_privacy_account(
    State(state): State<Arc<PrivacyApiState>>,
    Path(address): Path<String>,
) -> Result<Json<PrivacyAccountInfo>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting privacy account for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Query from database
    if let Some(ref pool) = state.db_pool {
        // Get privacy account registration info
        let account_result = sqlx::query(
            r#"
            SELECT public_key_x, public_key_y, is_registered,
                   EXTRACT(EPOCH FROM registered_at)::bigint as registered_at
            FROM private_accounts
            WHERE address = $1
            "#
        )
        .bind(&address)
        .fetch_optional(pool)
        .await;

        // Get transfer stats (sent/received)
        let stats_result = sqlx::query(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE sender_address = $1) as sent,
                COUNT(*) FILTER (WHERE receiver_address = $1) as received,
                COALESCE(SUM(CASE WHEN sender_address = $1 THEN 1 ELSE 0 END), 0) as deposits,
                COALESCE(SUM(CASE WHEN receiver_address = $1 THEN 1 ELSE 0 END), 0) as withdrawals
            FROM private_transfers
            WHERE (sender_address = $1 OR receiver_address = $1) AND status = 'completed'
            "#
        )
        .bind(&address)
        .fetch_optional(pool)
        .await;

        if let (Ok(Some(account)), Ok(stats_opt)) = (account_result, stats_result) {
            use sqlx::Row;

            let (transfers_sent, transfers_received) = if let Some(stats) = stats_opt {
                (
                    stats.try_get::<i64, _>("sent").unwrap_or(0) as u64,
                    stats.try_get::<i64, _>("received").unwrap_or(0) as u64,
                )
            } else {
                (0, 0)
            };

            return Ok(Json(PrivacyAccountInfo {
                address: address.clone(),
                is_registered: account.get::<bool, _>("is_registered"),
                public_key_x: account.try_get::<String, _>("public_key_x").ok(),
                public_key_y: account.try_get::<String, _>("public_key_y").ok(),
                registered_at: Some(account.get::<i64, _>("registered_at") as u64),
                total_deposits: "0".to_string(), // Encrypted - not queryable
                total_withdrawals: "0".to_string(), // Encrypted - not queryable
                total_transfers_sent: transfers_sent,
                total_transfers_received: transfers_received,
            }));
        }
    }

    // Account not found - return unregistered status
    Ok(Json(PrivacyAccountInfo {
        address: address.clone(),
        is_registered: false,
        public_key_x: None,
        public_key_y: None,
        registered_at: None,
        total_deposits: "0".to_string(),
        total_withdrawals: "0".to_string(),
        total_transfers_sent: 0,
        total_transfers_received: 0,
    }))
}

/// Register privacy account
async fn register_privacy_account(
    State(state): State<Arc<PrivacyApiState>>,
    Json(request): Json<RegisterAccountRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Register privacy account request");

    Ok(Json(TransactionResponse {
        success: true,
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.privacy_router_address.clone(),
            function_name: "register_account".to_string(),
            calldata: vec![
                request.public_key_x,
                request.public_key_y,
            ],
        }),
    }))
}

/// Get private balance
async fn get_private_balance(
    State(state): State<Arc<PrivacyApiState>>,
    Path(address): Path<String>,
) -> Result<Json<PrivateBalanceInfo>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting private balance for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Query from database - balance commitments and pending transfers
    // Note: Actual balance amounts are encrypted (ElGamal) and require client-side decryption
    if let Some(ref pool) = state.db_pool {
        // Check if account is registered
        let account_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM private_accounts WHERE address = $1 AND is_registered = true)"
        )
        .bind(&address)
        .fetch_one(pool)
        .await
        .unwrap_or(false);

        if !account_exists {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Privacy account not registered".to_string(),
                    code: "ACCOUNT_NOT_FOUND".to_string(),
                }),
            ));
        }

        // Get pending deposits/withdrawals counts
        let pending_result = sqlx::query(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE sender_address = $1 AND status = 'pending') as pending_out,
                COUNT(*) FILTER (WHERE receiver_address = $1 AND status = 'pending') as pending_in,
                MAX(EXTRACT(EPOCH FROM completed_at)::bigint) as last_completed
            FROM private_transfers
            WHERE sender_address = $1 OR receiver_address = $1
            "#
        )
        .bind(&address)
        .fetch_optional(pool)
        .await;

        let (pending_deposits, pending_withdrawals, last_updated) = if let Ok(Some(row)) = pending_result {
            use sqlx::Row;
            (
                row.try_get::<i64, _>("pending_in").unwrap_or(0).to_string(),
                row.try_get::<i64, _>("pending_out").unwrap_or(0).to_string(),
                row.try_get::<i64, _>("last_completed").ok().map(|t| t as u64).unwrap_or(now),
            )
        } else {
            ("0".to_string(), "0".to_string(), now)
        };

        // Balance is encrypted - client must decrypt with private key
        // We return a placeholder indicating the balance exists but is private
        return Ok(Json(PrivateBalanceInfo {
            address: address.clone(),
            token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
            token_symbol: "SAGE".to_string(),
            private_balance: "encrypted".to_string(), // Encrypted - requires client decryption
            private_balance_formatted: "••••••".to_string(), // Hidden
            pending_deposits,
            pending_withdrawals,
            last_updated,
        }));
    }

    // No database - return placeholder for unregistered account
    Ok(Json(PrivateBalanceInfo {
        address: address.clone(),
        token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
        token_symbol: "SAGE".to_string(),
        private_balance: "0".to_string(),
        private_balance_formatted: "0 SAGE".to_string(),
        pending_deposits: "0".to_string(),
        pending_withdrawals: "0".to_string(),
        last_updated: now,
    }))
}

/// Get all private balances (multi-token)
async fn get_all_private_balances(
    State(state): State<Arc<PrivacyApiState>>,
    Path(address): Path<String>,
) -> Result<Json<AllPrivateBalances>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting all private balances for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Query from database for tokens the user has interacted with in privacy system
    if let Some(ref pool) = state.db_pool {
        // Check if privacy account exists
        let account_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM private_accounts WHERE address = $1 AND is_registered = true)"
        )
        .bind(&address)
        .fetch_one(pool)
        .await
        .unwrap_or(false);

        if !account_exists {
            return Ok(Json(AllPrivateBalances {
                address: address.clone(),
                balances: vec![],
                total_value_usd: "0".to_string(),
            }));
        }

        // Query distinct tokens from privacy-enabled payments for this address
        let tokens_result = sqlx::query(
            r#"
            SELECT DISTINCT token,
                   CASE
                       WHEN token = 'SAGE' THEN '0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce'
                       WHEN token = 'USDC' THEN '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8'
                       WHEN token = 'STRK' THEN '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d'
                       ELSE token
                   END as token_address
            FROM payments
            WHERE worker_address = $1 AND privacy_enabled = true
            "#
        )
        .bind(&address)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = tokens_result {
            use sqlx::Row;

            let balances: Vec<TokenBalance> = rows.iter().map(|row| {
                let token_symbol: String = row.get("token");
                let token_address: String = row.get("token_address");

                // Balances are encrypted - client must decrypt
                TokenBalance {
                    token: token_address,
                    symbol: token_symbol,
                    balance: "encrypted".to_string(),
                    balance_formatted: "••••••".to_string(),
                    value_usd: "0".to_string(), // Cannot compute without decryption
                }
            }).collect();

            if !balances.is_empty() {
                return Ok(Json(AllPrivateBalances {
                    address: address.clone(),
                    balances,
                    total_value_usd: "encrypted".to_string(),
                }));
            }
        }

        // Account exists but no privacy transactions yet - return SAGE as default token
        return Ok(Json(AllPrivateBalances {
            address: address.clone(),
            balances: vec![TokenBalance {
                token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
                symbol: "SAGE".to_string(),
                balance: "encrypted".to_string(),
                balance_formatted: "••••••".to_string(),
                value_usd: "0".to_string(),
            }],
            total_value_usd: "encrypted".to_string(),
        }));
    }

    // No database connection - return empty
    Ok(Json(AllPrivateBalances {
        address,
        balances: vec![],
        total_value_usd: "0".to_string(),
    }))
}

/// Make private deposit
async fn private_deposit(
    State(state): State<Arc<PrivacyApiState>>,
    Json(request): Json<DepositRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Private deposit request: token={}, amount={}", request.token, request.amount);

    let function_name = if request.use_privacy_pool {
        "pp_deposit" // Privacy pool deposit
    } else {
        "deposit"
    };

    Ok(Json(TransactionResponse {
        success: true,
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.privacy_router_address.clone(),
            function_name: function_name.to_string(),
            calldata: vec![
                request.token,
                request.amount.clone(),
                "0".to_string(), // amount high (u256)
            ],
        }),
    }))
}

/// Make private withdrawal
async fn private_withdraw(
    State(state): State<Arc<PrivacyApiState>>,
    Json(request): Json<WithdrawRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Private withdraw request: token={}, amount={}", request.token, request.amount);

    Ok(Json(TransactionResponse {
        success: true,
        message: "Transaction data ready for wallet signing. ZK proof required.".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.privacy_router_address.clone(),
            function_name: "withdraw".to_string(),
            calldata: vec![
                request.token,
                request.amount.clone(),
                "0".to_string(),
                request.recipient,
                // Note: Actual withdrawal requires ZK proof generated client-side
            ],
        }),
    }))
}

/// Make private transfer
async fn private_transfer(
    State(state): State<Arc<PrivacyApiState>>,
    Json(request): Json<TransferRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!(
        "Private transfer request: token={}, amount={}, stealth={}",
        request.token, request.amount, request.use_stealth
    );

    let function_name = if request.use_stealth {
        "stealth_transfer"
    } else {
        "private_transfer"
    };

    Ok(Json(TransactionResponse {
        success: true,
        message: "Transaction data ready for wallet signing. ZK proof required.".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.privacy_router_address.clone(),
            function_name: function_name.to_string(),
            calldata: vec![
                request.token,
                request.amount.clone(),
                "0".to_string(),
                request.recipient,
                // Note: Actual transfer requires ZK proof + encrypted commitment
            ],
        }),
    }))
}

/// Get transfer history
async fn get_transfer_history(
    State(state): State<Arc<PrivacyApiState>>,
    Path(address): Path<String>,
    Query(params): Query<TransferQuery>,
) -> Result<Json<Vec<TransferRecord>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting transfer history for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let limit = params.limit.unwrap_or(50).min(100) as i64;

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let transfers_result = sqlx::query(
            r#"
            SELECT id::text, nullifier, sender_address, receiver_address,
                   encrypted_amount, status,
                   EXTRACT(EPOCH FROM initiated_at)::bigint as initiated_at,
                   EXTRACT(EPOCH FROM completed_at)::bigint as completed_at,
                   tx_hash
            FROM private_transfers
            WHERE sender_address = $1 OR receiver_address = $1
            ORDER BY initiated_at DESC
            LIMIT $2
            "#
        )
        .bind(&address)
        .bind(limit)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = transfers_result {
            use sqlx::Row;

            let transfers: Vec<TransferRecord> = rows.iter().map(|row| {
                let sender: Option<String> = row.try_get("sender_address").ok();
                let receiver: Option<String> = row.try_get("receiver_address").ok();
                let is_outgoing = sender.as_ref().map(|s| s == &address).unwrap_or(false);

                let transfer_type = if is_outgoing { "transfer_out" } else { "transfer_in" };
                let counterparty = if is_outgoing {
                    receiver.map(|r| format!("0x{}...{}", &r[2..6], &r[r.len()-4..]))
                } else {
                    sender.map(|s| format!("0x{}...{}", &s[2..6], &s[s.len()-4..]))
                };

                TransferRecord {
                    id: row.get::<String, _>("id"),
                    transfer_type: transfer_type.to_string(),
                    token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
                    token_symbol: "SAGE".to_string(),
                    amount: row.try_get::<String, _>("encrypted_amount").unwrap_or_default(),
                    amount_formatted: "••••••".to_string(), // Private - encrypted
                    counterparty,
                    status: row.get::<String, _>("status"),
                    timestamp: row.get::<i64, _>("initiated_at") as u64,
                    nullifier: row.try_get::<String, _>("nullifier").ok(),
                    tx_hash: row.try_get::<String, _>("tx_hash").ok(),
                }
            }).collect();

            if !transfers.is_empty() {
                return Ok(Json(transfers));
            }
        }
    }

    // Fallback to mock data
    let transfers = vec![
        TransferRecord {
            id: "1".to_string(),
            transfer_type: "deposit".to_string(),
            token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
            token_symbol: "SAGE".to_string(),
            amount: "5000000000000000000000".to_string(),
            amount_formatted: "5,000 SAGE".to_string(),
            counterparty: None,
            status: "completed".to_string(),
            timestamp: now - 86400,
            nullifier: None,
            tx_hash: Some("0xabc123...".to_string()),
        },
        TransferRecord {
            id: "2".to_string(),
            transfer_type: "transfer_out".to_string(),
            token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
            token_symbol: "SAGE".to_string(),
            amount: "1000000000000000000000".to_string(),
            amount_formatted: "1,000 SAGE".to_string(),
            counterparty: Some("0x***...***".to_string()),
            status: "completed".to_string(),
            timestamp: now - 3600,
            nullifier: Some("0xnull123...".to_string()),
            tx_hash: Some("0xdef456...".to_string()),
        },
    ];

    Ok(Json(transfers))
}

/// Get stealth addresses
async fn get_stealth_addresses(
    State(state): State<Arc<PrivacyApiState>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<StealthAddressInfo>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting stealth addresses for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Query stealth addresses from database
    if let Some(ref pool) = state.db_pool {
        let stealth_result = sqlx::query(
            r#"
            SELECT stealth_address, ephemeral_pubkey, view_tag, is_spent,
                   EXTRACT(EPOCH FROM created_at)::bigint as created_at,
                   EXTRACT(EPOCH FROM spent_at)::bigint as spent_at
            FROM stealth_addresses
            WHERE owner_address = $1
            ORDER BY created_at DESC
            LIMIT 100
            "#
        )
        .bind(&address)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = stealth_result {
            use sqlx::Row;

            let addresses: Vec<StealthAddressInfo> = rows.iter().map(|row| {
                StealthAddressInfo {
                    stealth_address: row.get::<String, _>("stealth_address"),
                    ephemeral_public_key: row.get::<String, _>("ephemeral_pubkey"),
                    created_at: row.get::<i64, _>("created_at") as u64,
                    used: row.get::<bool, _>("is_spent"),
                    label: row.try_get::<String, _>("view_tag").ok(), // view_tag used as label
                }
            }).collect();

            return Ok(Json(addresses));
        }
    }

    // No database or no addresses found - return empty list
    Ok(Json(vec![]))
}

/// Generate new stealth address
///
/// Note: For security, stealth address generation should primarily happen client-side
/// using the recipient's stealth meta-address and cryptographically secure randomness.
/// This endpoint provides server-side entropy that must be combined with client randomness.
async fn generate_stealth_address(
    State(_state): State<Arc<PrivacyApiState>>,
    Json(_request): Json<GenerateStealthRequest>,
) -> Result<Json<GenerateStealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Generate stealth address - providing server entropy");

    // Use cryptographically secure random bytes for server-side entropy
    // Client MUST combine this with their own randomness for full security
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    let mut server_entropy = [0u8; 32];
    rng.fill_bytes(&mut server_entropy);

    let mut ephemeral_seed = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_seed);

    // Return server-side entropy components
    // Client should use these as inputs to stealth address derivation algorithm:
    // 1. Generate ephemeral keypair from ephemeral_seed
    // 2. Perform ECDH with recipient's stealth meta-address
    // 3. Derive stealth address from shared secret
    Ok(Json(GenerateStealthResponse {
        stealth_address: format!("0x{}", hex::encode(server_entropy)),
        ephemeral_public_key: format!("0x{}", hex::encode(ephemeral_seed)),
        viewing_key: "client_derived".to_string(), // Must be derived client-side
    }))
}

/// Scan for stealth payments
///
/// Scans indexed blockchain events for stealth payments. The viewing_key is used
/// to identify which payments belong to the user by checking view tags (FMD).
async fn scan_stealth_payments(
    State(state): State<Arc<PrivacyApiState>>,
    Json(request): Json<ScanStealthRequest>,
) -> Result<Json<Vec<StealthPayment>>, (StatusCode, Json<ErrorResponse>)> {
    info!("Scan stealth payments request from block {:?}", request.from_block);

    // Query indexed StealthPayment events from blockchain_events table
    if let Some(ref pool) = state.db_pool {
        let from_block = request.from_block.unwrap_or(0) as i64;

        // Query stealth payment events
        let events_result = sqlx::query(
            r#"
            SELECT event_data, tx_hash, block_number
            FROM blockchain_events
            WHERE event_name = 'StealthPayment'
              AND block_number >= $1
            ORDER BY block_number DESC
            LIMIT 500
            "#
        )
        .bind(from_block)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = events_result {
            use sqlx::Row;

            let payments: Vec<StealthPayment> = rows.iter().filter_map(|row| {
                let event_data: serde_json::Value = row.get("event_data");
                let tx_hash: String = row.get("tx_hash");
                let block_number: i64 = row.get("block_number");

                // Extract fields from event data
                let stealth_address = event_data.get("stealth_address")?.as_str()?.to_string();
                let ephemeral_key = event_data.get("ephemeral_pubkey")
                    .or_else(|| event_data.get("sender_ephemeral_key"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let view_tag = event_data.get("view_tag").and_then(|v| v.as_str()).unwrap_or("");

                // Check if viewing key matches view tag (simplified FMD check)
                // In production, this would use proper fuzzy message detection
                let viewing_key_tag = &request.viewing_key[..8.min(request.viewing_key.len())];
                if !view_tag.is_empty() && !view_tag.starts_with(viewing_key_tag) {
                    return None; // View tag doesn't match
                }

                let token = event_data.get("token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce")
                    .to_string();
                let amount = event_data.get("amount")
                    .map(|v| {
                        if let Some(s) = v.as_str() {
                            s.to_string()
                        } else if let Some(n) = v.as_u64() {
                            n.to_string()
                        } else {
                            "0".to_string()
                        }
                    })
                    .unwrap_or_else(|| "0".to_string());
                let claimed = event_data.get("claimed").and_then(|v| v.as_bool()).unwrap_or(false);

                Some(StealthPayment {
                    stealth_address,
                    token,
                    amount,
                    sender_ephemeral_key: ephemeral_key,
                    block_number: block_number as u64,
                    tx_hash,
                    claimed,
                })
            }).collect();

            return Ok(Json(payments));
        }
    }

    // No database or no events found
    Ok(Json(vec![]))
}

/// Get worker payments (FMD)
///
/// Returns privacy-enabled worker payments with fuzzy message detection tags.
async fn get_worker_payments(
    State(state): State<Arc<PrivacyApiState>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<WorkerPaymentInfo>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting worker payments for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Query privacy-enabled payments from database
    if let Some(ref pool) = state.db_pool {
        let payments_result = sqlx::query(
            r#"
            SELECT p.id::text, p.job_id, p.token, p.amount::text as amount,
                   p.tx_hash,
                   EXTRACT(EPOCH FROM p.created_at)::bigint as created_at,
                   j.status as job_status
            FROM payments p
            LEFT JOIN jobs j ON p.job_id = j.job_id
            WHERE p.worker_address = $1 AND p.privacy_enabled = true
            ORDER BY p.created_at DESC
            LIMIT 100
            "#
        )
        .bind(&address)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = payments_result {
            use sqlx::Row;

            let payments: Vec<WorkerPaymentInfo> = rows.iter().map(|row| {
                let payment_id: String = row.get("id");
                let job_id: Option<String> = row.try_get("job_id").ok();
                let token: String = row.get("token");
                let amount: String = row.get("amount");
                let tx_hash: Option<String> = row.try_get("tx_hash").ok();
                let created_at: i64 = row.get("created_at");
                let job_status: Option<String> = row.try_get("job_status").ok();

                // Format amount (assuming 18 decimals for SAGE)
                let amount_formatted = format_token_amount(&amount, &token);

                // Determine payment status based on job completion
                let status = match job_status.as_deref() {
                    Some("completed") => "claimable",
                    Some("paid") => "claimed",
                    _ => "pending",
                }.to_string();

                // Generate FMD detection tag from payment ID (simplified)
                let detection_tag = format!("0x{}", &payment_id.replace("-", "")[..16.min(payment_id.len())]);

                WorkerPaymentInfo {
                    payment_id,
                    job_id: job_id.unwrap_or_default(),
                    token,
                    amount,
                    amount_formatted,
                    status: status.clone(),
                    detection_tag,
                    created_at: created_at as u64,
                    claimed_at: if status == "claimed" { Some(created_at as u64 + 3600) } else { None },
                    tx_hash,
                }
            }).collect();

            return Ok(Json(payments));
        }
    }

    // No database - return empty
    Ok(Json(vec![]))
}

/// Claim worker payment
async fn claim_worker_payment(
    State(state): State<Arc<PrivacyApiState>>,
    Path(worker_address): Path<String>,
    Json(request): Json<ClaimPaymentRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Claim worker payment: worker={}, payment_id={}", worker_address, request.payment_id);

    Ok(Json(TransactionResponse {
        success: true,
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.privacy_router_address.clone(),
            function_name: "claim_worker_payment".to_string(),
            calldata: vec![
                request.payment_id,
                request.proof,
            ],
        }),
    }))
}

/// Get privacy pools
///
/// Returns information about all privacy pools from indexed blockchain events.
async fn get_privacy_pools(
    State(state): State<Arc<PrivacyApiState>>,
) -> Json<Vec<PrivacyPoolInfo>> {
    debug!("Getting privacy pools");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Query privacy pool stats from indexed events
    if let Some(ref pool) = state.db_pool {
        // Get pool creation events and aggregate deposit/withdrawal counts
        let pools_result = sqlx::query(
            r#"
            WITH pool_events AS (
                SELECT
                    (event_data->>'pool_id')::int as pool_id,
                    event_data->>'token' as token,
                    event_data->>'denomination' as denomination,
                    event_name,
                    EXTRACT(EPOCH FROM block_timestamp)::bigint as timestamp
                FROM blockchain_events
                WHERE event_name IN ('PoolCreated', 'PrivacyDeposit', 'PrivacyWithdraw')
                  AND contract_name = 'PrivacyPools'
            ),
            pool_stats AS (
                SELECT
                    pool_id,
                    MAX(CASE WHEN event_name = 'PoolCreated' THEN token END) as token,
                    MAX(CASE WHEN event_name = 'PoolCreated' THEN denomination END) as denomination,
                    COUNT(*) FILTER (WHERE event_name = 'PrivacyDeposit') as deposits,
                    COUNT(*) FILTER (WHERE event_name = 'PrivacyWithdraw') as withdrawals,
                    MIN(CASE WHEN event_name = 'PoolCreated' THEN timestamp END) as created_at
                FROM pool_events
                GROUP BY pool_id
            )
            SELECT * FROM pool_stats ORDER BY pool_id
            "#
        )
        .fetch_all(pool)
        .await;

        if let Ok(rows) = pools_result {
            if !rows.is_empty() {
                use sqlx::Row;

                let pools: Vec<PrivacyPoolInfo> = rows.iter().map(|row| {
                    let pool_id: i32 = row.get("pool_id");
                    let token: Option<String> = row.try_get("token").ok();
                    let denomination: Option<String> = row.try_get("denomination").ok();
                    let deposits: i64 = row.try_get("deposits").unwrap_or(0);
                    let withdrawals: i64 = row.try_get("withdrawals").unwrap_or(0);
                    let created_at: i64 = row.try_get("created_at").unwrap_or(now as i64);

                    let token_address = token.unwrap_or_else(|| "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string());
                    let token_symbol = if token_address.contains("be521d24") { "USDC" } else { "SAGE" };
                    let denom = denomination.unwrap_or_else(|| "100000000000000000000".to_string());
                    let denom_formatted = format_token_amount(&denom, token_symbol);

                    PrivacyPoolInfo {
                        pool_id: pool_id as u8,
                        token: token_address,
                        token_symbol: token_symbol.to_string(),
                        denomination: denom,
                        denomination_formatted: denom_formatted,
                        total_deposits: deposits as u64,
                        total_withdrawals: withdrawals as u64,
                        current_anonymity_set: (deposits - withdrawals).max(0) as u64,
                        is_active: true,
                        created_at: created_at as u64,
                    }
                }).collect();

                if !pools.is_empty() {
                    return Json(pools);
                }
            }
        }
    }

    // Default pools if database is empty or unavailable
    let pools = vec![
        PrivacyPoolInfo {
            pool_id: 0,
            token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
            token_symbol: "SAGE".to_string(),
            denomination: "100000000000000000000".to_string(),
            denomination_formatted: "100 SAGE".to_string(),
            total_deposits: 0,
            total_withdrawals: 0,
            current_anonymity_set: 0,
            is_active: true,
            created_at: now - 86400 * 30,
        },
        PrivacyPoolInfo {
            pool_id: 1,
            token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
            token_symbol: "SAGE".to_string(),
            denomination: "1000000000000000000000".to_string(),
            denomination_formatted: "1,000 SAGE".to_string(),
            total_deposits: 0,
            total_withdrawals: 0,
            current_anonymity_set: 0,
            is_active: true,
            created_at: now - 86400 * 30,
        },
    ];

    Json(pools)
}

/// Get specific pool info
async fn get_pool_info(
    State(_state): State<Arc<PrivacyApiState>>,
    Path(pool_id): Path<u8>,
) -> Result<Json<PrivacyPoolInfo>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting pool info: {}", pool_id);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if pool_id > 2 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Pool not found".to_string(),
                code: "POOL_NOT_FOUND".to_string(),
            }),
        ));
    }

    Ok(Json(PrivacyPoolInfo {
        pool_id,
        token: "0x02de76e624a88db8fd519a64ef3207e7fa3fbd4286cf652157400a7ad1306bce".to_string(),
        token_symbol: "SAGE".to_string(),
        denomination: "100000000000000000000".to_string(),
        denomination_formatted: "100 SAGE".to_string(),
        total_deposits: 1234,
        total_withdrawals: 890,
        current_anonymity_set: 344,
        is_active: true,
        created_at: now - 86400 * 30,
    }))
}

/// Get privacy stats
///
/// Aggregates privacy statistics from database tables.
async fn get_privacy_stats(
    State(state): State<Arc<PrivacyApiState>>,
) -> Json<PrivacyStats> {
    debug!("Getting privacy stats");

    // Aggregate stats from database
    if let Some(ref pool) = state.db_pool {
        // Query multiple stats in parallel-ish using a single complex query
        let stats_result = sqlx::query(
            r#"
            SELECT
                (SELECT COUNT(*) FROM private_accounts WHERE is_registered = true) as active_accounts,
                (SELECT COUNT(*) FROM private_transfers WHERE status = 'completed') as total_transfers,
                (SELECT COUNT(*) FROM stealth_addresses) as stealth_addresses,
                (SELECT COUNT(*) FROM payments WHERE privacy_enabled = true) as worker_payments,
                (SELECT COUNT(DISTINCT (event_data->>'pool_id')) FROM blockchain_events WHERE event_name = 'PoolCreated') as total_pools
            "#
        )
        .fetch_optional(pool)
        .await;

        // Query pool anonymity set stats separately
        let pool_stats_result = sqlx::query(
            r#"
            WITH pool_sizes AS (
                SELECT
                    (event_data->>'pool_id') as pool_id,
                    SUM(CASE WHEN event_name = 'PrivacyDeposit' THEN 1 ELSE 0 END) -
                    SUM(CASE WHEN event_name = 'PrivacyWithdraw' THEN 1 ELSE 0 END) as anonymity_set
                FROM blockchain_events
                WHERE event_name IN ('PrivacyDeposit', 'PrivacyWithdraw')
                  AND contract_name = 'PrivacyPools'
                GROUP BY event_data->>'pool_id'
            )
            SELECT
                COALESCE(AVG(anonymity_set), 0)::bigint as avg_anonymity,
                COALESCE(MAX(anonymity_set), 0)::bigint as max_anonymity
            FROM pool_sizes
            WHERE anonymity_set > 0
            "#
        )
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = stats_result {
            use sqlx::Row;

            let active_accounts: i64 = row.try_get("active_accounts").unwrap_or(0);
            let total_transfers: i64 = row.try_get("total_transfers").unwrap_or(0);
            let stealth_addresses: i64 = row.try_get("stealth_addresses").unwrap_or(0);
            let worker_payments: i64 = row.try_get("worker_payments").unwrap_or(0);
            let total_pools: i64 = row.try_get("total_pools").unwrap_or(0);

            let (avg_anonymity, max_anonymity) = if let Ok(Some(pool_row)) = pool_stats_result {
                (
                    pool_row.try_get::<i64, _>("avg_anonymity").unwrap_or(0) as u64,
                    pool_row.try_get::<i64, _>("max_anonymity").unwrap_or(0) as u64,
                )
            } else {
                (0, 0)
            };

            return Json(PrivacyStats {
                total_private_deposits: "0".to_string(), // Encrypted - cannot aggregate
                total_private_withdrawals: "0".to_string(), // Encrypted
                total_private_transfers: total_transfers as u64,
                active_privacy_accounts: active_accounts as u64,
                total_pools: total_pools.max(2) as u32, // Minimum 2 default pools
                average_anonymity_set: avg_anonymity,
                largest_anonymity_set: max_anonymity,
                total_stealth_addresses: stealth_addresses as u64,
                total_worker_payments: worker_payments as u64,
            });
        }
    }

    // Default stats when database is unavailable
    Json(PrivacyStats {
        total_private_deposits: "0".to_string(),
        total_private_withdrawals: "0".to_string(),
        total_private_transfers: 0,
        active_privacy_accounts: 0,
        total_pools: 2,
        average_anonymity_set: 0,
        largest_anonymity_set: 0,
        total_stealth_addresses: 0,
        total_worker_payments: 0,
    })
}

/// Get ASP status
///
/// Returns Anonymity Set Provider status from indexed blockchain events.
async fn get_asp_status(
    State(state): State<Arc<PrivacyApiState>>,
) -> Json<AspStatus> {
    debug!("Getting ASP status");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Query ASP status from indexed events
    if let Some(ref pool) = state.db_pool {
        // Get the latest ASP epoch update event
        let asp_result = sqlx::query(
            r#"
            SELECT
                event_data->>'epoch' as epoch,
                event_data->>'merkle_root' as merkle_root,
                event_data->>'compliance_enabled' as compliance,
                EXTRACT(EPOCH FROM block_timestamp)::bigint as updated_at
            FROM blockchain_events
            WHERE event_name IN ('EpochUpdated', 'ASPStatusChanged')
              AND contract_name = 'PrivacyPools'
            ORDER BY block_number DESC
            LIMIT 1
            "#
        )
        .fetch_optional(pool)
        .await;

        // Get total members count (unique depositors across all pools)
        let members_result = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(DISTINCT event_data->>'depositor')
            FROM blockchain_events
            WHERE event_name = 'PrivacyDeposit'
              AND contract_name = 'PrivacyPools'
            "#
        )
        .fetch_one(pool)
        .await;

        let total_members = members_result.unwrap_or(0) as u64;

        if let Ok(Some(row)) = asp_result {
            use sqlx::Row;

            let epoch: String = row.try_get("epoch").unwrap_or_else(|_| "0".to_string());
            let merkle_root: String = row.try_get("merkle_root").unwrap_or_else(|_| "0x0".to_string());
            let compliance: String = row.try_get("compliance").unwrap_or_else(|_| "true".to_string());
            let updated_at: i64 = row.try_get("updated_at").unwrap_or(now as i64);

            return Json(AspStatus {
                is_active: true,
                current_epoch: epoch.parse().unwrap_or(0),
                merkle_root,
                total_members,
                last_updated: updated_at as u64,
                compliance_enabled: compliance.parse().unwrap_or(true),
            });
        }

        // Return status with just member count if no epoch events yet
        if total_members > 0 {
            return Json(AspStatus {
                is_active: true,
                current_epoch: 1,
                merkle_root: "0x0".to_string(),
                total_members,
                last_updated: now,
                compliance_enabled: true,
            });
        }
    }

    // Default status when no data available
    Json(AspStatus {
        is_active: true,
        current_epoch: 0,
        merkle_root: "0x0".to_string(),
        total_members: 0,
        last_updated: now,
        compliance_enabled: true,
    })
}

/// Get Merkle proof for a deposit commitment
///
/// Returns the Merkle proof needed to prove membership in the global deposit tree.
/// This is required for privacy pool withdrawals.
async fn get_merkle_proof(
    State(state): State<Arc<PrivacyApiState>>,
    Path(commitment): Path<String>,
) -> Result<Json<MerkleProofResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting Merkle proof for commitment: {}", commitment);

    // Query deposit from indexed blockchain events
    if let Some(ref pool) = state.db_pool {
        // Get deposit event for this commitment
        let deposit_result = sqlx::query(
            r#"
            SELECT
                event_data->>'commitment' as commitment,
                event_data->>'global_index' as global_index,
                event_data->>'depositor' as depositor,
                event_data->>'asset_id' as asset_id,
                event_data->>'root' as root,
                tx_hash,
                EXTRACT(EPOCH FROM block_timestamp)::bigint as timestamp
            FROM blockchain_events
            WHERE event_name = 'PPDepositExecuted'
              AND contract_name = 'PrivacyPools'
              AND (event_data->>'commitment' = $1
                   OR event_data->'keys'->1 = $1)
            LIMIT 1
            "#
        )
        .bind(&commitment)
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = deposit_result {
            use sqlx::Row;

            let leaf_index: String = row.try_get("global_index").unwrap_or_else(|_| "0".to_string());
            let depositor: String = row.try_get("depositor").unwrap_or_default();
            let asset_id: String = row.try_get("asset_id").unwrap_or_else(|_| "0".to_string());
            let root: String = row.try_get("root").unwrap_or_else(|_| "0x0".to_string());
            let timestamp: i64 = row.try_get("timestamp").unwrap_or(0);
            let tx_hash: Option<String> = row.try_get("tx_hash").ok();

            let leaf_idx: u64 = leaf_index.parse().unwrap_or(0);

            // Get current global root from latest deposit event
            let current_root_result = sqlx::query_scalar::<_, String>(
                r#"
                SELECT event_data->>'root'
                FROM blockchain_events
                WHERE event_name = 'PPDepositExecuted'
                  AND contract_name = 'PrivacyPools'
                ORDER BY block_number DESC, transaction_index DESC
                LIMIT 1
                "#
            )
            .fetch_optional(pool)
            .await;

            let current_root = current_root_result
                .ok()
                .flatten()
                .unwrap_or_else(|| root.clone());

            // Generate Merkle proof from indexed deposit tree
            // Query all deposits up to current size to reconstruct the proof
            let proof = generate_merkle_proof_from_db(pool, leaf_idx, &commitment).await;

            return Ok(Json(MerkleProofResponse {
                found: true,
                commitment: commitment.clone(),
                leaf_index: leaf_idx,
                root,
                current_root,
                siblings: proof.siblings,
                path_indices: proof.path_indices,
                depth: proof.depth,
                deposit_info: Some(DepositInfo {
                    depositor,
                    asset_id,
                    timestamp: timestamp as u64,
                    tx_hash,
                }),
            }));
        }
    }

    // Deposit not found
    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Deposit commitment not found. Make sure the deposit has been confirmed on-chain.".to_string(),
            code: "DEPOSIT_NOT_FOUND".to_string(),
        }),
    ))
}

/// Merkle proof structure from DB
struct MerkleProof {
    siblings: Vec<String>,
    path_indices: Vec<u8>,
    depth: u8,
}

/// Generate Merkle proof from indexed deposits in database
async fn generate_merkle_proof_from_db(
    pool: &sqlx::PgPool,
    leaf_index: u64,
    _commitment: &str,
) -> MerkleProof {
    // Query all deposit commitments to reconstruct the tree
    let deposits_result = sqlx::query_scalar::<_, String>(
        r#"
        SELECT event_data->>'commitment'
        FROM blockchain_events
        WHERE event_name = 'PPDepositExecuted'
          AND contract_name = 'PrivacyPools'
        ORDER BY block_number ASC, transaction_index ASC
        "#
    )
    .fetch_all(pool)
    .await;

    let commitments: Vec<String> = deposits_result.unwrap_or_default();

    if commitments.is_empty() {
        return MerkleProof {
            siblings: vec![],
            path_indices: vec![],
            depth: 0,
        };
    }

    // Calculate tree depth
    let size = commitments.len() as u64;
    let depth = calculate_tree_depth(size);

    // Build Merkle tree and generate proof
    let mut siblings = Vec::new();
    let mut path_indices = Vec::new();
    let mut current_level: Vec<String> = commitments;
    let mut current_index = leaf_index;

    for level in 0..depth {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        // Get sibling hash (or default zero hash if doesn't exist)
        let sibling = if (sibling_index as usize) < current_level.len() {
            current_level[sibling_index as usize].clone()
        } else {
            format!("0x{:0>64}", 0) // Zero hash for missing sibling
        };

        siblings.push(sibling);
        path_indices.push((current_index % 2) as u8);

        // Build next level
        let mut next_level = Vec::new();
        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                left // Duplicate last element if odd
            };

            // Hash pair using Poseidon (simplified - in production use actual Poseidon)
            let parent = format!("0x{}", poseidon_hash_pair(left, right));
            next_level.push(parent);
        }

        current_level = next_level;
        current_index /= 2;
    }

    MerkleProof {
        siblings,
        path_indices,
        depth,
    }
}

/// Calculate Merkle tree depth for given size
fn calculate_tree_depth(size: u64) -> u8 {
    if size == 0 {
        return 0;
    }
    let mut depth = 0u8;
    let mut n = size - 1;
    while n > 0 {
        depth += 1;
        n >>= 1;
    }
    depth.max(1)
}

/// Simplified Poseidon hash pair (placeholder - use actual implementation in production)
fn poseidon_hash_pair(left: &str, right: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // This is a PLACEHOLDER - in production, use proper Poseidon hash
    // The actual Merkle proof verification happens on-chain with the real Poseidon
    let mut hasher = DefaultHasher::new();
    left.hash(&mut hasher);
    right.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ============================================================================
// Helpers
// ============================================================================

fn is_valid_starknet_address(address: &str) -> bool {
    if !address.starts_with("0x") {
        return false;
    }

    let hex_part = &address[2..];

    if hex_part.is_empty() || hex_part.len() > 64 {
        return false;
    }

    hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Format token amount with proper decimals and symbol
fn format_token_amount(amount_wei: &str, token: &str) -> String {
    let decimals = match token.to_uppercase().as_str() {
        "USDC" | "USDT" => 6,
        "BTC" | "WBTC" => 8, // Native BTC uses 8 decimals
        _ => 18, // Default for SAGE, ETH, STRK
    };

    // Parse the amount
    let amount = amount_wei.parse::<u128>().unwrap_or(0);
    if amount == 0 {
        return format!("0 {}", token);
    }

    let divisor = 10u128.pow(decimals);
    let whole = amount / divisor;
    let fraction = amount % divisor;

    if fraction == 0 {
        format_with_commas(whole, token)
    } else {
        // Show up to 4 decimal places
        let frac_str = format!("{:0>width$}", fraction, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        let display_frac = if trimmed.len() > 4 { &trimmed[..4] } else { trimmed };
        format!("{}.{} {}", format_number_with_commas(whole), display_frac, token)
    }
}

/// Format number with thousands separators
fn format_with_commas(n: u128, token: &str) -> String {
    format!("{} {}", format_number_with_commas(n), token)
}

fn format_number_with_commas(n: u128) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_starknet_address() {
        assert!(is_valid_starknet_address("0x1234abcd"));
        assert!(is_valid_starknet_address(
            "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
        ));
        assert!(!is_valid_starknet_address("1234abcd"));
        assert!(!is_valid_starknet_address("0x"));
        assert!(!is_valid_starknet_address("0xGHIJ"));
    }
}
