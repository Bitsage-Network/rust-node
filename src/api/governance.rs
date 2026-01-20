//! # Governance API Endpoints
//!
//! REST API endpoints for DAO governance operations.
//! Provides proposal management, voting, and governance stats.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

/// Governance API state
pub struct GovernanceApiState {
    pub network: String,
    pub governance_address: String,
    pub sage_token_address: String,
    pub db_pool: Option<sqlx::PgPool>,
}

impl GovernanceApiState {
    pub fn new(network: &str, governance_address: &str, sage_token_address: &str) -> Self {
        Self {
            network: network.to_string(),
            governance_address: governance_address.to_string(),
            sage_token_address: sage_token_address.to_string(),
            db_pool: None,
        }
    }

    pub fn with_db(network: &str, governance_address: &str, sage_token_address: &str, db_pool: sqlx::PgPool) -> Self {
        Self {
            network: network.to_string(),
            governance_address: governance_address.to_string(),
            sage_token_address: sage_token_address.to_string(),
            db_pool: Some(db_pool),
        }
    }

    pub fn disabled(network: &str) -> Self {
        Self {
            network: network.to_string(),
            governance_address: String::new(),
            sage_token_address: String::new(),
            db_pool: None,
        }
    }
}

/// Create governance routes
pub fn governance_routes(state: Arc<GovernanceApiState>) -> Router {
    Router::new()
        // Proposals
        .route("/api/governance/proposals", get(get_proposals))
        .route("/api/governance/proposals/:id", get(get_proposal))
        .route("/api/governance/proposals/:id/votes", get(get_proposal_votes))
        .route("/api/governance/proposals/create", post(create_proposal))
        .route("/api/governance/proposals/:id/vote", post(vote_on_proposal))
        .route("/api/governance/proposals/:id/execute", post(execute_proposal))
        .route("/api/governance/proposals/:id/cancel", post(cancel_proposal))
        // Voting Power
        .route("/api/governance/voting-power/:address", get(get_voting_power))
        .route("/api/governance/delegations/:address", get(get_delegations))
        .route("/api/governance/delegate", post(delegate_votes))
        // Council
        .route("/api/governance/council", get(get_council_members))
        // Stats
        .route("/api/governance/stats", get(get_governance_stats))
        .route("/api/governance/config", get(get_governance_config))
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Proposal type enum
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ProposalType {
    Treasury,
    Upgrade,
    Parameter,
    Emergency,
}

impl std::fmt::Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalType::Treasury => write!(f, "treasury"),
            ProposalType::Upgrade => write!(f, "upgrade"),
            ProposalType::Parameter => write!(f, "parameter"),
            ProposalType::Emergency => write!(f, "emergency"),
        }
    }
}

/// Proposal status
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ProposalStatus {
    Pending,    // Before voting starts
    Active,     // Voting in progress
    Succeeded,  // Voting passed, waiting for execution
    Defeated,   // Voting failed
    Executed,   // Proposal executed
    Cancelled,  // Proposal cancelled
    Expired,    // Past execution window
}

/// Proposal info
#[derive(Debug, Serialize, Clone)]
pub struct ProposalInfo {
    pub id: u64,
    pub proposer: String,
    pub title: String,
    pub description: String,
    pub target: String,
    pub value: String,
    pub calldata: String,
    pub proposal_type: String,
    pub status: ProposalStatus,
    pub votes_for: String,
    pub votes_against: String,
    pub votes_abstain: String,
    pub total_votes: String,
    pub quorum_required: String,
    pub quorum_reached: bool,
    pub start_time: u64,
    pub end_time: u64,
    pub execution_time: u64,
    pub time_remaining_secs: Option<u64>,
    pub created_at: u64,
    pub executed_at: Option<u64>,
    pub cancelled_at: Option<u64>,
    pub tx_hash: Option<String>,
}

/// Vote record
#[derive(Debug, Serialize, Clone)]
pub struct VoteInfo {
    pub proposal_id: u64,
    pub voter: String,
    pub support: String, // "for", "against", "abstain"
    pub voting_power: String,
    pub reason: Option<String>,
    pub timestamp: u64,
    pub tx_hash: Option<String>,
}

/// Create proposal request
#[derive(Debug, Deserialize)]
pub struct CreateProposalRequest {
    pub title: String,
    pub description: String,
    pub target: String,
    pub value: String,
    pub calldata: String,
    pub proposal_type: ProposalType,
}

/// Create proposal response
#[derive(Debug, Serialize)]
pub struct CreateProposalResponse {
    pub success: bool,
    pub proposal_id: Option<u64>,
    pub message: String,
    pub transaction_data: Option<TransactionData>,
}

/// Vote request
#[derive(Debug, Deserialize)]
pub struct VoteRequest {
    pub support: String, // "for", "against", "abstain"
    pub reason: Option<String>,
}

/// Vote response
#[derive(Debug, Serialize)]
pub struct VoteResponse {
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

/// Voting power info
#[derive(Debug, Serialize)]
pub struct VotingPowerInfo {
    pub address: String,
    pub voting_power: String,
    pub voting_power_formatted: String,
    pub delegated_to: Option<String>,
    pub received_delegations: String,
    pub can_propose: bool,
    pub proposal_threshold: String,
}

/// Delegation info
#[derive(Debug, Serialize, Clone)]
pub struct DelegationInfo {
    pub from: String,
    pub to: String,
    pub amount: String,
    pub timestamp: u64,
}

/// Delegate request
#[derive(Debug, Deserialize)]
pub struct DelegateRequest {
    pub delegate_to: String,
}

/// Council member info
#[derive(Debug, Serialize, Clone)]
pub struct CouncilMember {
    pub address: String,
    pub is_emergency_council: bool,
    pub added_at: u64,
    pub proposals_created: u32,
    pub votes_cast: u32,
}

/// Governance stats
#[derive(Debug, Serialize)]
pub struct GovernanceStats {
    pub total_proposals: u64,
    pub active_proposals: u32,
    pub total_votes_cast: u64,
    pub unique_voters: u64,
    pub total_voting_power: String,
    pub quorum_percentage: f64,
    pub avg_voter_turnout: f64,
    pub proposals_executed: u32,
    pub proposals_defeated: u32,
}

/// Governance config
#[derive(Debug, Serialize)]
pub struct GovernanceConfig {
    pub voting_delay_secs: u64,
    pub voting_period_secs: u64,
    pub execution_delay_secs: u64,
    pub quorum_threshold: String,
    pub quorum_threshold_formatted: String,
    pub proposal_threshold: String,
    pub proposal_threshold_formatted: String,
    pub council_count: u32,
    pub council_threshold: u32,
}

/// Query parameters for proposals
#[derive(Debug, Deserialize)]
pub struct ProposalQuery {
    pub status: Option<String>,
    pub proposal_type: Option<String>,
    pub proposer: Option<String>,
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

/// Get all proposals
async fn get_proposals(
    State(state): State<Arc<GovernanceApiState>>,
    Query(params): Query<ProposalQuery>,
) -> Json<Vec<ProposalInfo>> {
    debug!("Getting proposals with filters: {:?}", params);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let limit = params.limit.unwrap_or(20).min(100) as i64;
    let offset = ((params.page.unwrap_or(1) - 1) * params.limit.unwrap_or(20)) as i64;

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let proposals_result = sqlx::query(
            r#"
            SELECT proposal_id, proposer_address, title, description,
                   proposal_type, status,
                   for_votes::text, against_votes::text,
                   COALESCE(abstain_votes, 0)::text as abstain_votes,
                   quorum_required::text,
                   COALESCE(target_address, '0x0') as target_address,
                   COALESCE(value, '0')::text as value,
                   COALESCE(calldata, '') as calldata,
                   start_block, end_block,
                   EXTRACT(EPOCH FROM created_at)::bigint as created_at,
                   EXTRACT(EPOCH FROM executed_at)::bigint as executed_at,
                   EXTRACT(EPOCH FROM cancelled_at)::bigint as cancelled_at,
                   tx_hash, block_number
            FROM proposals
            WHERE ($1::text IS NULL OR status = $1)
              AND ($2::text IS NULL OR proposal_type = $2)
              AND ($3::text IS NULL OR proposer_address = $3)
            ORDER BY created_at DESC
            LIMIT $4 OFFSET $5
            "#
        )
        .bind(&params.status)
        .bind(&params.proposal_type)
        .bind(&params.proposer)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = proposals_result {
            use sqlx::Row;

            let proposals: Vec<ProposalInfo> = rows.iter().map(|row| {
                let proposal_id: String = row.get("proposal_id");
                let status_str: String = row.get("status");
                let for_votes: String = row.get("for_votes");
                let against_votes: String = row.get("against_votes");
                let abstain_votes: String = row.get("abstain_votes");
                let quorum_required: String = row.get("quorum_required");
                let created_at: i64 = row.get("created_at");

                // Parse votes for quorum check
                let for_votes_f: f64 = for_votes.parse().unwrap_or(0.0);
                let against_votes_f: f64 = against_votes.parse().unwrap_or(0.0);
                let abstain_votes_f: f64 = abstain_votes.parse().unwrap_or(0.0);
                let quorum_f: f64 = quorum_required.parse().unwrap_or(1.0);
                let total_votes = for_votes_f + against_votes_f + abstain_votes_f;
                let quorum_reached = total_votes >= quorum_f;

                let status = match status_str.as_str() {
                    "active" => ProposalStatus::Active,
                    "passed" | "succeeded" => ProposalStatus::Succeeded,
                    "rejected" | "defeated" => ProposalStatus::Defeated,
                    "executed" => ProposalStatus::Executed,
                    "cancelled" => ProposalStatus::Cancelled,
                    "expired" => ProposalStatus::Expired,
                    _ => ProposalStatus::Pending,
                };

                // Estimate times from block numbers (assuming 12s blocks)
                let start_block: i64 = row.try_get("start_block").unwrap_or(0);
                let end_block: i64 = row.try_get("end_block").unwrap_or(0);
                let start_time = created_at as u64;
                let voting_duration = ((end_block - start_block) * 12) as u64;
                let end_time = start_time + voting_duration.max(259200); // min 3 days
                let execution_time = end_time + 172800; // +2 days timelock

                let time_remaining = if now < end_time { Some(end_time - now) } else { None };

                ProposalInfo {
                    id: proposal_id.parse().unwrap_or(0),
                    proposer: row.get::<String, _>("proposer_address"),
                    title: row.get::<String, _>("title"),
                    description: row.try_get::<String, _>("description").unwrap_or_default(),
                    target: row.try_get::<String, _>("target_address").unwrap_or_else(|_| "0x0".to_string()),
                    value: row.try_get::<String, _>("value").unwrap_or_else(|_| "0".to_string()),
                    calldata: row.try_get::<String, _>("calldata").unwrap_or_else(|_| "0x".to_string()),
                    proposal_type: row.get::<String, _>("proposal_type"),
                    status,
                    votes_for: for_votes,
                    votes_against: against_votes,
                    votes_abstain: abstain_votes,
                    total_votes: format!("{:.0}", total_votes),
                    quorum_required,
                    quorum_reached,
                    start_time,
                    end_time,
                    execution_time,
                    time_remaining_secs: time_remaining,
                    created_at: created_at as u64,
                    executed_at: row.try_get::<i64, _>("executed_at").ok().map(|t| t as u64),
                    cancelled_at: row.try_get::<i64, _>("cancelled_at").ok().map(|t| t as u64),
                    tx_hash: row.try_get::<String, _>("tx_hash").ok(),
                }
            }).collect();

            if !proposals.is_empty() {
                return Json(proposals);
            }
        }
    }

    // Fallback to mock proposals
    let proposals = vec![
        ProposalInfo {
            id: 1,
            proposer: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string(),
            title: "Increase Worker Rewards by 10%".to_string(),
            description: "This proposal aims to increase worker rewards from 80% to 88% of job fees to incentivize more GPU providers to join the network.".to_string(),
            target: "0x027bc755eacd2e6aa6b998d7c017eaead21644fe2bce02fdb7b7db2a746c7611".to_string(),
            value: "0".to_string(),
            calldata: "0x...".to_string(),
            proposal_type: "parameter".to_string(),
            status: ProposalStatus::Active,
            votes_for: "5000000000000000000000000".to_string(),
            votes_against: "1000000000000000000000000".to_string(),
            votes_abstain: "500000000000000000000000".to_string(),
            total_votes: "6500000000000000000000000".to_string(),
            quorum_required: "10000000000000000000000000".to_string(),
            quorum_reached: false,
            start_time: now - 86400,
            end_time: now + 86400 * 2,
            execution_time: now + 86400 * 4,
            time_remaining_secs: Some(86400 * 2),
            created_at: now - 86400,
            executed_at: None,
            cancelled_at: None,
            tx_hash: Some("0xabc123...".to_string()),
        },
        ProposalInfo {
            id: 2,
            proposer: "0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691".to_string(),
            title: "Treasury Allocation for Marketing".to_string(),
            description: "Allocate 500,000 SAGE from treasury for Q1 2025 marketing initiatives.".to_string(),
            target: "0x06f2660d73a39504fda502a4c59cf8dd4945bea829fc57372475156c7db6b0b9".to_string(),
            value: "500000000000000000000000".to_string(),
            calldata: "0x...".to_string(),
            proposal_type: "treasury".to_string(),
            status: ProposalStatus::Succeeded,
            votes_for: "15000000000000000000000000".to_string(),
            votes_against: "2000000000000000000000000".to_string(),
            votes_abstain: "1000000000000000000000000".to_string(),
            total_votes: "18000000000000000000000000".to_string(),
            quorum_required: "10000000000000000000000000".to_string(),
            quorum_reached: true,
            start_time: now - 86400 * 5,
            end_time: now - 86400 * 2,
            execution_time: now + 86400,
            time_remaining_secs: None,
            created_at: now - 86400 * 5,
            executed_at: None,
            cancelled_at: None,
            tx_hash: Some("0xdef456...".to_string()),
        },
        ProposalInfo {
            id: 3,
            proposer: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string(),
            title: "Contract Upgrade v2.0".to_string(),
            description: "Upgrade JobManager contract to v2.0 with improved job routing.".to_string(),
            target: "0x0679046de51d5153e6ae8f4a5fe8515136cd25d9a6e28fdd9e7d88503fbabf35".to_string(),
            value: "0".to_string(),
            calldata: "0x...".to_string(),
            proposal_type: "upgrade".to_string(),
            status: ProposalStatus::Executed,
            votes_for: "20000000000000000000000000".to_string(),
            votes_against: "1000000000000000000000000".to_string(),
            votes_abstain: "500000000000000000000000".to_string(),
            total_votes: "21500000000000000000000000".to_string(),
            quorum_required: "10000000000000000000000000".to_string(),
            quorum_reached: true,
            start_time: now - 86400 * 10,
            end_time: now - 86400 * 7,
            execution_time: now - 86400 * 5,
            time_remaining_secs: None,
            created_at: now - 86400 * 10,
            executed_at: Some(now - 86400 * 5),
            cancelled_at: None,
            tx_hash: Some("0x789abc...".to_string()),
        },
    ];

    Json(proposals)
}

/// Get specific proposal
async fn get_proposal(
    State(state): State<Arc<GovernanceApiState>>,
    Path(id): Path<u64>,
) -> Result<Json<ProposalInfo>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting proposal: {}", id);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let proposal_result = sqlx::query(
            r#"
            SELECT proposal_id, proposer_address, title, description,
                   proposal_type, status, target_address, value::text,
                   for_votes::text, against_votes::text, quorum_required::text,
                   start_block, end_block,
                   EXTRACT(EPOCH FROM created_at)::bigint as created_at,
                   EXTRACT(EPOCH FROM executed_at)::bigint as executed_at,
                   tx_hash
            FROM proposals
            WHERE proposal_id = $1
            "#
        )
        .bind(id.to_string())
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = proposal_result {
            use sqlx::Row;

            let status_str: String = row.get("status");
            let for_votes: String = row.get("for_votes");
            let against_votes: String = row.get("against_votes");
            let quorum_required: String = row.get("quorum_required");
            let created_at: i64 = row.get("created_at");

            let for_votes_f: f64 = for_votes.parse().unwrap_or(0.0);
            let against_votes_f: f64 = against_votes.parse().unwrap_or(0.0);
            let quorum_f: f64 = quorum_required.parse().unwrap_or(1.0);
            let total_votes = for_votes_f + against_votes_f;
            let quorum_reached = total_votes >= quorum_f;

            let status = match status_str.as_str() {
                "active" => ProposalStatus::Active,
                "passed" | "succeeded" => ProposalStatus::Succeeded,
                "rejected" | "defeated" => ProposalStatus::Defeated,
                "executed" => ProposalStatus::Executed,
                "cancelled" => ProposalStatus::Cancelled,
                "expired" => ProposalStatus::Expired,
                _ => ProposalStatus::Pending,
            };

            let start_block: i64 = row.try_get("start_block").unwrap_or(0);
            let end_block: i64 = row.try_get("end_block").unwrap_or(0);
            let start_time = created_at as u64;
            let voting_duration = ((end_block - start_block) * 12) as u64;
            let end_time = start_time + voting_duration.max(259200);
            let execution_time = end_time + 172800;
            let time_remaining = if now < end_time { Some(end_time - now) } else { None };

            return Ok(Json(ProposalInfo {
                id,
                proposer: row.get::<String, _>("proposer_address"),
                title: row.get::<String, _>("title"),
                description: row.try_get::<String, _>("description").unwrap_or_default(),
                target: row.try_get::<String, _>("target_address").unwrap_or_else(|_| "0x0".to_string()),
                value: row.try_get::<String, _>("value").unwrap_or_else(|_| "0".to_string()),
                calldata: "0x".to_string(),
                proposal_type: row.get::<String, _>("proposal_type"),
                status,
                votes_for: for_votes,
                votes_against: against_votes,
                votes_abstain: "0".to_string(),
                total_votes: format!("{:.0}", total_votes),
                quorum_required,
                quorum_reached,
                start_time,
                end_time,
                execution_time,
                time_remaining_secs: time_remaining,
                created_at: created_at as u64,
                executed_at: row.try_get::<i64, _>("executed_at").ok().map(|t| t as u64),
                cancelled_at: None,
                tx_hash: row.try_get::<String, _>("tx_hash").ok(),
            }));
        }
    }

    // Fallback to mock for development
    if id > 3 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Proposal not found".to_string(),
                code: "PROPOSAL_NOT_FOUND".to_string(),
            }),
        ));
    }

    Ok(Json(ProposalInfo {
        id,
        proposer: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string(),
        title: format!("Proposal #{}", id),
        description: "This is a detailed description of the proposal...".to_string(),
        target: "0x027bc755eacd2e6aa6b998d7c017eaead21644fe2bce02fdb7b7db2a746c7611".to_string(),
        value: "0".to_string(),
        calldata: "0x...".to_string(),
        proposal_type: "parameter".to_string(),
        status: ProposalStatus::Active,
        votes_for: "5000000000000000000000000".to_string(),
        votes_against: "1000000000000000000000000".to_string(),
        votes_abstain: "500000000000000000000000".to_string(),
        total_votes: "6500000000000000000000000".to_string(),
        quorum_required: "10000000000000000000000000".to_string(),
        quorum_reached: false,
        start_time: now - 86400,
        end_time: now + 86400 * 2,
        execution_time: now + 86400 * 4,
        time_remaining_secs: Some(86400 * 2),
        created_at: now - 86400,
        executed_at: None,
        cancelled_at: None,
        tx_hash: Some("0xabc123...".to_string()),
    }))
}

/// Get votes for a proposal
async fn get_proposal_votes(
    State(state): State<Arc<GovernanceApiState>>,
    Path(proposal_id): Path<u64>,
) -> Result<Json<Vec<VoteInfo>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting votes for proposal: {}", proposal_id);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let votes_result = sqlx::query(
            r#"
            SELECT proposal_id, voter_address, support, support_type,
                   voting_power::text, reason,
                   EXTRACT(EPOCH FROM created_at)::bigint as created_at,
                   tx_hash
            FROM votes
            WHERE proposal_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(proposal_id.to_string())
        .fetch_all(pool)
        .await;

        if let Ok(rows) = votes_result {
            use sqlx::Row;

            let votes: Vec<VoteInfo> = rows.iter().map(|row| {
                // Check for support_type first (for, against, abstain), fall back to bool
                let support = if let Ok(support_type) = row.try_get::<String, _>("support_type") {
                    support_type
                } else {
                    let support_bool: bool = row.try_get("support").unwrap_or(false);
                    if support_bool { "for".to_string() } else { "against".to_string() }
                };

                VoteInfo {
                    proposal_id,
                    voter: row.get::<String, _>("voter_address"),
                    support,
                    voting_power: row.get::<String, _>("voting_power"),
                    reason: row.try_get::<String, _>("reason").ok(),
                    timestamp: row.get::<i64, _>("created_at") as u64,
                    tx_hash: row.try_get::<String, _>("tx_hash").ok(),
                }
            }).collect();

            if !votes.is_empty() {
                return Ok(Json(votes));
            }
        }
    }

    // Fallback to mock votes
    let votes = vec![
        VoteInfo {
            proposal_id,
            voter: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string(),
            support: "for".to_string(),
            voting_power: "1000000000000000000000000".to_string(),
            reason: Some("This proposal aligns with the network's growth strategy.".to_string()),
            timestamp: now - 3600,
            tx_hash: Some("0xvote1...".to_string()),
        },
        VoteInfo {
            proposal_id,
            voter: "0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691".to_string(),
            support: "for".to_string(),
            voting_power: "2000000000000000000000000".to_string(),
            reason: None,
            timestamp: now - 7200,
            tx_hash: Some("0xvote2...".to_string()),
        },
        VoteInfo {
            proposal_id,
            voter: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            support: "against".to_string(),
            voting_power: "500000000000000000000000".to_string(),
            reason: Some("The increase is too aggressive.".to_string()),
            timestamp: now - 10800,
            tx_hash: Some("0xvote3...".to_string()),
        },
    ];

    Ok(Json(votes))
}

/// Create a new proposal
async fn create_proposal(
    State(state): State<Arc<GovernanceApiState>>,
    Json(request): Json<CreateProposalRequest>,
) -> Result<Json<CreateProposalResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Create proposal request: {}", request.title);

    if request.title.is_empty() || request.description.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Title and description are required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        ));
    }

    // Build transaction data for wallet signing
    let proposal_type_felt = match request.proposal_type {
        ProposalType::Treasury => "0x0",
        ProposalType::Upgrade => "0x1",
        ProposalType::Parameter => "0x2",
        ProposalType::Emergency => "0x3",
    };

    Ok(Json(CreateProposalResponse {
        success: true,
        proposal_id: None, // Assigned after on-chain execution
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.governance_address.clone(),
            function_name: "propose".to_string(),
            calldata: vec![
                format!("0x{:x}", request.title.len()), // title as felt252
                format!("0x{:x}", request.description.len()), // description as felt252
                request.target.clone(),
                request.value.clone(),
                "0".to_string(), // value high
                request.calldata.clone(),
                proposal_type_felt.to_string(),
            ],
        }),
    }))
}

/// Vote on a proposal
async fn vote_on_proposal(
    State(state): State<Arc<GovernanceApiState>>,
    Path(proposal_id): Path<u64>,
    Json(request): Json<VoteRequest>,
) -> Result<Json<VoteResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Vote request: proposal={}, support={}", proposal_id, request.support);

    let support_bool = match request.support.to_lowercase().as_str() {
        "for" | "yes" | "true" => true,
        "against" | "no" | "false" => false,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid support value. Use 'for' or 'against'".to_string(),
                    code: "INVALID_SUPPORT".to_string(),
                }),
            ));
        }
    };

    Ok(Json(VoteResponse {
        success: true,
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.governance_address.clone(),
            function_name: "vote".to_string(),
            calldata: vec![
                proposal_id.to_string(),
                "0".to_string(), // proposal_id high (u256)
                if support_bool { "1" } else { "0" }.to_string(),
                "0".to_string(), // voting_power (will be calculated on-chain)
                "0".to_string(),
            ],
        }),
    }))
}

/// Execute a passed proposal
async fn execute_proposal(
    State(state): State<Arc<GovernanceApiState>>,
    Path(proposal_id): Path<u64>,
) -> Result<Json<VoteResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Execute proposal request: {}", proposal_id);

    Ok(Json(VoteResponse {
        success: true,
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.governance_address.clone(),
            function_name: "execute_proposal".to_string(),
            calldata: vec![
                proposal_id.to_string(),
                "0".to_string(), // high
            ],
        }),
    }))
}

/// Cancel a proposal
async fn cancel_proposal(
    State(state): State<Arc<GovernanceApiState>>,
    Path(proposal_id): Path<u64>,
) -> Result<Json<VoteResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Cancel proposal request: {}", proposal_id);

    Ok(Json(VoteResponse {
        success: true,
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.governance_address.clone(),
            function_name: "cancel_proposal".to_string(),
            calldata: vec![
                proposal_id.to_string(),
                "0".to_string(),
            ],
        }),
    }))
}

/// Get voting power for an address
async fn get_voting_power(
    State(state): State<Arc<GovernanceApiState>>,
    Path(address): Path<String>,
) -> Result<Json<VotingPowerInfo>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting voting power for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Query from database if available
    if let Some(ref pool) = state.db_pool {
        // Query token balance and delegations
        let result = sqlx::query(
            r#"
            SELECT
                COALESCE(b.balance, 0)::text as balance,
                d.delegate_to,
                COALESCE(r.received_amount, 0)::text as received_delegations
            FROM (SELECT $1::text as address) addr
            LEFT JOIN token_balances b ON b.address = addr.address AND b.token_address = $2
            LEFT JOIN delegations d ON d.from_address = addr.address
            LEFT JOIN (
                SELECT to_address, SUM(amount) as received_amount
                FROM delegations
                WHERE to_address = $1
                GROUP BY to_address
            ) r ON r.to_address = addr.address
            "#
        )
        .bind(&address)
        .bind(&state.sage_token_address)
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = result {
            use sqlx::Row;
            let balance: String = row.try_get("balance").unwrap_or_else(|_| "0".to_string());
            let delegated_to: Option<String> = row.try_get("delegate_to").ok();
            let received: String = row.try_get("received_delegations").unwrap_or_else(|_| "0".to_string());

            // Calculate total voting power (balance + received delegations - delegated out)
            let balance_f: f64 = balance.parse().unwrap_or(0.0);
            let received_f: f64 = received.parse().unwrap_or(0.0);

            let voting_power = if delegated_to.is_some() {
                received_f // Only received if delegated out
            } else {
                balance_f + received_f
            };

            // Proposal threshold is 100K SAGE
            let threshold: f64 = 100_000_000_000_000_000_000_000.0;
            let can_propose = voting_power >= threshold;

            return Ok(Json(VotingPowerInfo {
                address: address.clone(),
                voting_power: format!("{:.0}", voting_power),
                voting_power_formatted: format_voting_power(voting_power as u128),
                delegated_to,
                received_delegations: received,
                can_propose,
                proposal_threshold: "100000000000000000000000".to_string(),
            }));
        }
    }

    // Fallback to mock data
    Ok(Json(VotingPowerInfo {
        address: address.clone(),
        voting_power: "1500000000000000000000000".to_string(), // 1.5M SAGE
        voting_power_formatted: "1,500,000 SAGE".to_string(),
        delegated_to: None,
        received_delegations: "500000000000000000000000".to_string(), // 500K
        can_propose: true,
        proposal_threshold: "100000000000000000000000".to_string(), // 100K
    }))
}

/// Format voting power for display
fn format_voting_power(wei: u128) -> String {
    let sage = wei as f64 / 1e18;
    if sage >= 1_000_000.0 {
        format!("{:.2}M SAGE", sage / 1_000_000.0)
    } else if sage >= 1_000.0 {
        // Format with thousands separator manually
        let formatted = format!("{:.0}", sage);
        let chars: Vec<_> = formatted.chars().collect();
        let mut result = String::new();
        for (i, c) in chars.iter().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(*c);
        }
        format!("{} SAGE", result.chars().rev().collect::<String>())
    } else if sage >= 1.0 {
        format!("{:.2} SAGE", sage)
    } else {
        "0 SAGE".to_string()
    }
}

/// Get delegations for an address
async fn get_delegations(
    State(state): State<Arc<GovernanceApiState>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<DelegationInfo>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting delegations for: {}", address);

    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Query from database if available
    if let Some(ref pool) = state.db_pool {
        let result = sqlx::query(
            r#"
            SELECT from_address, to_address, amount::text,
                   EXTRACT(EPOCH FROM created_at)::bigint as timestamp
            FROM delegations
            WHERE to_address = $1 OR from_address = $1
            ORDER BY created_at DESC
            LIMIT 100
            "#
        )
        .bind(&address)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = result {
            use sqlx::Row;
            let delegations: Vec<DelegationInfo> = rows.iter().map(|row| {
                DelegationInfo {
                    from: row.get::<String, _>("from_address"),
                    to: row.get::<String, _>("to_address"),
                    amount: row.get::<String, _>("amount"),
                    timestamp: row.get::<i64, _>("timestamp") as u64,
                }
            }).collect();

            if !delegations.is_empty() {
                return Ok(Json(delegations));
            }
        }
    }

    // Fallback to mock data
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let delegations = vec![
        DelegationInfo {
            from: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            to: address.clone(),
            amount: "250000000000000000000000".to_string(),
            timestamp: now - 86400 * 7,
        },
        DelegationInfo {
            from: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            to: address.clone(),
            amount: "250000000000000000000000".to_string(),
            timestamp: now - 86400 * 3,
        },
    ];

    Ok(Json(delegations))
}

/// Delegate votes
async fn delegate_votes(
    State(state): State<Arc<GovernanceApiState>>,
    Json(request): Json<DelegateRequest>,
) -> Result<Json<VoteResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Delegate request: to={}", request.delegate_to);

    if !is_valid_starknet_address(&request.delegate_to) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid delegate address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Note: Delegation typically happens on the token contract, not governance
    Ok(Json(VoteResponse {
        success: true,
        message: "Transaction data ready for wallet signing".to_string(),
        transaction_data: Some(TransactionData {
            contract_address: state.sage_token_address.clone(),
            function_name: "delegate".to_string(),
            calldata: vec![request.delegate_to],
        }),
    }))
}

/// Get council members
async fn get_council_members(
    State(state): State<Arc<GovernanceApiState>>,
) -> Json<Vec<CouncilMember>> {
    debug!("Getting council members");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Query from database if available
    if let Some(ref pool) = state.db_pool {
        let result = sqlx::query(
            r#"
            SELECT
                c.address,
                c.is_emergency_council,
                EXTRACT(EPOCH FROM c.added_at)::bigint as added_at,
                COALESCE(p.proposal_count, 0)::integer as proposals_created,
                COALESCE(v.vote_count, 0)::integer as votes_cast
            FROM council_members c
            LEFT JOIN (
                SELECT proposer_address, COUNT(*) as proposal_count
                FROM proposals
                GROUP BY proposer_address
            ) p ON p.proposer_address = c.address
            LEFT JOIN (
                SELECT voter_address, COUNT(*) as vote_count
                FROM votes
                GROUP BY voter_address
            ) v ON v.voter_address = c.address
            WHERE c.is_active = true
            ORDER BY c.added_at ASC
            "#
        )
        .fetch_all(pool)
        .await;

        if let Ok(rows) = result {
            use sqlx::Row;
            let members: Vec<CouncilMember> = rows.iter().map(|row| {
                CouncilMember {
                    address: row.get::<String, _>("address"),
                    is_emergency_council: row.get::<bool, _>("is_emergency_council"),
                    added_at: row.get::<i64, _>("added_at") as u64,
                    proposals_created: row.get::<i32, _>("proposals_created") as u32,
                    votes_cast: row.get::<i32, _>("votes_cast") as u32,
                }
            }).collect();

            if !members.is_empty() {
                return Json(members);
            }
        }
    }

    // Fallback to mock data
    let members = vec![
        CouncilMember {
            address: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string(),
            is_emergency_council: true,
            added_at: now - 86400 * 30,
            proposals_created: 5,
            votes_cast: 12,
        },
        CouncilMember {
            address: "0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691".to_string(),
            is_emergency_council: true,
            added_at: now - 86400 * 30,
            proposals_created: 3,
            votes_cast: 10,
        },
        CouncilMember {
            address: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            is_emergency_council: false,
            added_at: now - 86400 * 15,
            proposals_created: 1,
            votes_cast: 8,
        },
    ];

    Json(members)
}

/// Get governance stats
async fn get_governance_stats(
    State(state): State<Arc<GovernanceApiState>>,
) -> Json<GovernanceStats> {
    debug!("Getting governance stats");

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        // Query proposal counts
        let proposal_stats = sqlx::query(
            r#"
            SELECT
                COUNT(*)::bigint as total_proposals,
                COUNT(*) FILTER (WHERE status = 'active')::integer as active_proposals,
                COUNT(*) FILTER (WHERE status = 'executed')::integer as proposals_executed,
                COUNT(*) FILTER (WHERE status = 'rejected' OR status = 'defeated')::integer as proposals_defeated
            FROM proposals
            "#
        )
        .fetch_one(pool)
        .await;

        // Query vote counts
        let vote_stats = sqlx::query(
            r#"
            SELECT
                COUNT(*)::bigint as total_votes,
                COUNT(DISTINCT voter_address)::bigint as unique_voters,
                COALESCE(SUM(voting_power), 0)::text as total_voting_power
            FROM votes
            "#
        )
        .fetch_one(pool)
        .await;

        // Query quorum achievement rate and turnout
        let quorum_stats = sqlx::query(
            r#"
            WITH proposal_turnout AS (
                SELECT
                    p.proposal_id,
                    p.quorum_required,
                    COALESCE(p.for_votes, 0) + COALESCE(p.against_votes, 0) + COALESCE(p.abstain_votes, 0) as total_votes,
                    CASE WHEN COALESCE(p.for_votes, 0) + COALESCE(p.against_votes, 0) + COALESCE(p.abstain_votes, 0) >= p.quorum_required
                         THEN 1 ELSE 0 END as quorum_reached
                FROM proposals p
                WHERE p.status NOT IN ('pending', 'cancelled')
            )
            SELECT
                COALESCE(AVG(quorum_reached) * 100, 0)::float as quorum_pct,
                COALESCE(AVG(CASE WHEN quorum_required > 0
                    THEN (total_votes::float / quorum_required::float) * 100
                    ELSE 0 END), 0)::float as avg_turnout
            FROM proposal_turnout
            "#
        )
        .fetch_optional(pool)
        .await;

        if let (Ok(proposals), Ok(votes)) = (proposal_stats, vote_stats) {
            use sqlx::Row;

            let total_proposals: i64 = proposals.get("total_proposals");
            let active_proposals: i32 = proposals.get("active_proposals");
            let proposals_executed: i32 = proposals.get("proposals_executed");
            let proposals_defeated: i32 = proposals.get("proposals_defeated");
            let total_votes: i64 = votes.get("total_votes");
            let unique_voters: i64 = votes.get("unique_voters");
            let total_voting_power: String = votes.get("total_voting_power");

            // Get quorum and turnout stats
            let (quorum_percentage, avg_turnout) = if let Ok(Some(qs)) = quorum_stats {
                (
                    qs.try_get::<f64, _>("quorum_pct").unwrap_or(0.0),
                    qs.try_get::<f64, _>("avg_turnout").unwrap_or(0.0),
                )
            } else {
                // Fallback calculation
                let avg_turnout = if total_proposals > 0 {
                    (unique_voters as f64 / total_proposals as f64) * 10.0
                } else {
                    0.0
                };
                (0.0, avg_turnout)
            };

            return Json(GovernanceStats {
                total_proposals: total_proposals as u64,
                active_proposals: active_proposals as u32,
                total_votes_cast: total_votes as u64,
                unique_voters: unique_voters as u64,
                total_voting_power,
                quorum_percentage,
                avg_voter_turnout: avg_turnout,
                proposals_executed: proposals_executed as u32,
                proposals_defeated: proposals_defeated as u32,
            });
        }
    }

    // Fallback to mock data
    Json(GovernanceStats {
        total_proposals: 15,
        active_proposals: 2,
        total_votes_cast: 1250,
        unique_voters: 342,
        total_voting_power: "50000000000000000000000000".to_string(),
        quorum_percentage: 65.0,
        avg_voter_turnout: 45.2,
        proposals_executed: 10,
        proposals_defeated: 3,
    })
}

/// Get governance config
async fn get_governance_config(
    State(state): State<Arc<GovernanceApiState>>,
) -> Json<GovernanceConfig> {
    debug!("Getting governance config");

    // Query config from database - derive from proposal data and blockchain events
    if let Some(pool) = &state.db_pool {
        // Get quorum threshold from existing proposals (most common value)
        let config_query = sqlx::query(
            r#"
            WITH proposal_config AS (
                SELECT
                    quorum_required,
                    end_block - start_block as voting_blocks,
                    COUNT(*) as usage_count
                FROM proposals
                WHERE quorum_required IS NOT NULL AND start_block IS NOT NULL AND end_block IS NOT NULL
                GROUP BY quorum_required, end_block - start_block
                ORDER BY usage_count DESC
                LIMIT 1
            ),
            council_info AS (
                SELECT
                    COUNT(DISTINCT voter_address) as council_count
                FROM votes v
                JOIN proposals p ON v.proposal_id = p.proposal_id
                WHERE p.proposal_type = 'emergency'
            )
            SELECT
                COALESCE(pc.quorum_required::text, '10000000000000000000000000') as quorum_threshold,
                COALESCE(pc.voting_blocks, 21600) as voting_blocks,
                COALESCE(ci.council_count, 3) as council_count
            FROM (SELECT 1) dummy
            LEFT JOIN proposal_config pc ON true
            LEFT JOIN council_info ci ON true
            "#
        )
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = config_query {
            use sqlx::Row;

            let quorum_threshold: String = row.try_get("quorum_threshold")
                .unwrap_or_else(|_| "10000000000000000000000000".to_string());
            let voting_blocks: i64 = row.try_get("voting_blocks").unwrap_or(21600);
            let council_count: i64 = row.try_get("council_count").unwrap_or(3);

            // Convert blocks to seconds (assuming ~12 second block time on Starknet)
            let block_time_secs: u64 = 12;
            let voting_period_secs = (voting_blocks as u64) * block_time_secs;

            // Format quorum threshold for display
            let quorum_formatted = format_sage_amount(&quorum_threshold);

            // Proposal threshold is typically 1% of quorum (100K SAGE default)
            let proposal_threshold = "100000000000000000000000".to_string();

            return Json(GovernanceConfig {
                voting_delay_secs: 86400,      // 1 day (7200 blocks)
                voting_period_secs,
                execution_delay_secs: 172800,  // 2 days timelock
                quorum_threshold,
                quorum_threshold_formatted: quorum_formatted,
                proposal_threshold: proposal_threshold.clone(),
                proposal_threshold_formatted: "100,000 SAGE".to_string(),
                council_count: council_count as u32,
                council_threshold: ((council_count as u32) / 2) + 1, // Majority
            });
        }
    }

    // Default config if database unavailable
    Json(GovernanceConfig {
        voting_delay_secs: 86400,      // 1 day
        voting_period_secs: 259200,    // 3 days
        execution_delay_secs: 172800,  // 2 days (timelock)
        quorum_threshold: "10000000000000000000000000".to_string(), // 10M SAGE
        quorum_threshold_formatted: "10,000,000 SAGE".to_string(),
        proposal_threshold: "100000000000000000000000".to_string(), // 100K SAGE
        proposal_threshold_formatted: "100,000 SAGE".to_string(),
        council_count: 3,
        council_threshold: 2,
    })
}

/// Format SAGE amount with 18 decimals for display
fn format_sage_amount(amount: &str) -> String {
    // Parse the amount and divide by 10^18
    if let Ok(val) = amount.parse::<u128>() {
        let sage_amount = val / 1_000_000_000_000_000_000u128;
        // Format with thousands separators
        let formatted = sage_amount.to_string();
        let chars: Vec<char> = formatted.chars().rev().collect();
        let with_commas: String = chars
            .chunks(3)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(",")
            .chars()
            .rev()
            .collect();
        format!("{} SAGE", with_commas)
    } else {
        "10,000,000 SAGE".to_string()
    }
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
