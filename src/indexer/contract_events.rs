//! # Contract Events
//!
//! Type definitions for all indexed contract events.
//! These structures map to the database schema.

use serde::{Deserialize, Serialize};

// ============================================================================
// Job Manager Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSubmittedEvent {
    pub job_id: String,
    pub client_address: String,
    pub job_type: String,
    pub payment_amount: String,
    pub priority: u32,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAssignedEvent {
    pub job_id: String,
    pub worker_address: String,
    pub assigned_at: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCompletedEvent {
    pub job_id: String,
    pub worker_address: String,
    pub result_hash: String,
    pub execution_time_ms: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCancelledEvent {
    pub job_id: String,
    pub reason: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReleasedEvent {
    pub job_id: String,
    pub worker_address: String,
    pub amount: String,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Staking Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakedEvent {
    pub worker_address: String,
    pub worker_id: String,
    pub amount: String,
    pub gpu_tier: String,
    pub has_tee: bool,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnstakedEvent {
    pub worker_address: String,
    pub amount: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnstakeInitiatedEvent {
    pub worker_address: String,
    pub amount: String,
    pub unlock_time: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashedEvent {
    pub worker_address: String,
    pub amount: String,
    pub reason: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeIncreasedEvent {
    pub worker_address: String,
    pub additional_amount: String,
    pub new_total: String,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// OTC Orderbook Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderPlacedEvent {
    pub order_id: String,
    pub maker_address: String,
    pub pair_id: u32,
    pub side: String, // "buy" or "sell"
    pub price: String,
    pub amount: String,
    pub expires_at: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderFilledEvent {
    pub order_id: String,
    pub taker_address: String,
    pub filled_amount: String,
    pub remaining_amount: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderCancelledEvent {
    pub order_id: String,
    pub maker_address: String,
    pub refund_amount: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeExecutedEvent {
    pub trade_id: String,
    pub pair_id: u32,
    pub maker_order_id: String,
    pub taker_order_id: Option<String>,
    pub maker_address: String,
    pub taker_address: String,
    pub price: String,
    pub amount: String,
    pub quote_amount: String,
    pub side: String,
    pub maker_fee: String,
    pub taker_fee: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairAddedEvent {
    pub pair_id: u32,
    pub base_token: String,
    pub quote_token: String,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Governance Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalCreatedEvent {
    pub proposal_id: String,
    pub proposer_address: String,
    pub proposal_type: String,
    pub title: String,
    pub description: Option<String>,
    pub start_block: u64,
    pub end_block: u64,
    pub quorum_required: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteCastEvent {
    pub proposal_id: String,
    pub voter_address: String,
    pub support: u8, // 0 = against, 1 = for, 2 = abstain
    pub voting_power: String,
    pub reason: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalExecutedEvent {
    pub proposal_id: String,
    pub executor_address: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalCancelledEvent {
    pub proposal_id: String,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Privacy (Obelysk) Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateTransferInitiatedEvent {
    pub nullifier: String,
    pub sender_address: Option<String>,
    pub encrypted_amount: String,
    pub commitment: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateTransferCompletedEvent {
    pub nullifier: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAddressRegisteredEvent {
    pub owner_address: String,
    pub stealth_address: String,
    pub ephemeral_pubkey: String,
    pub view_tag: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateDepositEvent {
    pub depositor: String,
    pub commitment: String,
    pub amount: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateWithdrawalEvent {
    pub nullifier: String,
    pub recipient: String,
    pub amount: String,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Proof Verifier Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSubmittedEvent {
    pub job_id: String,
    pub worker_address: String,
    pub proof_hash: String,
    pub proof_type: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofVerifiedEvent {
    pub job_id: String,
    pub worker_address: String,
    pub proof_hash: String,
    pub is_valid: bool,
    pub verification_time_ms: u32,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRejectedEvent {
    pub job_id: String,
    pub worker_address: String,
    pub proof_hash: String,
    pub reason: String,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Reputation Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationUpdatedEvent {
    pub worker_address: String,
    pub old_score: u32,
    pub new_score: u32,
    pub reason: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegisteredEvent {
    pub worker_address: String,
    pub worker_id: String,
    pub initial_score: u32,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Referral Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferrerRegisteredEvent {
    pub referrer_address: String,
    pub referral_code: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferralRecordedEvent {
    pub referrer_address: String,
    pub referred_address: String,
    pub referral_code: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommissionPaidEvent {
    pub referrer_address: String,
    pub referred_address: String,
    pub amount: String,
    pub trade_volume: String,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Faucet Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetClaimedEvent {
    pub claimer_address: String,
    pub amount: String,
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetConfigUpdatedEvent {
    pub drip_amount: String,
    pub cooldown_secs: u64,
    pub tx_hash: String,
    pub block_number: u64,
}

// ============================================================================
// Generic Event Wrapper
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IndexedEvent {
    // Job Manager
    JobSubmitted(JobSubmittedEvent),
    JobAssigned(JobAssignedEvent),
    JobCompleted(JobCompletedEvent),
    JobCancelled(JobCancelledEvent),
    PaymentReleased(PaymentReleasedEvent),
    
    // Staking
    Staked(StakedEvent),
    Unstaked(UnstakedEvent),
    UnstakeInitiated(UnstakeInitiatedEvent),
    Slashed(SlashedEvent),
    StakeIncreased(StakeIncreasedEvent),
    
    // OTC
    OrderPlaced(OrderPlacedEvent),
    OrderFilled(OrderFilledEvent),
    OrderCancelled(OrderCancelledEvent),
    TradeExecuted(TradeExecutedEvent),
    PairAdded(PairAddedEvent),
    
    // Governance
    ProposalCreated(ProposalCreatedEvent),
    VoteCast(VoteCastEvent),
    ProposalExecuted(ProposalExecutedEvent),
    ProposalCancelled(ProposalCancelledEvent),
    
    // Privacy
    PrivateTransferInitiated(PrivateTransferInitiatedEvent),
    PrivateTransferCompleted(PrivateTransferCompletedEvent),
    StealthAddressRegistered(StealthAddressRegisteredEvent),
    PrivateDeposit(PrivateDepositEvent),
    PrivateWithdrawal(PrivateWithdrawalEvent),
    
    // Proofs
    ProofSubmitted(ProofSubmittedEvent),
    ProofVerified(ProofVerifiedEvent),
    ProofRejected(ProofRejectedEvent),
    
    // Reputation
    ReputationUpdated(ReputationUpdatedEvent),
    WorkerRegistered(WorkerRegisteredEvent),
    
    // Referral
    ReferrerRegistered(ReferrerRegisteredEvent),
    ReferralRecorded(ReferralRecordedEvent),
    CommissionPaid(CommissionPaidEvent),
    
    // Faucet
    FaucetClaimed(FaucetClaimedEvent),
    FaucetConfigUpdated(FaucetConfigUpdatedEvent),
}

impl IndexedEvent {
    /// Get the event type name
    pub fn event_type(&self) -> &'static str {
        match self {
            IndexedEvent::JobSubmitted(_) => "JobSubmitted",
            IndexedEvent::JobAssigned(_) => "JobAssigned",
            IndexedEvent::JobCompleted(_) => "JobCompleted",
            IndexedEvent::JobCancelled(_) => "JobCancelled",
            IndexedEvent::PaymentReleased(_) => "PaymentReleased",
            IndexedEvent::Staked(_) => "Staked",
            IndexedEvent::Unstaked(_) => "Unstaked",
            IndexedEvent::UnstakeInitiated(_) => "UnstakeInitiated",
            IndexedEvent::Slashed(_) => "Slashed",
            IndexedEvent::StakeIncreased(_) => "StakeIncreased",
            IndexedEvent::OrderPlaced(_) => "OrderPlaced",
            IndexedEvent::OrderFilled(_) => "OrderFilled",
            IndexedEvent::OrderCancelled(_) => "OrderCancelled",
            IndexedEvent::TradeExecuted(_) => "TradeExecuted",
            IndexedEvent::PairAdded(_) => "PairAdded",
            IndexedEvent::ProposalCreated(_) => "ProposalCreated",
            IndexedEvent::VoteCast(_) => "VoteCast",
            IndexedEvent::ProposalExecuted(_) => "ProposalExecuted",
            IndexedEvent::ProposalCancelled(_) => "ProposalCancelled",
            IndexedEvent::PrivateTransferInitiated(_) => "PrivateTransferInitiated",
            IndexedEvent::PrivateTransferCompleted(_) => "PrivateTransferCompleted",
            IndexedEvent::StealthAddressRegistered(_) => "StealthAddressRegistered",
            IndexedEvent::PrivateDeposit(_) => "PrivateDeposit",
            IndexedEvent::PrivateWithdrawal(_) => "PrivateWithdrawal",
            IndexedEvent::ProofSubmitted(_) => "ProofSubmitted",
            IndexedEvent::ProofVerified(_) => "ProofVerified",
            IndexedEvent::ProofRejected(_) => "ProofRejected",
            IndexedEvent::ReputationUpdated(_) => "ReputationUpdated",
            IndexedEvent::WorkerRegistered(_) => "WorkerRegistered",
            IndexedEvent::ReferrerRegistered(_) => "ReferrerRegistered",
            IndexedEvent::ReferralRecorded(_) => "ReferralRecorded",
            IndexedEvent::CommissionPaid(_) => "CommissionPaid",
            IndexedEvent::FaucetClaimed(_) => "FaucetClaimed",
            IndexedEvent::FaucetConfigUpdated(_) => "FaucetConfigUpdated",
        }
    }
    
    /// Get the contract name for this event
    pub fn contract_name(&self) -> &'static str {
        match self {
            IndexedEvent::JobSubmitted(_) |
            IndexedEvent::JobAssigned(_) |
            IndexedEvent::JobCompleted(_) |
            IndexedEvent::JobCancelled(_) |
            IndexedEvent::PaymentReleased(_) => "JobManager",
            
            IndexedEvent::Staked(_) |
            IndexedEvent::Unstaked(_) |
            IndexedEvent::UnstakeInitiated(_) |
            IndexedEvent::Slashed(_) |
            IndexedEvent::StakeIncreased(_) => "Staking",
            
            IndexedEvent::OrderPlaced(_) |
            IndexedEvent::OrderFilled(_) |
            IndexedEvent::OrderCancelled(_) |
            IndexedEvent::TradeExecuted(_) |
            IndexedEvent::PairAdded(_) => "OTCOrderbook",
            
            IndexedEvent::ProposalCreated(_) |
            IndexedEvent::VoteCast(_) |
            IndexedEvent::ProposalExecuted(_) |
            IndexedEvent::ProposalCancelled(_) => "Governance",
            
            IndexedEvent::PrivateTransferInitiated(_) |
            IndexedEvent::PrivateTransferCompleted(_) |
            IndexedEvent::StealthAddressRegistered(_) |
            IndexedEvent::PrivateDeposit(_) |
            IndexedEvent::PrivateWithdrawal(_) => "PrivacyRouter",
            
            IndexedEvent::ProofSubmitted(_) |
            IndexedEvent::ProofVerified(_) |
            IndexedEvent::ProofRejected(_) => "ProofVerifier",
            
            IndexedEvent::ReputationUpdated(_) |
            IndexedEvent::WorkerRegistered(_) => "Reputation",
            
            IndexedEvent::ReferrerRegistered(_) |
            IndexedEvent::ReferralRecorded(_) |
            IndexedEvent::CommissionPaid(_) => "Referral",
            
            IndexedEvent::FaucetClaimed(_) |
            IndexedEvent::FaucetConfigUpdated(_) => "Faucet",
        }
    }
    
    /// Get the block number from any event
    pub fn block_number(&self) -> u64 {
        match self {
            IndexedEvent::JobSubmitted(e) => e.block_number,
            IndexedEvent::JobAssigned(e) => e.block_number,
            IndexedEvent::JobCompleted(e) => e.block_number,
            IndexedEvent::JobCancelled(e) => e.block_number,
            IndexedEvent::PaymentReleased(e) => e.block_number,
            IndexedEvent::Staked(e) => e.block_number,
            IndexedEvent::Unstaked(e) => e.block_number,
            IndexedEvent::UnstakeInitiated(e) => e.block_number,
            IndexedEvent::Slashed(e) => e.block_number,
            IndexedEvent::StakeIncreased(e) => e.block_number,
            IndexedEvent::OrderPlaced(e) => e.block_number,
            IndexedEvent::OrderFilled(e) => e.block_number,
            IndexedEvent::OrderCancelled(e) => e.block_number,
            IndexedEvent::TradeExecuted(e) => e.block_number,
            IndexedEvent::PairAdded(e) => e.block_number,
            IndexedEvent::ProposalCreated(e) => e.block_number,
            IndexedEvent::VoteCast(e) => e.block_number,
            IndexedEvent::ProposalExecuted(e) => e.block_number,
            IndexedEvent::ProposalCancelled(e) => e.block_number,
            IndexedEvent::PrivateTransferInitiated(e) => e.block_number,
            IndexedEvent::PrivateTransferCompleted(e) => e.block_number,
            IndexedEvent::StealthAddressRegistered(e) => e.block_number,
            IndexedEvent::PrivateDeposit(e) => e.block_number,
            IndexedEvent::PrivateWithdrawal(e) => e.block_number,
            IndexedEvent::ProofSubmitted(e) => e.block_number,
            IndexedEvent::ProofVerified(e) => e.block_number,
            IndexedEvent::ProofRejected(e) => e.block_number,
            IndexedEvent::ReputationUpdated(e) => e.block_number,
            IndexedEvent::WorkerRegistered(e) => e.block_number,
            IndexedEvent::ReferrerRegistered(e) => e.block_number,
            IndexedEvent::ReferralRecorded(e) => e.block_number,
            IndexedEvent::CommissionPaid(e) => e.block_number,
            IndexedEvent::FaucetClaimed(e) => e.block_number,
            IndexedEvent::FaucetConfigUpdated(e) => e.block_number,
        }
    }
    
    /// Get the transaction hash from any event
    pub fn tx_hash(&self) -> &str {
        match self {
            IndexedEvent::JobSubmitted(e) => &e.tx_hash,
            IndexedEvent::JobAssigned(e) => &e.tx_hash,
            IndexedEvent::JobCompleted(e) => &e.tx_hash,
            IndexedEvent::JobCancelled(e) => &e.tx_hash,
            IndexedEvent::PaymentReleased(e) => &e.tx_hash,
            IndexedEvent::Staked(e) => &e.tx_hash,
            IndexedEvent::Unstaked(e) => &e.tx_hash,
            IndexedEvent::UnstakeInitiated(e) => &e.tx_hash,
            IndexedEvent::Slashed(e) => &e.tx_hash,
            IndexedEvent::StakeIncreased(e) => &e.tx_hash,
            IndexedEvent::OrderPlaced(e) => &e.tx_hash,
            IndexedEvent::OrderFilled(e) => &e.tx_hash,
            IndexedEvent::OrderCancelled(e) => &e.tx_hash,
            IndexedEvent::TradeExecuted(e) => &e.tx_hash,
            IndexedEvent::PairAdded(e) => &e.tx_hash,
            IndexedEvent::ProposalCreated(e) => &e.tx_hash,
            IndexedEvent::VoteCast(e) => &e.tx_hash,
            IndexedEvent::ProposalExecuted(e) => &e.tx_hash,
            IndexedEvent::ProposalCancelled(e) => &e.tx_hash,
            IndexedEvent::PrivateTransferInitiated(e) => &e.tx_hash,
            IndexedEvent::PrivateTransferCompleted(e) => &e.tx_hash,
            IndexedEvent::StealthAddressRegistered(e) => &e.tx_hash,
            IndexedEvent::PrivateDeposit(e) => &e.tx_hash,
            IndexedEvent::PrivateWithdrawal(e) => &e.tx_hash,
            IndexedEvent::ProofSubmitted(e) => &e.tx_hash,
            IndexedEvent::ProofVerified(e) => &e.tx_hash,
            IndexedEvent::ProofRejected(e) => &e.tx_hash,
            IndexedEvent::ReputationUpdated(e) => &e.tx_hash,
            IndexedEvent::WorkerRegistered(e) => &e.tx_hash,
            IndexedEvent::ReferrerRegistered(e) => &e.tx_hash,
            IndexedEvent::ReferralRecorded(e) => &e.tx_hash,
            IndexedEvent::CommissionPaid(e) => &e.tx_hash,
            IndexedEvent::FaucetClaimed(e) => &e.tx_hash,
            IndexedEvent::FaucetConfigUpdated(e) => &e.tx_hash,
        }
    }
}
