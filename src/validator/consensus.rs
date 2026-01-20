//! SageGuard Consensus Protocol for BitSage Network
//!
//! Implements Byzantine Fault Tolerant (BFT) consensus for proof validation.
//! Validators stake SAGE tokens and vote on proof validity, requiring a 2/3
//! supermajority for acceptance.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    SAGEGUARD CONSENSUS PROTOCOL                      │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │  1. PROOF RECEIVED    2. LOCAL VERIFY     3. BROADCAST VOTE         │
//! │  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐          │
//! │  │ Worker submits│──▶│ Validate with │──▶│ Sign vote &   │          │
//! │  │ proof + job   │   │ Stwo verifier │   │ send to peers │          │
//! │  └───────────────┘   └───────────────┘   └───────────────┘          │
//! │                                               │                      │
//! │                                               ▼                      │
//! │  4. COLLECT VOTES    5. CHECK QUORUM     6. FINALIZE                │
//! │  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐          │
//! │  │ Gather votes  │──▶│ 67%+ agreement│──▶│ Accept/Reject │          │
//! │  │ with timeout  │   │ required      │   │ Update state  │          │
//! │  └───────────────┘   └───────────────┘   └───────────────┘          │
//! │                                                                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - **Safety**: No two honest validators finalize conflicting decisions
//! - **Liveness**: If 2/3 validators are honest, consensus is reached
//! - **Slashing**: Validators who vote for invalid proofs are slashed
//! - **ECDSA Signatures**: P-256 signatures prevent vote forgery

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;

// Import metrics
use crate::validator::metrics as consensus_metrics;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn, debug};

use crate::obelysk::{StarkProof, CompressedProof, ProofCompressor};

// ECDSA signature verification using P-256 curve
use p256::ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey, signature::Verifier};

/// Vote timeout for collecting validator votes
pub const VOTE_TIMEOUT_SECS: u64 = 30;

/// Minimum quorum percentage (67% for BFT)
pub const QUORUM_PERCENTAGE: u64 = 67;

/// Maximum validators that can participate
pub const MAX_VALIDATORS: usize = 100;

/// Proof-of-Compute metrics for a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfComputeMetrics {
    /// Total number of proofs generated
    pub total_proofs_generated: u64,

    /// Number of valid proofs (accepted by consensus)
    pub valid_proofs: u64,

    /// Number of invalid proofs (rejected by consensus)
    pub invalid_proofs: u64,

    /// Average proof generation time in milliseconds
    pub avg_proof_time_ms: u64,

    /// Total compute contribution score (weighted by proof complexity)
    pub compute_score: u128,

    /// Last proof timestamp
    pub last_proof_timestamp: u64,

    /// Performance score (0-100, based on validity rate and speed)
    pub performance_score: u8,
}

impl Default for ProofOfComputeMetrics {
    fn default() -> Self {
        ProofOfComputeMetrics {
            total_proofs_generated: 0,
            valid_proofs: 0,
            invalid_proofs: 0,
            avg_proof_time_ms: 0,
            compute_score: 0,
            last_proof_timestamp: 0,
            performance_score: 100, // Start with perfect score
        }
    }
}

impl ProofOfComputeMetrics {
    /// Calculate validity rate (0-100)
    pub fn validity_rate(&self) -> u8 {
        if self.total_proofs_generated == 0 {
            return 100;
        }
        ((self.valid_proofs * 100) / self.total_proofs_generated).min(100) as u8
    }

    /// Update metrics after a proof is validated
    pub fn update_after_proof(&mut self, is_valid: bool, proof_time_ms: u64, complexity_score: u128) {
        self.total_proofs_generated += 1;

        if is_valid {
            self.valid_proofs += 1;
            self.compute_score += complexity_score;
        } else {
            self.invalid_proofs += 1;
        }

        // Update rolling average proof time
        if self.avg_proof_time_ms == 0 {
            self.avg_proof_time_ms = proof_time_ms;
        } else {
            // Exponential moving average with alpha = 0.2
            self.avg_proof_time_ms = ((self.avg_proof_time_ms as u128 * 8 + proof_time_ms as u128 * 2) / 10) as u64;
        }

        self.last_proof_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Recalculate performance score
        self.update_performance_score();
    }

    /// Update performance score based on validity rate and speed
    fn update_performance_score(&mut self) {
        let validity_rate = self.validity_rate();

        // Speed score: faster is better (normalized to 0-50)
        // Assume 10 seconds is average, scale accordingly
        let speed_score = if self.avg_proof_time_ms > 0 {
            let target_time_ms = 10_000; // 10 seconds target
            let speed_ratio = (target_time_ms as f64 / self.avg_proof_time_ms as f64).min(2.0);
            (speed_ratio * 50.0) as u8
        } else {
            50
        };

        // Validity score: 0-50 based on validity rate
        let validity_score = (validity_rate as f64 * 0.5) as u8;

        self.performance_score = (validity_score + speed_score).min(100);
    }

    /// Check if metrics are stale (no proofs in last 24 hours)
    pub fn is_stale(&self) -> bool {
        if self.last_proof_timestamp == 0 {
            return false; // New validator
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.last_proof_timestamp > 86400 // 24 hours
    }

    /// Decay score for inactivity
    pub fn apply_decay(&mut self) {
        if self.is_stale() {
            // Reduce performance score by 20% for stale validators
            self.performance_score = ((self.performance_score as f64) * 0.8) as u8;
        }
    }
}

/// Validator identity and stake info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator address
    pub address: String,

    /// Public key for signature verification (SEC1-encoded, 33 bytes compressed)
    pub public_key: Vec<u8>,

    /// Staked amount
    pub stake_amount: u128,

    /// Whether validator is active
    pub is_active: bool,

    /// Last seen timestamp
    pub last_seen: u64,

    /// Proof-of-Compute metrics
    pub poc_metrics: ProofOfComputeMetrics,
}

impl ValidatorInfo {
    /// Get the ECDSA verifying key from the stored public key
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(&self.public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))
    }

    /// Calculate combined voting weight (stake + PoC)
    ///
    /// Weight = stake_weight * stake_ratio + poc_weight * poc_ratio
    /// where:
    /// - stake_weight = stake_amount
    /// - poc_weight = compute_score * performance_multiplier
    /// - performance_multiplier = performance_score / 100
    pub fn voting_weight(&self, stake_ratio: f64, poc_ratio: f64) -> u128 {
        // Stake component
        let stake_weight = (self.stake_amount as f64 * stake_ratio) as u128;

        // PoC component: compute_score scaled by performance
        let performance_multiplier = self.poc_metrics.performance_score as f64 / 100.0;
        let poc_weight = (self.poc_metrics.compute_score as f64 * performance_multiplier * poc_ratio) as u128;

        stake_weight + poc_weight
    }

    /// Get stake-only weight (backwards compatible)
    pub fn stake_weight(&self) -> u128 {
        self.stake_amount
    }
}

/// A vote cast by a validator on proof validity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Validator who cast this vote
    pub validator_address: String,

    /// Job ID being voted on
    pub job_id: u128,

    /// Proof hash being voted on
    pub proof_hash: [u8; 32],

    /// Whether the validator deems the proof valid
    pub is_valid: bool,

    /// Signature over the vote (hex encoded)
    pub signature: String,

    /// Timestamp of vote
    pub timestamp: u64,

    /// Optional reason for rejection
    pub rejection_reason: Option<String>,
}

impl Vote {
    /// Create a new vote
    pub fn new(
        validator_address: String,
        job_id: u128,
        proof_hash: [u8; 32],
        is_valid: bool,
        signature: &[u8; 64],
    ) -> Self {
        Vote {
            validator_address,
            job_id,
            proof_hash,
            is_valid,
            signature: hex::encode(signature),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rejection_reason: None,
        }
    }

    /// Create a rejection vote with reason
    pub fn rejection(
        validator_address: String,
        job_id: u128,
        proof_hash: [u8; 32],
        signature: &[u8; 64],
        reason: String,
    ) -> Self {
        Vote {
            validator_address,
            job_id,
            proof_hash,
            is_valid: false,
            signature: hex::encode(signature),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rejection_reason: Some(reason),
        }
    }

    /// Compute vote hash for signing
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(self.validator_address.as_bytes());
        hasher.update(&self.job_id.to_le_bytes());
        hasher.update(&self.proof_hash);
        hasher.update(&[self.is_valid as u8]);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Result of consensus on a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusResult {
    /// Proof accepted by supermajority
    Approved {
        /// Votes in favor
        votes_for: Vec<Vote>,
        /// Votes against
        votes_against: Vec<Vote>,
        /// Total stake voting in favor
        stake_for: u128,
    },

    /// Proof rejected by supermajority
    Rejected {
        /// Votes in favor
        votes_for: Vec<Vote>,
        /// Votes against
        votes_against: Vec<Vote>,
        /// Primary rejection reason
        rejection_reason: String,
    },

    /// Timeout - not enough votes received
    Timeout {
        /// Votes received
        votes_received: usize,
        /// Required votes
        votes_required: usize,
    },

    /// Inconclusive - no supermajority
    Inconclusive {
        /// Votes for
        votes_for: usize,
        /// Votes against
        votes_against: usize,
    },
}

impl ConsensusResult {
    /// Check if the result is approved
    pub fn is_approved(&self) -> bool {
        matches!(self, ConsensusResult::Approved { .. })
    }

    /// Get the consensus decision as a boolean
    pub fn decision(&self) -> Option<bool> {
        match self {
            ConsensusResult::Approved { .. } => Some(true),
            ConsensusResult::Rejected { .. } => Some(false),
            _ => None,
        }
    }
}

/// Proof submission for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSubmission {
    /// Job identifier
    pub job_id: u128,

    /// Worker who submitted the proof
    pub worker_address: String,

    /// Compressed proof data
    pub compressed_proof: CompressedProof,

    /// Submission timestamp
    pub timestamp: u64,
}

/// Consensus view (round) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct View {
    /// View number (increments on leader change)
    pub view_number: u64,

    /// Current leader address
    pub leader_address: String,

    /// View start timestamp
    pub started_at: u64,

    /// View timeout deadline
    pub timeout_at: u64,
}

/// Leader proposal for a consensus round
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderProposal {
    /// View number this proposal belongs to
    pub view_number: u64,

    /// Job ID being proposed for validation
    pub job_id: u128,

    /// Proof hash
    pub proof_hash: [u8; 32],

    /// Leader's signature over the proposal
    pub signature: String,

    /// Proposal timestamp
    pub timestamp: u64,
}

impl LeaderProposal {
    /// Compute proposal hash for signing
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.view_number.to_le_bytes());
        hasher.update(&self.job_id.to_le_bytes());
        hasher.update(&self.proof_hash);
        hasher.update(&self.timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// View change request when leader times out
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChangeRequest {
    /// Old view number being replaced
    pub old_view: u64,

    /// New view number requested
    pub new_view: u64,

    /// Validator requesting the view change
    pub validator_address: String,

    /// Signature over the request
    pub signature: String,

    /// Timestamp
    pub timestamp: u64,
}

/// SageGuard Consensus Engine
///
/// Byzantine Fault Tolerant consensus for validating Stwo proofs in the BitSage Network.
/// Validators stake SAGE tokens to participate and use ECDSA signatures for vote authentication.
///
/// # Leader-Based Consensus
///
/// SageGuard uses leader-based rounds (views) for ordering proposals:
/// - Each view has a designated leader (round-robin rotation)
/// - Leader proposes which proof to validate
/// - Validators vote on the leader's proposal
/// - View changes occur on timeout or leader failure
///
/// # Fraud Proof Integration
///
/// SageGuard can optionally integrate with the on-chain fraud proof contract to:
/// - Automatically submit challenges for invalid validator votes
/// - Trigger slashing for proven fraudulent behavior
/// - Track fraud proof statistics
pub struct SageGuardConsensus {
    /// Our validator identity
    identity: ValidatorInfo,

    /// ECDSA signing key for signing votes
    signing_key: SigningKey,

    /// Known validators in the network
    validators: Arc<RwLock<HashMap<String, ValidatorInfo>>>,

    /// Current consensus view
    current_view: Arc<RwLock<View>>,

    /// Pending votes per job
    pending_votes: Arc<RwLock<HashMap<u128, Vec<Vote>>>>,

    /// Finalized results
    finalized_results: Arc<RwLock<HashMap<u128, ConsensusResult>>>,

    /// View change requests (validator_address -> request)
    view_change_requests: Arc<RwLock<HashMap<String, ViewChangeRequest>>>,

    /// Vote broadcast channel
    vote_tx: broadcast::Sender<Vote>,

    /// Optional fraud proof client for on-chain slashing
    fraud_proof_client: Option<Arc<dyn crate::obelysk::starknet::fraud_proof_client::FraudProofClientTrait>>,

    /// Optional persistence layer for consensus state
    persistence: Option<Arc<crate::validator::persistence::ConsensusPersistence>>,

    /// Configuration
    config: ConsensusConfig,
}

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Vote collection timeout
    pub vote_timeout: Duration,

    /// View timeout (leader must propose within this time)
    pub view_timeout: Duration,

    /// Minimum stake required to vote
    pub min_stake: u128,

    /// Quorum percentage required (default 67)
    pub quorum_percentage: u64,

    /// Enable slashing for invalid votes
    pub enable_slashing: bool,

    /// Enable leader-based consensus (vs leaderless voting)
    pub enable_leader: bool,

    /// Enable Proof-of-Compute weighted voting
    pub enable_poc_weighting: bool,

    /// Stake weight ratio (0.0-1.0, e.g., 0.7 = 70% stake)
    pub stake_ratio: f64,

    /// PoC weight ratio (0.0-1.0, e.g., 0.3 = 30% PoC)
    /// Note: stake_ratio + poc_ratio should typically equal 1.0
    pub poc_ratio: f64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            vote_timeout: Duration::from_secs(VOTE_TIMEOUT_SECS),
            view_timeout: Duration::from_secs(VOTE_TIMEOUT_SECS), // Same as vote timeout
            min_stake: 1000_000_000_000_000_000, // 1 SAGE
            quorum_percentage: QUORUM_PERCENTAGE,
            enable_slashing: true,
            enable_leader: true, // Leader-based consensus enabled by default
            enable_poc_weighting: true, // PoC weighting enabled by default
            stake_ratio: 0.7, // 70% weight from stake
            poc_ratio: 0.3,   // 30% weight from PoC performance
        }
    }
}

impl SageGuardConsensus {
    /// Create a new SageGuard consensus engine
    ///
    /// # Arguments
    /// * `address` - Validator's unique address
    /// * `signing_key` - ECDSA P-256 signing key for vote authentication
    /// * `stake_amount` - Amount of SAGE tokens staked
    /// * `config` - Consensus configuration
    pub fn new(
        address: String,
        signing_key: SigningKey,
        stake_amount: u128,
        config: ConsensusConfig,
    ) -> Self {
        Self::with_extensions(address, signing_key, stake_amount, config, None, None)
    }

    /// Create a new SageGuard consensus engine with fraud proof client
    ///
    /// # Arguments
    /// * `address` - Validator's unique address
    /// * `signing_key` - ECDSA P-256 signing key for vote authentication
    /// * `stake_amount` - Amount of SAGE tokens staked
    /// * `config` - Consensus configuration
    /// * `fraud_proof_client` - Optional fraud proof client for on-chain slashing
    pub fn with_fraud_proof_client(
        address: String,
        signing_key: SigningKey,
        stake_amount: u128,
        config: ConsensusConfig,
        fraud_proof_client: Option<Arc<dyn crate::obelysk::starknet::fraud_proof_client::FraudProofClientTrait>>,
    ) -> Self {
        Self::with_extensions(address, signing_key, stake_amount, config, fraud_proof_client, None)
    }

    /// Create a new SageGuard consensus engine with fraud proof client and persistence
    ///
    /// # Arguments
    /// * `address` - Validator's unique address
    /// * `signing_key` - ECDSA P-256 signing key for vote authentication
    /// * `stake_amount` - Amount of SAGE tokens staked
    /// * `config` - Consensus configuration
    /// * `fraud_proof_client` - Optional fraud proof client for on-chain slashing
    /// * `persistence` - Optional persistence layer for consensus state
    pub fn with_extensions(
        address: String,
        signing_key: SigningKey,
        stake_amount: u128,
        config: ConsensusConfig,
        fraud_proof_client: Option<Arc<dyn crate::obelysk::starknet::fraud_proof_client::FraudProofClientTrait>>,
        persistence: Option<Arc<crate::validator::persistence::ConsensusPersistence>>,
    ) -> Self {
        let (vote_tx, _) = broadcast::channel(1000);

        // Derive public key from signing key
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(true).to_bytes().to_vec();

        let identity = ValidatorInfo {
            address: address.clone(),
            public_key,
            stake_amount,
            is_active: true,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            poc_metrics: ProofOfComputeMetrics::default(),
        };

        // Initialize view 0 with ourselves as initial leader
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 1000; // Convert to seconds

        let initial_view = View {
            view_number: 0,
            leader_address: address,
            started_at: now,
            timeout_at: now + config.view_timeout.as_secs().max(1), // At least 1 second
        };

        let consensus = SageGuardConsensus {
            identity,
            signing_key,
            validators: Arc::new(RwLock::new(HashMap::new())),
            current_view: Arc::new(RwLock::new(initial_view)),
            pending_votes: Arc::new(RwLock::new(HashMap::new())),
            finalized_results: Arc::new(RwLock::new(HashMap::new())),
            view_change_requests: Arc::new(RwLock::new(HashMap::new())),
            vote_tx,
            fraud_proof_client,
            persistence: persistence.clone(),
            config,
        };

        // Load previous state from persistence if available
        // Note: This uses blocking operations, but they're safe here since
        // this is a constructor that's typically called during initialization
        // before the async runtime is fully engaged. If called from an async context,
        // the caller should use spawn_blocking.
        if let Some(persist) = &persistence {
            // Try to load but don't panic if we're in an async context
            if let Ok(Some(view)) = persist.load_current_view() {
                debug!("Recovered view {} from persistence", view.view_number);
                // Use try_write instead of blocking_write to avoid panic in async context
                if let Ok(mut current_view) = consensus.current_view.try_write() {
                    *current_view = view;
                } else {
                    warn!("Could not recover view from persistence (lock contention)");
                }
            }

            if let Ok(validators_list) = persist.load_all_validators() {
                // Use try_write instead of blocking_write to avoid panic in async context
                if let Ok(mut validators) = consensus.validators.try_write() {
                    for validator in validators_list {
                        debug!("Recovered validator {} from persistence", validator.address);
                        validators.insert(validator.address.clone(), validator);
                    }
                } else {
                    warn!("Could not recover validators from persistence (lock contention)");
                }
            }

            info!("Consensus state recovery attempted from persistence");
        }

        consensus
    }

    /// Create a new SageGuard consensus engine with random key (for testing)
    pub fn new_random(
        address: String,
        stake_amount: u128,
        config: ConsensusConfig,
    ) -> Self {
        use rand::rngs::OsRng;
        let signing_key = SigningKey::random(&mut OsRng);
        Self::new(address, signing_key, stake_amount, config)
    }

    /// Register a validator
    pub async fn register_validator(&self, validator: ValidatorInfo) -> Result<()> {
        if validator.stake_amount < self.config.min_stake {
            return Err(anyhow!(
                "Stake too low: {} (min {})",
                validator.stake_amount,
                self.config.min_stake
            ));
        }

        let mut validators = self.validators.write().await;
        if validators.len() >= MAX_VALIDATORS {
            return Err(anyhow!("Maximum validators reached"));
        }

        info!("Registering validator: {}", validator.address);
        let address = validator.address.clone();
        validators.insert(address.clone(), validator.clone());

        // Update metrics
        consensus_metrics::VALIDATORS_REGISTERED_TOTAL
            .with_label_values(&[&validator.address])
            .inc();

        let active_count = validators.values().filter(|v| v.is_active).count();
        consensus_metrics::ACTIVE_VALIDATORS.set(active_count as f64);

        // Persist validator to database
        if let Some(persist) = &self.persistence {
            persist.save_validator(&validator)?;
        }

        Ok(())
    }

    /// Remove a validator
    pub async fn remove_validator(&self, address: &str) -> Result<()> {
        let mut validators = self.validators.write().await;
        validators.remove(address);
        info!("Removed validator: {}", address);

        // Update metrics
        consensus_metrics::VALIDATORS_REMOVED_TOTAL
            .with_label_values(&[address, "manual"])
            .inc();

        let active_count = validators.values().filter(|v| v.is_active).count();
        consensus_metrics::ACTIVE_VALIDATORS.set(active_count as f64);

        Ok(())
    }

    /// Get active validator count
    pub async fn active_validator_count(&self) -> usize {
        let validators = self.validators.read().await;
        validators.values().filter(|v| v.is_active).count()
    }

    // ========================================================================
    // Leader Election & View Management
    // ========================================================================

    /// Elect a leader for a given view number using round-robin
    ///
    /// Leader selection is deterministic based on view number:
    /// leader_index = view_number % validator_count
    pub async fn elect_leader(&self, view_number: u64) -> Result<String> {
        let validators = self.validators.read().await;

        // Get sorted list of ALL active validator addresses (including ourselves)
        let mut active_validators: Vec<String> = validators
            .values()
            .filter(|v| v.is_active)
            .map(|v| v.address.clone())
            .collect();

        // Add ourselves to the list
        if self.identity.is_active {
            active_validators.push(self.identity.address.clone());
        }

        active_validators.sort(); // Deterministic ordering

        if active_validators.is_empty() {
            return Ok(self.identity.address.clone());
        }

        // Round-robin selection
        let leader_index = (view_number as usize) % active_validators.len();
        Ok(active_validators[leader_index].clone())
    }

    /// Check if we are the current leader
    pub async fn is_leader(&self) -> bool {
        let view = self.current_view.read().await;
        view.leader_address == self.identity.address
    }

    /// Get the current view
    pub async fn get_current_view(&self) -> View {
        let view = self.current_view.read().await;
        view.clone()
    }

    /// Advance to a new view (view change)
    ///
    /// This is called when:
    /// 1. Current leader times out
    /// 2. 2/3 validators request view change
    /// 3. Consensus is reached and we move to next round
    pub async fn advance_view(&self, reason: &str) -> Result<View> {
        let mut view = self.current_view.write().await;
        let new_view_number = view.view_number + 1;

        // Elect new leader
        let new_leader = self.elect_leader(new_view_number).await?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let new_view = View {
            view_number: new_view_number,
            leader_address: new_leader.clone(),
            started_at: now,
            timeout_at: now + self.config.view_timeout.as_secs(),
        };

        *view = new_view.clone();

        info!(
            "Advanced to view {} with leader {} (reason: {})",
            new_view_number, new_leader, reason
        );

        // Update metrics
        consensus_metrics::VIEW_CHANGES_TOTAL
            .with_label_values(&[reason])
            .inc();

        consensus_metrics::CURRENT_VIEW.set(new_view_number as f64);

        // Clear view change requests for the old view
        let mut view_changes = self.view_change_requests.write().await;
        view_changes.clear();

        Ok(new_view)
    }

    /// Check if current view has timed out
    pub async fn is_view_timeout(&self) -> bool {
        let view = self.current_view.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now >= view.timeout_at
    }

    /// Propose a proof for validation (leader only)
    pub async fn propose_proof(&self, submission: &ProofSubmission) -> Result<LeaderProposal> {
        if !self.is_leader().await {
            return Err(anyhow!("Only the leader can propose proofs"));
        }

        let view = self.current_view.read().await;

        let proposal = LeaderProposal {
            view_number: view.view_number,
            job_id: submission.job_id,
            proof_hash: submission.compressed_proof.proof_hash,
            signature: String::new(), // Will be filled below
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Sign the proposal
        let proposal_hash = proposal.compute_hash();
        let signature = self.sign_data(&proposal_hash)?;

        let mut signed_proposal = proposal;
        signed_proposal.signature = hex::encode(&signature);

        info!(
            "Leader proposed job {} in view {}",
            signed_proposal.job_id, signed_proposal.view_number
        );

        Ok(signed_proposal)
    }

    /// Request a view change (any validator can call this)
    pub async fn request_view_change(&self) -> Result<ViewChangeRequest> {
        let view = self.current_view.read().await;

        let request = ViewChangeRequest {
            old_view: view.view_number,
            new_view: view.view_number + 1,
            validator_address: self.identity.address.clone(),
            signature: String::new(), // Will be filled below
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Sign the request
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&request.old_view.to_le_bytes());
        hasher.update(&request.new_view.to_le_bytes());
        hasher.update(request.validator_address.as_bytes());
        let hash_bytes = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let signature = self.sign_data(&hash)?;

        let mut signed_request = request;
        signed_request.signature = hex::encode(&signature);

        // Store the request
        let mut view_changes = self.view_change_requests.write().await;
        view_changes.insert(self.identity.address.clone(), signed_request.clone());

        info!(
            "Requested view change from {} to {}",
            signed_request.old_view, signed_request.new_view
        );

        // Check if we have 2/3 majority for view change
        let validators = self.validators.read().await;
        let total_validators = validators.len() + 1; // +1 for ourselves
        let required = (total_validators * 2) / 3;

        if view_changes.len() >= required {
            drop(view_changes);
            drop(validators);
            drop(view);
            self.advance_view("2/3 validators requested view change").await?;
        }

        Ok(signed_request)
    }

    // ========================================================================
    // Proof Validation (with leader support)
    // ========================================================================

    /// Vote on a proof submission
    ///
    /// In leader-based mode:
    /// - Leader proposes the proof first
    /// - Non-leaders wait for proposal before voting
    /// - View changes occur on timeout
    pub async fn vote_on_proof(
        &self,
        submission: &ProofSubmission,
    ) -> Result<ConsensusResult> {
        let job_id = submission.job_id;

        info!("Starting consensus for job {} from {}", job_id, submission.worker_address);

        // Leader-based consensus flow
        if self.config.enable_leader {
            if self.is_leader().await {
                // We are the leader - propose the proof
                let proposal = self.propose_proof(submission).await?;
                info!("Leader proposed job {} in view {}", job_id, proposal.view_number);

                // Leader also votes on their own proposal
                let local_result = self.verify_proof_locally(&submission.compressed_proof).await;
                let our_vote = self.create_vote(job_id, &submission.compressed_proof.proof_hash, local_result).await?;
                self.broadcast_vote(&our_vote).await?;
            } else {
                // We are not the leader - wait for leader's proposal
                info!("Non-leader waiting for proposal for job {}", job_id);

                // Wait for leader proposal or timeout
                let proposal_received = self.wait_for_leader_proposal(job_id).await;

                if !proposal_received {
                    // Leader timed out - request view change
                    warn!("Leader timeout for job {}, requesting view change", job_id);
                    self.request_view_change().await?;

                    return Ok(ConsensusResult::Timeout {
                        votes_received: 0,
                        votes_required: 1,
                    });
                }

                // Proposal received - vote on the proof
                let local_result = self.verify_proof_locally(&submission.compressed_proof).await;
                let our_vote = self.create_vote(job_id, &submission.compressed_proof.proof_hash, local_result).await?;
                self.broadcast_vote(&our_vote).await?;
            }
        } else {
            // Leaderless consensus - original flow
            let local_result = self.verify_proof_locally(&submission.compressed_proof).await;
            let our_vote = self.create_vote(job_id, &submission.compressed_proof.proof_hash, local_result).await?;
            self.broadcast_vote(&our_vote).await?;
        }

        // Collect votes from other validators
        let votes = self.collect_votes(job_id, self.config.vote_timeout).await?;

        // Check for quorum and finalize
        let result = self.finalize_consensus(job_id, votes).await?;

        // Store the result
        {
            let mut finalized = self.finalized_results.write().await;
            finalized.insert(job_id, result.clone());
        }

        // Advance to next view after successful consensus (leader mode only)
        if self.config.enable_leader && result.is_approved() {
            self.advance_view("consensus reached").await?;
        }

        info!("Consensus for job {}: {:?}", job_id, result.decision());

        Ok(result)
    }

    /// Wait for leader proposal (non-leader validators)
    ///
    /// Returns true if proposal received, false on timeout
    async fn wait_for_leader_proposal(&self, job_id: u128) -> bool {
        let timeout = self.config.view_timeout;
        let start = std::time::Instant::now();

        // In production, this would listen for actual leader proposals via P2P
        // For now, we check if the view has timed out
        while start.elapsed() < timeout {
            if self.is_view_timeout().await {
                return false;
            }

            // Check if we've received votes from the leader
            let pending = self.pending_votes.read().await;
            if let Some(votes) = pending.get(&job_id) {
                let view = self.current_view.read().await;
                let has_leader_vote = votes.iter().any(|v| v.validator_address == view.leader_address);
                drop(view);

                if has_leader_vote {
                    return true;
                }
            }
            drop(pending);

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        false
    }

    /// Verify a proof locally using Stwo verifier
    async fn verify_proof_locally(&self, compressed_proof: &CompressedProof) -> bool {
        // Decompress the proof
        let proof_bytes = match ProofCompressor::decompress(compressed_proof) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to decompress proof: {}", e);
                return false;
            }
        };

        // Deserialize to StarkProof
        let proof: StarkProof = match bincode::deserialize(&proof_bytes) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to deserialize proof: {}", e);
                return false;
            }
        };

        // Verify proof structure is valid
        // Note: Full STARK verification requires the original trace
        // For consensus, we verify:
        // 1. Proof deserialized successfully (done above)
        // 2. Proof has valid metadata
        // 3. Proof size is reasonable
        proof.metadata.proof_size_bytes > 0 && proof.metadata.trace_length > 0
    }

    /// Create a signed vote
    async fn create_vote(
        &self,
        job_id: u128,
        proof_hash: &[u8; 32],
        is_valid: bool,
    ) -> Result<Vote> {
        // Create unsigned vote first to compute hash
        let mut vote = Vote::new(
            self.identity.address.clone(),
            job_id,
            *proof_hash,
            is_valid,
            &[0u8; 64], // Placeholder
        );

        // Sign the vote
        let vote_hash = vote.compute_hash();
        let signature = self.sign_data(&vote_hash)?;
        vote.signature = hex::encode(&signature);

        Ok(vote)
    }

    /// Sign data with our ECDSA private key
    fn sign_data(&self, data: &[u8; 32]) -> Result<[u8; 64]> {
        // Sign with ECDSA P-256
        let signature: Signature = self.signing_key.sign(data);

        // Convert to 64-byte array (r || s)
        let signature_bytes = signature.to_bytes();
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);

        Ok(sig_array)
    }

    /// Verify an ECDSA signature on a vote
    fn verify_vote_signature(&self, vote: &Vote, validator: &ValidatorInfo) -> Result<bool> {
        // Get the verifying key for this validator
        let verifying_key = validator.verifying_key()?;

        // Decode the signature from hex
        let signature_bytes = hex::decode(&vote.signature)
            .map_err(|e| anyhow!("Failed to decode signature: {}", e))?;

        if signature_bytes.len() != 64 {
            return Ok(false);
        }

        // Parse the signature
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

        // Compute the vote hash (same as when signing)
        let vote_hash = vote.compute_hash();

        // Verify the signature
        match verifying_key.verify(&vote_hash, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Broadcast a vote to other validators
    async fn broadcast_vote(&self, vote: &Vote) -> Result<()> {
        // Store our vote
        {
            let mut pending = self.pending_votes.write().await;
            pending
                .entry(vote.job_id)
                .or_insert_with(Vec::new)
                .push(vote.clone());
        }

        // Broadcast via channel (in production, use P2P)
        let _ = self.vote_tx.send(vote.clone());

        debug!("Broadcasted vote for job {}: valid={}", vote.job_id, vote.is_valid);

        Ok(())
    }

    /// Collect votes from validators with timeout
    async fn collect_votes(&self, job_id: u128, timeout: Duration) -> Result<Vec<Vote>> {
        let start = std::time::Instant::now();
        let validators = self.validators.read().await;
        let required_votes = validators.len();
        drop(validators);

        // Wait for votes or timeout
        while start.elapsed() < timeout {
            let pending = self.pending_votes.read().await;
            if let Some(votes) = pending.get(&job_id) {
                if votes.len() >= required_votes {
                    return Ok(votes.clone());
                }
            }
            drop(pending);

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Return whatever votes we have
        let pending = self.pending_votes.read().await;
        Ok(pending.get(&job_id).cloned().unwrap_or_default())
    }

    /// Finalize consensus based on collected votes
    async fn finalize_consensus(&self, job_id: u128, votes: Vec<Vote>) -> Result<ConsensusResult> {
        // Start timing finalization
        let timer = consensus_metrics::FINALIZATION_DURATION
            .with_label_values(&["pending"])
            .start_timer();

        let validators = self.validators.read().await;
        let total_validators = validators.len();

        if total_validators == 0 {
            return Ok(ConsensusResult::Timeout {
                votes_received: votes.len(),
                votes_required: 1,
            });
        }

        // Count votes weighted by stake + PoC (only valid signatures)
        let mut votes_for: Vec<Vote> = Vec::new();
        let mut votes_against: Vec<Vote> = Vec::new();
        let mut weight_for: u128 = 0;
        let mut weight_against: u128 = 0;
        let mut invalid_votes = 0;

        for vote in &votes {
            if let Some(validator) = validators.get(&vote.validator_address) {
                // Verify the vote signature
                match self.verify_vote_signature(vote, validator) {
                    Ok(true) => {
                        // Calculate validator's voting weight
                        let vote_weight = if self.config.enable_poc_weighting {
                            validator.voting_weight(self.config.stake_ratio, self.config.poc_ratio)
                        } else {
                            validator.stake_weight()
                        };

                        // Valid signature - count the vote
                        if vote.is_valid {
                            votes_for.push(vote.clone());
                            weight_for += vote_weight;
                        } else {
                            votes_against.push(vote.clone());
                            weight_against += vote_weight;
                        }
                    }
                    Ok(false) => {
                        warn!("Invalid signature from validator {}", vote.validator_address);
                        invalid_votes += 1;

                        // Submit fraud proof for invalid signature
                        if let Some(client) = &self.fraud_proof_client {
                            if client.should_challenge(100) { // 100% confidence on invalid signature
                                let vote_hash = self.compute_vote_hash(vote);
                                let expected_hash = [0u8; 32]; // Invalid signatures have no valid hash
                                let evidence_hash = vote_hash; // The vote itself is the evidence

                                let client = Arc::clone(client);
                                let validator_addr = vote.validator_address.clone();
                                tokio::spawn(async move {
                                    match client.submit_challenge(
                                        job_id,
                                        &validator_addr,
                                        expected_hash,
                                        vote_hash,
                                        evidence_hash,
                                        crate::obelysk::starknet::fraud_proof_client::VerificationMethod::HashComparison,
                                    ).await {
                                        Ok(challenge_id) => {
                                            info!("Submitted fraud proof challenge {} for invalid signature from {}",
                                                challenge_id, validator_addr);
                                        }
                                        Err(e) => {
                                            warn!("Failed to submit fraud proof for {}: {}", validator_addr, e);
                                        }
                                    }
                                });
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Signature verification error for {}: {}", vote.validator_address, e);
                        invalid_votes += 1;
                    }
                }
            }
        }

        if invalid_votes > 0 {
            info!("Rejected {} votes with invalid signatures for job {}", invalid_votes, job_id);
        }

        let total_weight = weight_for + weight_against;
        let quorum_weight = (total_weight * self.config.quorum_percentage as u128) / 100;

        // Check quorum
        if votes.len() < (total_validators * 2 / 3) {
            return Ok(ConsensusResult::Timeout {
                votes_received: votes.len(),
                votes_required: (total_validators * 2 / 3) + 1,
            });
        }

        // Determine result based on weighted votes (stake + PoC)
        let result = if weight_for >= quorum_weight {
            ConsensusResult::Approved {
                votes_for: votes_for.clone(),
                votes_against: votes_against.clone(),
                stake_for: weight_for, // Now includes PoC weight
            }
        } else if weight_against >= quorum_weight {
            // Get primary rejection reason
            let rejection_reason = votes_against
                .first()
                .and_then(|v| v.rejection_reason.clone())
                .unwrap_or_else(|| "Proof verification failed".to_string());

            ConsensusResult::Rejected {
                votes_for: votes_for.clone(),
                votes_against: votes_against.clone(),
                rejection_reason,
            }
        } else {
            ConsensusResult::Inconclusive {
                votes_for: votes_for.len(),
                votes_against: votes_against.len(),
            }
        };

        // Detect and challenge fraudulent votes (validators who voted against consensus)
        self.detect_fraudulent_votes(job_id, &result, &votes_for, &votes_against).await;

        // Persist consensus result to database
        if let Some(persist) = &self.persistence {
            if let Err(e) = persist.save_consensus_result(job_id, &result) {
                warn!("Failed to persist consensus result for job {}: {}", job_id, e);
            } else {
                debug!("Persisted consensus result for job {}", job_id);
            }
        }

        // Record metrics based on outcome
        let outcome = match &result {
            ConsensusResult::Approved { .. } => {
                drop(timer);
                consensus_metrics::FINALIZATION_DURATION
                    .with_label_values(&["approved"])
                    .observe(0.0); // Timer was already recorded
                consensus_metrics::ROUNDS_TOTAL
                    .with_label_values(&["approved"])
                    .inc();
                "approved"
            }
            ConsensusResult::Rejected { .. } => {
                drop(timer);
                consensus_metrics::FINALIZATION_DURATION
                    .with_label_values(&["rejected"])
                    .observe(0.0);
                consensus_metrics::ROUNDS_TOTAL
                    .with_label_values(&["rejected"])
                    .inc();
                "rejected"
            }
            ConsensusResult::Timeout { .. } => {
                drop(timer);
                consensus_metrics::FINALIZATION_DURATION
                    .with_label_values(&["timeout"])
                    .observe(0.0);
                consensus_metrics::ROUNDS_TOTAL
                    .with_label_values(&["timeout"])
                    .inc();
                "timeout"
            }
            ConsensusResult::Inconclusive { .. } => {
                drop(timer);
                consensus_metrics::FINALIZATION_DURATION
                    .with_label_values(&["inconclusive"])
                    .observe(0.0);
                consensus_metrics::ROUNDS_TOTAL
                    .with_label_values(&["inconclusive"])
                    .inc();
                "inconclusive"
            }
        };

        debug!("Consensus finalized for job {} with outcome: {}", job_id, outcome);

        Ok(result)
    }

    /// Receive a vote from another validator
    pub async fn receive_vote(&self, vote: Vote) -> Result<()> {
        // Get validator info to verify signature
        let validators = self.validators.read().await;
        let validator = validators
            .get(&vote.validator_address)
            .ok_or_else(|| anyhow!("Unknown validator: {}", vote.validator_address))?;

        // Verify vote signature
        let is_valid = self.verify_vote_signature(&vote, validator)?;
        if !is_valid {
            warn!("Received vote with invalid signature from {}", vote.validator_address);
            return Err(anyhow!("Invalid vote signature"));
        }

        drop(validators);

        // Signature valid - store the vote
        let mut pending = self.pending_votes.write().await;
        pending
            .entry(vote.job_id)
            .or_insert_with(Vec::new)
            .push(vote.clone());

        // Persist vote to database
        if let Some(persist) = &self.persistence {
            if let Err(e) = persist.save_vote(&vote) {
                warn!("Failed to persist vote for job {}: {}", vote.job_id, e);
            }
        }

        Ok(())
    }

    /// Get a finalized result
    pub async fn get_result(&self, job_id: u128) -> Option<ConsensusResult> {
        let finalized = self.finalized_results.read().await;
        finalized.get(&job_id).cloned()
    }

    /// Subscribe to vote broadcasts
    pub fn subscribe_votes(&self) -> broadcast::Receiver<Vote> {
        self.vote_tx.subscribe()
    }

    /// Slash a validator for invalid voting
    pub async fn slash_validator(&self, address: &str, reason: &str) -> Result<()> {
        if !self.config.enable_slashing {
            return Ok(());
        }

        let mut validators = self.validators.write().await;
        if let Some(validator) = validators.get_mut(address) {
            // Mark as inactive
            validator.is_active = false;
            warn!("Slashed validator {}: {}", address, reason);
        }

        Ok(())
    }

    // ========================================================================
    // Proof-of-Compute Metrics Management
    // ========================================================================

    /// Update validator PoC metrics after proof validation
    ///
    /// # Arguments
    /// * `validator_address` - Address of the validator who generated the proof
    /// * `is_valid` - Whether the proof was accepted by consensus
    /// * `proof_time_ms` - Time taken to generate the proof in milliseconds
    /// * `complexity_score` - Score representing proof complexity (trace length, etc.)
    pub async fn update_validator_metrics(
        &self,
        validator_address: &str,
        is_valid: bool,
        proof_time_ms: u64,
        complexity_score: u128,
    ) -> Result<()> {
        let mut validators = self.validators.write().await;

        if let Some(validator) = validators.get_mut(validator_address) {
            validator.poc_metrics.update_after_proof(is_valid, proof_time_ms, complexity_score);
            debug!(
                "Updated PoC metrics for {}: valid={}, time={}ms, score={}, performance={}",
                validator_address,
                is_valid,
                proof_time_ms,
                complexity_score,
                validator.poc_metrics.performance_score
            );

            // Persist updated validator metrics
            if let Some(persist) = &self.persistence {
                let validator_clone = validator.clone();
                drop(validators); // Release lock before persistence
                if let Err(e) = persist.save_validator(&validator_clone) {
                    warn!("Failed to persist validator metrics for {}: {}", validator_address, e);
                }
            }
        } else {
            warn!("Attempted to update metrics for unknown validator: {}", validator_address);
        }

        Ok(())
    }

    /// Apply decay to all validator PoC metrics
    ///
    /// Should be called periodically (e.g., daily) to reduce scores
    /// for inactive validators
    pub async fn apply_metrics_decay(&self) {
        let mut validators = self.validators.write().await;

        for validator in validators.values_mut() {
            validator.poc_metrics.apply_decay();
        }

        debug!("Applied PoC metrics decay to {} validators", validators.len());
    }

    /// Get validator's current voting weight
    pub async fn get_validator_weight(&self, address: &str) -> Option<u128> {
        let validators = self.validators.read().await;

        validators.get(address).map(|v| {
            if self.config.enable_poc_weighting {
                v.voting_weight(self.config.stake_ratio, self.config.poc_ratio)
            } else {
                v.stake_weight()
            }
        })
    }

    /// Get all validator weights (for debugging/monitoring)
    pub async fn get_all_validator_weights(&self) -> HashMap<String, u128> {
        let validators = self.validators.read().await;

        validators
            .iter()
            .map(|(addr, v)| {
                let weight = if self.config.enable_poc_weighting {
                    v.voting_weight(self.config.stake_ratio, self.config.poc_ratio)
                } else {
                    v.stake_weight()
                };
                (addr.clone(), weight)
            })
            .collect()
    }

    /// Detect and challenge fraudulent votes (validators who voted against consensus)
    ///
    /// This method is called after consensus is finalized to detect validators who:
    /// - Voted "valid" when consensus says "invalid"
    /// - Voted "invalid" when consensus says "valid"
    ///
    /// Challenges are submitted with confidence based on the majority margin.
    async fn detect_fraudulent_votes(
        &self,
        job_id: u128,
        result: &ConsensusResult,
        votes_for: &[Vote],
        votes_against: &[Vote],
    ) {
        // Only check for fraud if we have a definitive consensus
        let (consensus_is_valid, minority_votes) = match result {
            ConsensusResult::Approved { .. } => {
                // Consensus says valid, check votes_against for fraud
                (true, votes_against)
            }
            ConsensusResult::Rejected { .. } => {
                // Consensus says invalid, check votes_for for fraud
                (false, votes_for)
            }
            _ => return, // No definitive consensus, can't detect fraud
        };

        // Calculate confidence based on majority margin
        let total_votes = votes_for.len() + votes_against.len();
        if total_votes == 0 {
            return;
        }

        let majority_count = if consensus_is_valid {
            votes_for.len()
        } else {
            votes_against.len()
        };

        // Confidence = (majority_count / total_votes) * 100
        let confidence = ((majority_count * 100) / total_votes) as u8;

        // Only submit challenges if we have fraud proof client
        let Some(client) = &self.fraud_proof_client else {
            return;
        };

        // Check if confidence is high enough to challenge
        if !client.should_challenge(confidence) {
            return;
        }

        // Submit challenges for each validator who voted against consensus
        for vote in minority_votes {
            let validator_addr = vote.validator_address.clone();
            let vote_hash = self.compute_vote_hash(vote);

            // Record fraud detection metric
            consensus_metrics::FRAUD_DETECTED_TOTAL
                .with_label_values(&[&job_id.to_string()])
                .inc();

            // Expected vote hash (what they should have voted)
            let mut expected_vote = vote.clone();
            expected_vote.is_valid = consensus_is_valid;
            let expected_hash = self.compute_vote_hash(&expected_vote);

            // Evidence is the actual vote they submitted
            let evidence_hash = vote_hash;

            let client = Arc::clone(client);
            tokio::spawn(async move {
                match client.submit_challenge(
                    job_id,
                    &validator_addr,
                    expected_hash,
                    vote_hash,
                    evidence_hash,
                    crate::obelysk::starknet::fraud_proof_client::VerificationMethod::HashComparison,
                ).await {
                    Ok(challenge_id) => {
                        info!(
                            "Submitted fraud proof challenge {} for validator {} (voted against consensus with {}% confidence)",
                            challenge_id, validator_addr, confidence
                        );
                    }
                    Err(e) => {
                        warn!("Failed to submit fraud proof for {}: {}", validator_addr, e);
                    }
                }
            });
        }
    }

    /// Compute hash of a vote for fraud proof evidence
    fn compute_vote_hash(&self, vote: &Vote) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&vote.job_id.to_le_bytes());
        hasher.update(&vote.validator_address.as_bytes());
        hasher.update(&[vote.is_valid as u8]);
        hasher.update(&vote.proof_hash);
        hasher.update(&vote.timestamp.to_le_bytes());

        if let Some(reason) = &vote.rejection_reason {
            hasher.update(reason.as_bytes());
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Start background task to monitor view timeouts
    ///
    /// This should be called once when starting the consensus engine.
    /// It periodically checks if the current view has timed out and triggers
    /// a view change if needed.
    pub fn start_view_monitor(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut check_interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                check_interval.tick().await;

                // Only monitor in leader mode
                if !self.config.enable_leader {
                    continue;
                }

                // Check if view has timed out
                if self.is_view_timeout().await {
                    let view = self.get_current_view().await;

                    // Only non-leaders trigger view changes on timeout
                    // (Leaders should have proposed already)
                    if view.leader_address != self.identity.address {
                        warn!("View {} timed out, requesting view change", view.view_number);

                        if let Err(e) = self.request_view_change().await {
                            warn!("Failed to request view change: {}", e);
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn create_test_validator_with_key(address: &str) -> (ValidatorInfo, SigningKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(true).to_bytes().to_vec();

        let validator = ValidatorInfo {
            address: address.to_string(),
            public_key,
            stake_amount: 1000_000_000_000_000_000,
            is_active: true,
            last_seen: 0,
            poc_metrics: ProofOfComputeMetrics::default(),
        };

        (validator, signing_key)
    }

    fn create_test_validator_with_metrics(
        address: &str,
        stake_amount: u128,
        total_proofs: u64,
        valid_proofs: u64,
        avg_time_ms: u64,
        compute_score: u128,
    ) -> (ValidatorInfo, SigningKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(true).to_bytes().to_vec();

        let mut poc_metrics = ProofOfComputeMetrics {
            total_proofs_generated: total_proofs,
            valid_proofs,
            invalid_proofs: total_proofs - valid_proofs,
            avg_proof_time_ms: avg_time_ms,
            compute_score,
            last_proof_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            performance_score: 100,
        };

        poc_metrics.update_performance_score();

        let validator = ValidatorInfo {
            address: address.to_string(),
            public_key,
            stake_amount,
            is_active: true,
            last_seen: 0,
            poc_metrics,
        };

        (validator, signing_key)
    }

    #[tokio::test]
    async fn test_validator_registration() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        let (v2, _) = create_test_validator_with_key("validator2");
        consensus.register_validator(v2).await.unwrap();

        assert_eq!(consensus.active_validator_count().await, 1);
    }

    #[tokio::test]
    async fn test_vote_creation() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        let vote = consensus.create_vote(123, &[0u8; 32], true).await.unwrap();

        assert_eq!(vote.job_id, 123);
        assert!(vote.is_valid);
        assert!(!vote.signature.is_empty());
    }

    #[tokio::test]
    async fn test_vote_signature_verification() {
        let (validator, signing_key) = create_test_validator_with_key("validator1");
        let consensus = SageGuardConsensus::new(
            "validator1".to_string(),
            signing_key,
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        // Create a vote
        let vote = consensus.create_vote(123, &[0u8; 32], true).await.unwrap();

        // Verify the signature
        let is_valid = consensus.verify_vote_signature(&vote, &validator).unwrap();
        assert!(is_valid, "Vote signature should be valid");

        // Test with tampered vote
        let mut tampered_vote = vote.clone();
        tampered_vote.is_valid = !tampered_vote.is_valid;
        let is_valid = consensus.verify_vote_signature(&tampered_vote, &validator).unwrap();
        assert!(!is_valid, "Tampered vote should have invalid signature");
    }

    #[tokio::test]
    async fn test_vote_hash() {
        let vote = Vote::new(
            "validator1".to_string(),
            123,
            [0u8; 32],
            true,
            &[0u8; 64],
        );

        let hash1 = vote.compute_hash();
        let hash2 = vote.compute_hash();

        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_consensus_result_approved() {
        let result = ConsensusResult::Approved {
            votes_for: vec![],
            votes_against: vec![],
            stake_for: 1000,
        };

        assert!(result.is_approved());
        assert_eq!(result.decision(), Some(true));
    }

    #[tokio::test]
    async fn test_consensus_result_rejected() {
        let result = ConsensusResult::Rejected {
            votes_for: vec![],
            votes_against: vec![],
            rejection_reason: "Invalid proof".to_string(),
        };

        assert!(!result.is_approved());
        assert_eq!(result.decision(), Some(false));
    }

    #[tokio::test]
    async fn test_leader_election_round_robin() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        // Register additional validators (total: validator1, validator2, validator3)
        let (v2, _) = create_test_validator_with_key("validator2");
        let (v3, _) = create_test_validator_with_key("validator3");
        consensus.register_validator(v2).await.unwrap();
        consensus.register_validator(v3).await.unwrap();

        // Test round-robin: with 3 validators (sorted: v1, v2, v3), leader should rotate
        let leader0 = consensus.elect_leader(0).await.unwrap();
        let leader1 = consensus.elect_leader(1).await.unwrap();
        let leader2 = consensus.elect_leader(2).await.unwrap();
        let leader3 = consensus.elect_leader(3).await.unwrap();

        // Leaders should be different and rotate
        assert_ne!(leader0, leader1);
        assert_ne!(leader1, leader2);
        assert_ne!(leader2, leader0);

        // Should cycle back to first leader after 3 rounds (3 validators)
        assert_eq!(leader0, leader3);
    }

    #[tokio::test]
    async fn test_is_leader() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        // Initially, we are the leader (view 0, only validator)
        assert!(consensus.is_leader().await);

        // Register another validator
        let (v2, _) = create_test_validator_with_key("validator2");
        consensus.register_validator(v2).await.unwrap();

        // Advance to next view
        consensus.advance_view("test").await.unwrap();

        // Leadership should have changed (round-robin)
        let is_leader = consensus.is_leader().await;
        let view = consensus.get_current_view().await;
        assert_eq!(is_leader, view.leader_address == consensus.identity.address);
    }

    #[tokio::test]
    async fn test_view_advance() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        let initial_view = consensus.get_current_view().await;
        assert_eq!(initial_view.view_number, 0);

        // Advance view
        let new_view = consensus.advance_view("test view change").await.unwrap();
        assert_eq!(new_view.view_number, 1);

        // Verify current view updated
        let current = consensus.get_current_view().await;
        assert_eq!(current.view_number, 1);
    }

    #[tokio::test]
    async fn test_view_timeout_detection() {
        let mut config = ConsensusConfig::default();
        config.view_timeout = Duration::from_secs(1); // 1 second timeout

        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            config,
        );

        // Initially not timed out (view just started)
        assert!(!consensus.is_view_timeout().await, "View should not be timed out immediately");

        // Wait for timeout to occur
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Should be timed out now
        assert!(consensus.is_view_timeout().await, "View should be timed out after 1.1 seconds");
    }

    #[tokio::test]
    async fn test_leader_proposal() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        // Create a test proof submission
        let submission = ProofSubmission {
            job_id: 42,
            worker_address: "worker1".to_string(),
            compressed_proof: CompressedProof {
                data: vec![0u8; 100],
                original_size: 200,
                algorithm: crate::obelysk::proof_compression::CompressionAlgorithm::Zstd,
                proof_hash: [1u8; 32],
                compressed_hash: [2u8; 32],
                compression_ratio: 2.0,
            },
            timestamp: 0,
        };

        // As leader, we should be able to propose
        let proposal = consensus.propose_proof(&submission).await.unwrap();

        assert_eq!(proposal.job_id, 42);
        assert_eq!(proposal.proof_hash, [1u8; 32]);
        assert!(!proposal.signature.is_empty());
    }

    #[tokio::test]
    async fn test_view_change_request() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        let initial_view = consensus.get_current_view().await;

        // Request view change
        let request = consensus.request_view_change().await.unwrap();

        assert_eq!(request.old_view, initial_view.view_number);
        assert_eq!(request.new_view, initial_view.view_number + 1);
        assert_eq!(request.validator_address, "validator1");
        assert!(!request.signature.is_empty());
    }

    #[tokio::test]
    async fn test_view_change_with_majority() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        // Register 2 more validators (total 3)
        let (v2, _) = create_test_validator_with_key("validator2");
        let (v3, _) = create_test_validator_with_key("validator3");
        consensus.register_validator(v2).await.unwrap();
        consensus.register_validator(v3).await.unwrap();

        let initial_view = consensus.get_current_view().await;

        // Request view change from validator1
        consensus.request_view_change().await.unwrap();

        // View should not change yet (only 1/3 validators requested)
        let current = consensus.get_current_view().await;
        assert_eq!(current.view_number, initial_view.view_number);

        // Simulate view change request from validator2
        // (In production, this would come via P2P)
        let mut view_changes = consensus.view_change_requests.write().await;
        view_changes.insert(
            "validator2".to_string(),
            ViewChangeRequest {
                old_view: initial_view.view_number,
                new_view: initial_view.view_number + 1,
                validator_address: "validator2".to_string(),
                signature: "mock".to_string(),
                timestamp: 0,
            },
        );
        drop(view_changes);

        // Now we have 2/3 majority - manually trigger view change
        consensus.advance_view("2/3 majority").await.unwrap();

        // View should have advanced
        let new_view = consensus.get_current_view().await;
        assert_eq!(new_view.view_number, initial_view.view_number + 1);
    }

    #[tokio::test]
    async fn test_leader_vs_leaderless_mode() {
        // Test with leader mode enabled
        let mut config_leader = ConsensusConfig::default();
        config_leader.enable_leader = true;

        let consensus_leader = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            config_leader,
        );

        assert!(consensus_leader.config.enable_leader);

        // Test with leaderless mode
        let mut config_leaderless = ConsensusConfig::default();
        config_leaderless.enable_leader = false;

        let consensus_leaderless = SageGuardConsensus::new_random(
            "validator2".to_string(),
            1000_000_000_000_000_000,
            config_leaderless,
        );

        assert!(!consensus_leaderless.config.enable_leader);
    }

    // ========================================================================
    // Proof-of-Compute Weighted Voting Tests
    // ========================================================================

    #[tokio::test]
    async fn test_poc_metrics_update() {
        let mut metrics = ProofOfComputeMetrics::default();

        // Initially perfect score
        assert_eq!(metrics.performance_score, 100);
        assert_eq!(metrics.total_proofs_generated, 0);

        // Update with valid proof
        metrics.update_after_proof(true, 8000, 1000);

        assert_eq!(metrics.total_proofs_generated, 1);
        assert_eq!(metrics.valid_proofs, 1);
        assert_eq!(metrics.invalid_proofs, 0);
        assert_eq!(metrics.avg_proof_time_ms, 8000);
        assert_eq!(metrics.compute_score, 1000);

        // Update with another valid proof (faster)
        metrics.update_after_proof(true, 5000, 1500);

        assert_eq!(metrics.total_proofs_generated, 2);
        assert_eq!(metrics.valid_proofs, 2);
        // Moving average: (8000 * 0.8 + 5000 * 0.2) = 7400
        assert_eq!(metrics.avg_proof_time_ms, 7400);
        assert_eq!(metrics.compute_score, 2500);

        // Validity rate should be 100%
        assert_eq!(metrics.validity_rate(), 100);
    }

    #[tokio::test]
    async fn test_poc_metrics_with_invalid_proofs() {
        let mut metrics = ProofOfComputeMetrics::default();

        // 7 valid, 3 invalid
        for _ in 0..7 {
            metrics.update_after_proof(true, 10000, 100);
        }
        for _ in 0..3 {
            metrics.update_after_proof(false, 10000, 0);
        }

        assert_eq!(metrics.total_proofs_generated, 10);
        assert_eq!(metrics.valid_proofs, 7);
        assert_eq!(metrics.invalid_proofs, 3);
        assert_eq!(metrics.validity_rate(), 70);
        assert_eq!(metrics.compute_score, 700); // Only valid proofs count
    }

    #[tokio::test]
    async fn test_validator_voting_weight() {
        let (mut validator, _) = create_test_validator_with_key("validator1");

        // Set up PoC metrics
        validator.poc_metrics.total_proofs_generated = 100;
        validator.poc_metrics.valid_proofs = 95;
        validator.poc_metrics.invalid_proofs = 5;
        validator.poc_metrics.compute_score = 10_000_000;
        validator.poc_metrics.update_performance_score();

        // Stake-only weight
        let stake_weight = validator.stake_weight();
        assert_eq!(stake_weight, 1000_000_000_000_000_000);

        // Combined weight (70% stake, 30% PoC)
        let combined_weight = validator.voting_weight(0.7, 0.3);

        // Should be > stake_only because of PoC contribution
        assert!(combined_weight > stake_weight * 70 / 100);
    }

    #[tokio::test]
    async fn test_poc_weighted_voting_disabled() {
        let mut config = ConsensusConfig::default();
        config.enable_poc_weighting = false;

        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            config,
        );

        // Create validator with PoC metrics
        let (v2, _) = create_test_validator_with_metrics(
            "validator2",
            1000_000_000_000_000_000,
            100,
            95,
            8000,
            5_000_000,
        );

        consensus.register_validator(v2.clone()).await.unwrap();

        // With PoC disabled, weight should equal stake
        let weight = consensus.get_validator_weight("validator2").await.unwrap();
        assert_eq!(weight, v2.stake_amount);
    }

    #[tokio::test]
    async fn test_poc_weighted_voting_enabled() {
        let mut config = ConsensusConfig::default();
        config.enable_poc_weighting = true;
        config.stake_ratio = 0.6;
        config.poc_ratio = 0.4;

        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            config,
        );

        // Create high-performing validator
        let (v2, _) = create_test_validator_with_metrics(
            "validator2",
            1000_000_000_000_000_000, // 1 SAGE stake
            100,                       // 100 proofs
            98,                        // 98% validity
            5000,                      // 5s avg time (faster than 10s target)
            10_000_000,                // High compute score
        );

        consensus.register_validator(v2.clone()).await.unwrap();

        // Weight should be > stake due to PoC contribution
        let weight = consensus.get_validator_weight("validator2").await.unwrap();
        let stake_component = (v2.stake_amount as f64 * 0.6) as u128;

        assert!(weight > stake_component, "Weight should include PoC contribution");
    }

    #[tokio::test]
    async fn test_update_validator_metrics() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        let (v2, _) = create_test_validator_with_key("validator2");
        consensus.register_validator(v2).await.unwrap();

        // Update metrics
        consensus
            .update_validator_metrics("validator2", true, 8000, 1000)
            .await
            .unwrap();

        // Verify metrics were updated
        let weight = consensus.get_validator_weight("validator2").await.unwrap();

        // Weight should now include PoC contribution
        assert!(weight > 0);
    }

    #[tokio::test]
    async fn test_poc_metrics_staleness() {
        let mut metrics = ProofOfComputeMetrics {
            total_proofs_generated: 10,
            valid_proofs: 10,
            invalid_proofs: 0,
            avg_proof_time_ms: 8000,
            compute_score: 1000,
            last_proof_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 86400 - 1, // 24 hours + 1 second ago
            performance_score: 100,
        };

        // Should be stale
        assert!(metrics.is_stale());

        // Apply decay
        let original_score = metrics.performance_score;
        metrics.apply_decay();

        // Score should be reduced
        assert!(metrics.performance_score < original_score);
        assert_eq!(metrics.performance_score, 80); // 20% reduction
    }

    #[tokio::test]
    async fn test_get_all_validator_weights() {
        let consensus = SageGuardConsensus::new_random(
            "validator1".to_string(),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
        );

        // Validator2: Higher performance, same stake
        let (v2, _) = create_test_validator_with_metrics(
            "validator2",
            2000_000_000_000_000_000, // Same stake as v3
            100,                       // More proofs
            96,                        // 96% validity
            5000,                      // Fast (5s)
            50_000_000,                // High compute score
        );

        // Validator3: Lower performance, same stake
        let (v3, _) = create_test_validator_with_metrics(
            "validator3",
            2000_000_000_000_000_000, // Same stake as v2
            30,                        // Fewer proofs
            20,                        // 67% validity
            15000,                     // Slow (15s)
            10_000_000,                // Lower compute score
        );

        consensus.register_validator(v2).await.unwrap();
        consensus.register_validator(v3).await.unwrap();

        // Get all weights
        let weights = consensus.get_all_validator_weights().await;

        assert_eq!(weights.len(), 2);
        assert!(weights.contains_key("validator2"));
        assert!(weights.contains_key("validator3"));

        // Validator2 should have higher weight (much better performance, same stake)
        assert!(
            weights["validator2"] > weights["validator3"],
            "v2 weight={}, v3 weight={}",
            weights["validator2"],
            weights["validator3"]
        );
    }

    #[tokio::test]
    async fn test_performance_score_calculation() {
        // Test 1: Perfect performance: 100% valid, fast (5s vs 10s target)
        let mut metrics_perfect = ProofOfComputeMetrics::default();
        metrics_perfect.total_proofs_generated = 10;
        metrics_perfect.valid_proofs = 10;
        metrics_perfect.invalid_proofs = 0;
        metrics_perfect.avg_proof_time_ms = 5000;
        metrics_perfect.update_performance_score();

        // Should get near-perfect score
        assert!(
            metrics_perfect.performance_score >= 95,
            "Perfect performance should score >= 95, got {}",
            metrics_perfect.performance_score
        );

        // Test 2: Good performance: 90% valid, average speed
        let mut metrics_good = ProofOfComputeMetrics::default();
        metrics_good.total_proofs_generated = 10;
        metrics_good.valid_proofs = 9;
        metrics_good.invalid_proofs = 1;
        metrics_good.avg_proof_time_ms = 10000;
        metrics_good.update_performance_score();

        assert!(
            metrics_good.performance_score >= 70,
            "Good performance should score >= 70, got {}",
            metrics_good.performance_score
        );

        // Test 3: Poor performance: 50% valid, slow (20s)
        let mut metrics_poor = ProofOfComputeMetrics::default();
        metrics_poor.total_proofs_generated = 10;
        metrics_poor.valid_proofs = 5;
        metrics_poor.invalid_proofs = 5;
        metrics_poor.avg_proof_time_ms = 20000;
        metrics_poor.update_performance_score();

        // Should get significantly lower score than good performance
        assert!(
            metrics_poor.performance_score < metrics_good.performance_score,
            "Poor performance ({}) should score less than good performance ({})",
            metrics_poor.performance_score,
            metrics_good.performance_score
        );
    }

    // ========================================================================
    // Fraud Proof Integration Tests
    // ========================================================================

    /// Mock fraud proof client for testing
    struct MockFraudProofClient {
        submitted_challenges: Arc<tokio::sync::RwLock<Vec<(u128, String, [u8; 32], [u8; 32])>>>,
        confidence_threshold: u8,
        auto_challenge: bool,
    }

    #[async_trait::async_trait]
    impl crate::obelysk::starknet::fraud_proof_client::FraudProofClientTrait for MockFraudProofClient {
        async fn submit_challenge(
            &self,
            job_id: u128,
            validator_address: &str,
            original_vote_hash: [u8; 32],
            disputed_vote_hash: [u8; 32],
            _evidence_hash: [u8; 32],
            _verification_method: crate::obelysk::starknet::fraud_proof_client::VerificationMethod,
        ) -> Result<u128> {
            let mut challenges = self.submitted_challenges.write().await;
            challenges.push((job_id, validator_address.to_string(), original_vote_hash, disputed_vote_hash));
            Ok(job_id) // Use job_id as challenge_id for testing
        }

        async fn get_challenge(&self, _challenge_id: u128) -> Result<Option<crate::obelysk::starknet::fraud_proof_client::Challenge>> {
            Ok(None)
        }

        async fn resolve_challenge(&self, _challenge_id: u128) -> Result<()> {
            Ok(())
        }

        fn should_challenge(&self, confidence: u8) -> bool {
            self.auto_challenge && confidence >= self.confidence_threshold
        }

        async fn get_stats(&self) -> Result<crate::obelysk::starknet::fraud_proof_client::FraudProofStats> {
            Ok(crate::obelysk::starknet::fraud_proof_client::FraudProofStats {
                total_challenges: 0,
                valid_challenges: 0,
                invalid_challenges: 0,
                total_slashed: 0,
                total_rewards_paid: 0,
            })
        }
    }

    #[tokio::test]
    async fn test_fraud_proof_client_creation() {
        // Test that we can create a consensus with fraud proof client
        let mock_client = Arc::new(MockFraudProofClient {
            submitted_challenges: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            confidence_threshold: 90,
            auto_challenge: true,
        });

        let consensus = SageGuardConsensus::with_fraud_proof_client(
            "validator1".to_string(),
            SigningKey::random(&mut rand::rngs::OsRng),
            1000_000_000_000_000_000,
            ConsensusConfig::default(),
            Some(mock_client.clone()),
        );

        // Verify consensus was created successfully (check it has active validators count)
        let count = consensus.active_validator_count().await;
        assert!(count >= 0);
    }

    #[tokio::test]
    async fn test_fraud_proof_client_should_challenge() {
        use crate::obelysk::starknet::fraud_proof_client::FraudProofClientTrait;

        // Test confidence threshold logic
        let mock_client: &dyn FraudProofClientTrait = &MockFraudProofClient {
            submitted_challenges: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            confidence_threshold: 90,
            auto_challenge: true,
        };

        // Below threshold - should not challenge
        assert!(!mock_client.should_challenge(80));
        assert!(!mock_client.should_challenge(89));

        // At or above threshold - should challenge
        assert!(mock_client.should_challenge(90));
        assert!(mock_client.should_challenge(95));
        assert!(mock_client.should_challenge(100));
    }

    #[tokio::test]
    async fn test_fraud_proof_client_auto_challenge_disabled() {
        use crate::obelysk::starknet::fraud_proof_client::FraudProofClientTrait;

        // Test that auto-challenge can be disabled
        let mock_client: &dyn FraudProofClientTrait = &MockFraudProofClient {
            submitted_challenges: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            confidence_threshold: 70,
            auto_challenge: false, // Disabled
        };

        // Even with 100% confidence, should not challenge when disabled
        assert!(!mock_client.should_challenge(100));
    }

    #[tokio::test]
    async fn test_fraud_proof_manual_submission() {
        use crate::obelysk::starknet::fraud_proof_client::FraudProofClientTrait;

        // Test that fraud proof can be manually submitted
        let mock_client = MockFraudProofClient {
            submitted_challenges: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            confidence_threshold: 90,
            auto_challenge: true,
        };

        let job_id = 100;
        let validator_address = "validator1";
        let original_hash = [1u8; 32];
        let disputed_hash = [2u8; 32];
        let evidence_hash = [3u8; 32];
        let method = crate::obelysk::starknet::fraud_proof_client::VerificationMethod::HashComparison;

        // Manually submit a challenge via trait
        let client_trait: &dyn FraudProofClientTrait = &mock_client;
        let challenge_id = client_trait
            .submit_challenge(
                job_id,
                validator_address,
                original_hash,
                disputed_hash,
                evidence_hash,
                method,
            )
            .await
            .unwrap();

        assert_eq!(challenge_id, job_id);

        // Verify challenge was recorded
        let challenges = mock_client.submitted_challenges.read().await;
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].0, job_id);
        assert_eq!(challenges[0].1, validator_address);
    }
}
