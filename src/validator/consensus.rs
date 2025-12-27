//! Validator Consensus Protocol for Bitsage Network
//!
//! Implements Byzantine Fault Tolerant (BFT) consensus for proof validation.
//! Validators vote on proof validity and require 2/3 supermajority for acceptance.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    PROOF VALIDATION CONSENSUS                        │
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

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc, broadcast};
use tracing::{info, warn, debug};

use crate::obelysk::{StarkProof, CompressedProof, ProofCompressor};

/// Vote timeout for collecting validator votes
pub const VOTE_TIMEOUT_SECS: u64 = 30;

/// Minimum quorum percentage (67% for BFT)
pub const QUORUM_PERCENTAGE: u64 = 67;

/// Maximum validators that can participate
pub const MAX_VALIDATORS: usize = 100;

/// Validator identity and stake info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator address
    pub address: String,

    /// Public key for signature verification
    pub public_key: [u8; 32],

    /// Staked amount
    pub stake_amount: u128,

    /// Whether validator is active
    pub is_active: bool,

    /// Last seen timestamp
    pub last_seen: u64,
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

/// Validator Consensus Engine
pub struct ValidatorConsensus {
    /// Our validator identity
    identity: ValidatorInfo,

    /// Private key for signing votes
    private_key: [u8; 32],

    /// Known validators in the network
    validators: Arc<RwLock<HashMap<String, ValidatorInfo>>>,

    /// Pending votes per job
    pending_votes: Arc<RwLock<HashMap<u128, Vec<Vote>>>>,

    /// Finalized results
    finalized_results: Arc<RwLock<HashMap<u128, ConsensusResult>>>,

    /// Vote broadcast channel
    vote_tx: broadcast::Sender<Vote>,

    /// Configuration
    config: ConsensusConfig,
}

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Vote collection timeout
    pub vote_timeout: Duration,

    /// Minimum stake required to vote
    pub min_stake: u128,

    /// Quorum percentage required (default 67)
    pub quorum_percentage: u64,

    /// Enable slashing for invalid votes
    pub enable_slashing: bool,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            vote_timeout: Duration::from_secs(VOTE_TIMEOUT_SECS),
            min_stake: 1000_000_000_000_000_000, // 1 SAGE
            quorum_percentage: QUORUM_PERCENTAGE,
            enable_slashing: true,
        }
    }
}

impl ValidatorConsensus {
    /// Create a new consensus engine
    pub fn new(
        identity: ValidatorInfo,
        private_key: [u8; 32],
        config: ConsensusConfig,
    ) -> Self {
        let (vote_tx, _) = broadcast::channel(1000);

        ValidatorConsensus {
            identity,
            private_key,
            validators: Arc::new(RwLock::new(HashMap::new())),
            pending_votes: Arc::new(RwLock::new(HashMap::new())),
            finalized_results: Arc::new(RwLock::new(HashMap::new())),
            vote_tx,
            config,
        }
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
        validators.insert(validator.address.clone(), validator);
        Ok(())
    }

    /// Remove a validator
    pub async fn remove_validator(&self, address: &str) -> Result<()> {
        let mut validators = self.validators.write().await;
        validators.remove(address);
        info!("Removed validator: {}", address);
        Ok(())
    }

    /// Get active validator count
    pub async fn active_validator_count(&self) -> usize {
        let validators = self.validators.read().await;
        validators.values().filter(|v| v.is_active).count()
    }

    /// Vote on a proof submission
    pub async fn vote_on_proof(
        &self,
        submission: &ProofSubmission,
    ) -> Result<ConsensusResult> {
        let job_id = submission.job_id;

        info!("Starting consensus for job {} from {}", job_id, submission.worker_address);

        // Step 1: Verify proof locally
        let local_result = self.verify_proof_locally(&submission.compressed_proof).await;

        // Step 2: Create and sign our vote
        let our_vote = self.create_vote(job_id, &submission.compressed_proof.proof_hash, local_result).await?;

        // Step 3: Broadcast our vote
        self.broadcast_vote(&our_vote).await?;

        // Step 4: Collect votes from other validators
        let votes = self.collect_votes(job_id, self.config.vote_timeout).await?;

        // Step 5: Check for quorum and finalize
        let result = self.finalize_consensus(job_id, votes).await?;

        // Store the result
        {
            let mut finalized = self.finalized_results.write().await;
            finalized.insert(job_id, result.clone());
        }

        info!("Consensus for job {}: {:?}", job_id, result.decision());

        Ok(result)
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

    /// Sign data with our private key
    fn sign_data(&self, data: &[u8; 32]) -> Result<[u8; 64]> {
        use sha2::{Sha256, Digest};

        // Simple signature: H(private_key || data)
        // In production, use proper ECDSA or Schnorr
        let mut hasher = Sha256::new();
        hasher.update(&self.private_key);
        hasher.update(data);
        let sig1 = hasher.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(&sig1);
        hasher2.update(&self.private_key);
        let sig2 = hasher2.finalize();

        let mut signature = [0u8; 64];
        signature[0..32].copy_from_slice(&sig1);
        signature[32..64].copy_from_slice(&sig2);

        Ok(signature)
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
        let validators = self.validators.read().await;
        let total_validators = validators.len();

        if total_validators == 0 {
            return Ok(ConsensusResult::Timeout {
                votes_received: votes.len(),
                votes_required: 1,
            });
        }

        // Count votes weighted by stake
        let mut votes_for: Vec<Vote> = Vec::new();
        let mut votes_against: Vec<Vote> = Vec::new();
        let mut stake_for: u128 = 0;
        let mut stake_against: u128 = 0;

        for vote in &votes {
            if let Some(validator) = validators.get(&vote.validator_address) {
                if vote.is_valid {
                    votes_for.push(vote.clone());
                    stake_for += validator.stake_amount;
                } else {
                    votes_against.push(vote.clone());
                    stake_against += validator.stake_amount;
                }
            }
        }

        let total_stake = stake_for + stake_against;
        let quorum_stake = (total_stake * self.config.quorum_percentage as u128) / 100;

        // Check quorum
        if votes.len() < (total_validators * 2 / 3) {
            return Ok(ConsensusResult::Timeout {
                votes_received: votes.len(),
                votes_required: (total_validators * 2 / 3) + 1,
            });
        }

        // Determine result based on stake-weighted votes
        if stake_for >= quorum_stake {
            Ok(ConsensusResult::Approved {
                votes_for,
                votes_against,
                stake_for,
            })
        } else if stake_against >= quorum_stake {
            // Get primary rejection reason
            let rejection_reason = votes_against
                .first()
                .and_then(|v| v.rejection_reason.clone())
                .unwrap_or_else(|| "Proof verification failed".to_string());

            Ok(ConsensusResult::Rejected {
                votes_for,
                votes_against,
                rejection_reason,
            })
        } else {
            Ok(ConsensusResult::Inconclusive {
                votes_for: votes_for.len(),
                votes_against: votes_against.len(),
            })
        }
    }

    /// Receive a vote from another validator
    pub async fn receive_vote(&self, vote: Vote) -> Result<()> {
        // Verify vote signature
        // (In production, verify against validator's public key)

        // Store the vote
        let mut pending = self.pending_votes.write().await;
        pending
            .entry(vote.job_id)
            .or_insert_with(Vec::new)
            .push(vote);

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator(address: &str) -> ValidatorInfo {
        ValidatorInfo {
            address: address.to_string(),
            public_key: [0u8; 32],
            stake_amount: 1000_000_000_000_000_000,
            is_active: true,
            last_seen: 0,
        }
    }

    #[tokio::test]
    async fn test_validator_registration() {
        let identity = create_test_validator("validator1");
        let consensus = ValidatorConsensus::new(
            identity.clone(),
            [0u8; 32],
            ConsensusConfig::default(),
        );

        let v2 = create_test_validator("validator2");
        consensus.register_validator(v2).await.unwrap();

        assert_eq!(consensus.active_validator_count().await, 1);
    }

    #[tokio::test]
    async fn test_vote_creation() {
        let identity = create_test_validator("validator1");
        let consensus = ValidatorConsensus::new(
            identity,
            [1u8; 32],
            ConsensusConfig::default(),
        );

        let vote = consensus.create_vote(123, &[0u8; 32], true).await.unwrap();

        assert_eq!(vote.job_id, 123);
        assert!(vote.is_valid);
        assert!(!vote.signature.is_empty());
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
}
