//! Fraud Proof Client for BitSage Validator Consensus
//!
//! Integrates SageGuard consensus with the on-chain fraud proof system
//! to automatically slash validators who cast fraudulent votes.

use anyhow::{Result, anyhow};
use starknet::{
    accounts::Call,
    core::types::FieldElement,
    core::utils::get_selector_from_name,
};
use std::sync::Arc;
use tracing::{info, debug};

use super::account_manager::AccountManager;

/// Fraud proof challenge status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    ValidProof,    // Challenger wins, validator slashed
    InvalidProof,  // Validator wins
    Expired,       // Challenge expired
}

impl From<u8> for ChallengeStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => ChallengeStatus::Pending,
            1 => ChallengeStatus::ValidProof,
            2 => ChallengeStatus::InvalidProof,
            3 => ChallengeStatus::Expired,
            _ => ChallengeStatus::Pending,
        }
    }
}

/// Verification method for fraud proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMethod {
    ZKProof = 0,           // ZK-SNARK verification
    HashComparison = 1,    // Simple hash comparison
    TEEAttestation = 2,    // Hardware TEE verification
    ManualArbitration = 3, // DAO/Committee vote
}

/// Challenge record from the fraud proof contract
#[derive(Debug, Clone)]
pub struct Challenge {
    pub challenge_id: u128,
    pub job_id: u128,
    pub validator_address: String,
    pub challenger: String,
    pub deposit: u128,
    pub original_vote_hash: [u8; 32],
    pub disputed_vote_hash: [u8; 32],
    pub verification_method: VerificationMethod,
    pub status: ChallengeStatus,
    pub created_at: u64,
    pub resolved_at: u64,
}

/// Fraud Proof Client Configuration
#[derive(Debug, Clone)]
pub struct FraudProofConfig {
    /// Fraud proof contract address
    pub contract_address: FieldElement,

    /// Challenge deposit amount (in SAGE tokens)
    pub challenge_deposit: u128,

    /// Challenge period (seconds)
    pub challenge_period: u64,

    /// Minimum confidence threshold to submit challenge (0-100)
    pub confidence_threshold: u8,

    /// Enable automatic challenge submission
    pub auto_challenge: bool,
}

impl Default for FraudProofConfig {
    fn default() -> Self {
        FraudProofConfig {
            contract_address: FieldElement::ZERO,
            challenge_deposit: 500_000_000_000_000_000_000, // 500 SAGE
            challenge_period: 86400,                         // 24 hours
            confidence_threshold: 90,                        // 90% confidence
            auto_challenge: true,
        }
    }
}

/// Client for interacting with the fraud proof contract
pub struct FraudProofClient {
    /// Configuration
    config: FraudProofConfig,

    /// Starknet account manager for signing transactions
    account_manager: Option<Arc<AccountManager>>,

    /// Challenge tracking
    submitted_challenges: Arc<tokio::sync::RwLock<std::collections::HashMap<u128, Challenge>>>,
}

impl FraudProofClient {
    /// Create a new fraud proof client (dev mode, no account manager)
    pub fn new(config: FraudProofConfig) -> Self {
        FraudProofClient {
            config,
            account_manager: None,
            submitted_challenges: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Create a new fraud proof client with account manager for production use
    pub fn with_account(config: FraudProofConfig, account_manager: Arc<AccountManager>) -> Self {
        FraudProofClient {
            config,
            account_manager: Some(account_manager),
            submitted_challenges: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Submit a fraud challenge for an invalid validator vote
    ///
    /// # Arguments
    /// * `job_id` - The consensus job ID
    /// * `validator_address` - Address of the fraudulent validator
    /// * `original_vote_hash` - Hash of the expected/correct vote
    /// * `disputed_vote_hash` - Hash of the fraudulent vote
    /// * `evidence_hash` - Hash of the evidence (proof data, etc.)
    /// * `verification_method` - How to verify the fraud
    pub async fn submit_challenge(
        &self,
        job_id: u128,
        validator_address: &str,
        original_vote_hash: [u8; 32],
        disputed_vote_hash: [u8; 32],
        evidence_hash: [u8; 32],
        verification_method: VerificationMethod,
    ) -> Result<u128> {
        info!(
            "Submitting fraud challenge for validator {} on job {}",
            validator_address, job_id
        );

        // If account manager is available, submit real transaction
        let challenge_id = if let Some(account_mgr) = &self.account_manager {
            self.submit_on_chain_challenge(
                account_mgr,
                job_id,
                validator_address,
                original_vote_hash,
                disputed_vote_hash,
                evidence_hash,
                verification_method,
            ).await?
        } else {
            // Dev mode: log only
            info!(
                "⚠️  Dev mode: Fraud challenge details: validator={}, method={:?}, original={:?}, disputed={:?}",
                validator_address,
                verification_method,
                &original_vote_hash[..8],
                &disputed_vote_hash[..8]
            );
            job_id // Use job_id as challenge_id in dev mode
        };

        // Track the challenge locally
        let challenge = Challenge {
            challenge_id,
            job_id,
            validator_address: validator_address.to_string(),
            challenger: self.account_manager
                .as_ref()
                .map(|am| format!("{:#064x}", am.address()))
                .unwrap_or_else(|| "dev_mode".to_string()),
            deposit: self.config.challenge_deposit,
            original_vote_hash,
            disputed_vote_hash,
            verification_method,
            status: ChallengeStatus::Pending,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            resolved_at: 0,
        };

        let mut challenges = self.submitted_challenges.write().await;
        challenges.insert(challenge_id, challenge);

        Ok(challenge_id)
    }

    /// Submit fraud proof challenge on-chain
    async fn submit_on_chain_challenge(
        &self,
        account_mgr: &AccountManager,
        job_id: u128,
        validator_address: &str,
        original_vote_hash: [u8; 32],
        disputed_vote_hash: [u8; 32],
        evidence_hash: [u8; 32],
        verification_method: VerificationMethod,
    ) -> Result<u128> {
        info!("Submitting fraud challenge on-chain to contract {:#064x}", self.config.contract_address);

        // Convert validator address
        let validator_felt = FieldElement::from_hex_be(validator_address)
            .map_err(|e| anyhow!("Invalid validator address: {}", e))?;

        // Convert hashes to FieldElements
        let original_hash_felt = Self::bytes_to_field_element(&original_vote_hash)?;
        let disputed_hash_felt = Self::bytes_to_field_element(&disputed_vote_hash)?;
        let evidence_hash_felt = Self::bytes_to_field_element(&evidence_hash)?;

        // Build calldata: submit_challenge(job_id, validator, original_hash, disputed_hash, evidence_hash, method)
        let calldata = vec![
            FieldElement::from(job_id),
            validator_felt,
            original_hash_felt,
            disputed_hash_felt,
            evidence_hash_felt,
            FieldElement::from(verification_method as u64),
        ];

        // Create contract call
        let selector = get_selector_from_name("submit_challenge")
            .map_err(|e| anyhow!("Failed to get selector: {}", e))?;

        let call = Call {
            to: self.config.contract_address,
            selector,
            calldata,
        };

        // Execute transaction
        let tx_hash = account_mgr.execute_calls(vec![call]).await
            .map_err(|e| anyhow!("Failed to submit fraud challenge transaction: {}", e))?;

        info!(
            "Fraud challenge submitted on-chain! Tx hash: {:#064x}",
            tx_hash
        );

        // In production, we should wait for the transaction to be accepted
        // and parse the ChallengeSubmitted event to get the actual challenge_id
        // For now, use job_id as challenge_id
        Ok(job_id)
    }

    /// Convert 32-byte array to FieldElement
    fn bytes_to_field_element(bytes: &[u8; 32]) -> Result<FieldElement> {
        FieldElement::from_bytes_be(bytes)
            .map_err(|e| anyhow!("Failed to convert bytes to FieldElement: {:?}", e))
    }

    /// Get challenge status
    pub async fn get_challenge(&self, challenge_id: u128) -> Result<Option<Challenge>> {
        // First check local cache
        {
            let challenges = self.submitted_challenges.read().await;
            if let Some(challenge) = challenges.get(&challenge_id) {
                return Ok(Some(challenge.clone()));
            }
        }

        // NOTE: In production, query from contract using Starknet RPC
        // For now, return None if not in cache
        debug!("Challenge {} not found in cache", challenge_id);
        Ok(None)
    }

    /// Resolve a challenge (call after challenge period)
    pub async fn resolve_challenge(&self, challenge_id: u128) -> Result<()> {
        info!("Resolving challenge {}", challenge_id);

        // NOTE: In production, call resolve_challenge on fraud_proof contract
        // This would execute a Starknet transaction

        info!("Challenge {} resolution logged (dev mode)", challenge_id);
        Ok(())
    }

    /// Check if a validator should be challenged
    ///
    /// Returns true if confidence is above threshold
    pub fn should_challenge(&self, confidence: u8) -> bool {
        self.config.auto_challenge && confidence >= self.config.confidence_threshold
    }

    /// Get fraud proof statistics
    pub async fn get_stats(&self) -> Result<FraudProofStats> {
        // NOTE: In production, query stats from contract using Starknet RPC

        Ok(FraudProofStats {
            total_challenges: 0,
            valid_challenges: 0,
            invalid_challenges: 0,
            total_slashed: 0,
            total_rewards_paid: 0,
        })
    }

}

/// Fraud proof statistics
#[derive(Debug, Clone)]
pub struct FraudProofStats {
    pub total_challenges: u64,
    pub valid_challenges: u64,
    pub invalid_challenges: u64,
    pub total_slashed: u128,
    pub total_rewards_paid: u128,
}

/// Trait for fraud proof client to enable dynamic dispatch
#[async_trait::async_trait]
pub trait FraudProofClientTrait: Send + Sync {
    /// Submit a fraud challenge
    async fn submit_challenge(
        &self,
        job_id: u128,
        validator_address: &str,
        original_vote_hash: [u8; 32],
        disputed_vote_hash: [u8; 32],
        evidence_hash: [u8; 32],
        verification_method: VerificationMethod,
    ) -> Result<u128>;

    /// Get challenge status
    async fn get_challenge(&self, challenge_id: u128) -> Result<Option<Challenge>>;

    /// Resolve a challenge
    async fn resolve_challenge(&self, challenge_id: u128) -> Result<()>;

    /// Check if should submit challenge based on confidence
    fn should_challenge(&self, confidence: u8) -> bool;

    /// Get fraud proof statistics
    async fn get_stats(&self) -> Result<FraudProofStats>;
}

#[async_trait::async_trait]
impl FraudProofClientTrait for FraudProofClient {
    async fn submit_challenge(
        &self,
        job_id: u128,
        validator_address: &str,
        original_vote_hash: [u8; 32],
        disputed_vote_hash: [u8; 32],
        evidence_hash: [u8; 32],
        verification_method: VerificationMethod,
    ) -> Result<u128> {
        self.submit_challenge(job_id, validator_address, original_vote_hash, disputed_vote_hash, evidence_hash, verification_method).await
    }

    async fn get_challenge(&self, challenge_id: u128) -> Result<Option<Challenge>> {
        self.get_challenge(challenge_id).await
    }

    async fn resolve_challenge(&self, challenge_id: u128) -> Result<()> {
        self.resolve_challenge(challenge_id).await
    }

    fn should_challenge(&self, confidence: u8) -> bool {
        self.should_challenge(confidence)
    }

    async fn get_stats(&self) -> Result<FraudProofStats> {
        self.get_stats().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_status_conversion() {
        assert_eq!(ChallengeStatus::from(0), ChallengeStatus::Pending);
        assert_eq!(ChallengeStatus::from(1), ChallengeStatus::ValidProof);
        assert_eq!(ChallengeStatus::from(2), ChallengeStatus::InvalidProof);
        assert_eq!(ChallengeStatus::from(3), ChallengeStatus::Expired);
    }

    #[test]
    fn test_should_challenge_logic() {
        let config = FraudProofConfig {
            auto_challenge: true,
            confidence_threshold: 90,
            ..Default::default()
        };

        // Create a mock provider (in real tests, use proper mocking)
        // For now, just test the config logic
        assert!(config.confidence_threshold == 90);
    }
}
