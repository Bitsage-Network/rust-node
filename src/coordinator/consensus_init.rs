//! Consensus Initialization Helper
//!
//! Provides convenient initialization of the full SageGuard consensus stack:
//! - AccountManager (keystore → transaction signing)
//! - FraudProofClient (on-chain fraud challenges)
//! - ConsensusPersistence (RocksDB state)
//! - StakingClient (validator stake queries)
//! - SageGuardConsensus (BFT voting)

use anyhow::{Context, Result};
use p256::ecdsa::SigningKey;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use crate::obelysk::starknet::{
    AccountManager, AccountManagerConfig, FraudProofClient, FraudProofConfig, StakingClient,
    StakingClientConfig,
};
use crate::validator::{
    consensus::{ConsensusConfig, SageGuardConsensus},
    persistence::{ConsensusPersistence, PersistenceConfig},
};

/// Consensus initialization configuration from TOML
#[derive(Debug, Clone)]
pub struct ConsensusInitConfig {
    // Starknet account
    pub deployer_address: String,
    pub keystore_path: String,
    pub keystore_password: String,
    pub rpc_url: String,
    pub network: String,

    // Contract addresses
    pub fraud_proof_address: String,
    pub worker_staking_address: String,

    // Consensus settings
    pub enable_consensus: bool,
    pub quorum_percentage: u8,
    pub vote_timeout_seconds: u64,
    pub max_validators: usize,
    pub enable_poc_weighting: bool,
    pub stake_ratio: f64,
    pub poc_ratio: f64,

    // Persistence
    pub persistence_enabled: bool,
    pub persistence_db_path: String,
    pub max_results_history: u64,

    // Fraud proofs
    pub fraud_proof_enabled: bool,
    pub fraud_proof_confidence_threshold: u8,
    pub fraud_proof_auto_challenge: bool,
    pub fraud_proof_deposit: u128,
}

impl ConsensusInitConfig {
    /// Load from environment or use defaults
    pub fn from_env() -> Result<Self> {
        // Check if we're in production mode
        let is_production = std::env::var("BITSAGE_ENV")
            .map(|v| v.to_lowercase() == "production" || v.to_lowercase() == "mainnet")
            .unwrap_or(false);

        let network = std::env::var("STARKNET_NETWORK")
            .unwrap_or_else(|_| "sepolia".to_string());

        // Require KEYSTORE_PASSWORD in production or mainnet
        let keystore_password = std::env::var("KEYSTORE_PASSWORD")
            .unwrap_or_else(|_| {
                if is_production || network.to_lowercase() == "mainnet" {
                    panic!("CRITICAL: KEYSTORE_PASSWORD environment variable is required for production/mainnet. Never use default passwords with real funds!");
                }
                tracing::warn!("⚠️  KEYSTORE_PASSWORD not set, using insecure default. Only acceptable for testnet development!");
                "bitsage123-dev-only".to_string()
            });

        Ok(Self {
            deployer_address: std::env::var("DEPLOYER_ADDRESS")
                .unwrap_or_else(|_| "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string()),
            keystore_path: std::env::var("KEYSTORE_PATH")
                .unwrap_or_else(|_| "../BitSage-Cairo-Smart-Contracts/deployment/sepolia_keystore.json".to_string()),
            keystore_password,
            rpc_url: std::env::var("STARKNET_RPC_URL")
                .unwrap_or_else(|_| "https://starknet-sepolia-rpc.publicnode.com".to_string()),
            network,

            fraud_proof_address: std::env::var("FRAUD_PROOF_ADDRESS")
                .unwrap_or_else(|_| "0x5d5bc1565e4df7c61c811b0c494f1345fc0f964e154e57e829c727990116b50".to_string()),
            worker_staking_address: std::env::var("WORKER_STAKING_ADDRESS")
                .unwrap_or_else(|_| "0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613".to_string()),

            enable_consensus: std::env::var("ENABLE_CONSENSUS")
                .map(|v| v == "true")
                .unwrap_or(true),
            quorum_percentage: std::env::var("QUORUM_PERCENTAGE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(67),
            vote_timeout_seconds: std::env::var("VOTE_TIMEOUT_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            max_validators: std::env::var("MAX_VALIDATORS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            enable_poc_weighting: std::env::var("ENABLE_POC_WEIGHTING")
                .map(|v| v == "true")
                .unwrap_or(true),
            stake_ratio: std::env::var("STAKE_RATIO")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.7),
            poc_ratio: std::env::var("POC_RATIO")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.3),

            persistence_enabled: std::env::var("PERSISTENCE_ENABLED")
                .map(|v| v == "true")
                .unwrap_or(true),
            persistence_db_path: std::env::var("PERSISTENCE_DB_PATH")
                .unwrap_or_else(|_| "./data/consensus".to_string()),
            max_results_history: std::env::var("MAX_RESULTS_HISTORY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10000),

            fraud_proof_enabled: std::env::var("FRAUD_PROOF_ENABLED")
                .map(|v| v == "true")
                .unwrap_or(true),
            fraud_proof_confidence_threshold: std::env::var("FRAUD_PROOF_CONFIDENCE_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90),
            fraud_proof_auto_challenge: std::env::var("FRAUD_PROOF_AUTO_CHALLENGE")
                .map(|v| v == "true")
                .unwrap_or(true),
            fraud_proof_deposit: std::env::var("FRAUD_PROOF_DEPOSIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500_000_000_000_000_000_000), // 500 SAGE
        })
    }
}

/// Initialized consensus components
pub struct InitializedConsensus {
    pub consensus: Arc<SageGuardConsensus>,
    pub staking_client: Arc<StakingClient>,
    pub account_manager: Arc<AccountManager>,
    pub fraud_proof_client: Arc<FraudProofClient>,
    pub persistence: Arc<ConsensusPersistence>,
}

/// Initialize the full consensus stack
pub async fn initialize_consensus(config: ConsensusInitConfig) -> Result<InitializedConsensus> {
    info!("🚀 Initializing SageGuard consensus system...");

    if !config.enable_consensus {
        return Err(anyhow::anyhow!("Consensus is disabled in configuration"));
    }

    // 1. Initialize AccountManager
    info!("📝 Loading Starknet account from keystore...");
    let account_config = AccountManagerConfig::from_toml(
        &config.keystore_path,
        config.keystore_password.clone(),
        &config.deployer_address,
        config.rpc_url.clone(),
        &config.network,
    )?;

    let account_manager = Arc::new(
        AccountManager::new(account_config)
            .await
            .context("Failed to initialize AccountManager")?,
    );

    info!(
        "✅ Account manager initialized for address: {}",
        config.deployer_address
    );

    // 2. Initialize FraudProofClient
    let fraud_proof_config = FraudProofConfig {
        contract_address: starknet::core::types::FieldElement::from_hex_be(
            &config.fraud_proof_address,
        )?,
        challenge_deposit: config.fraud_proof_deposit,
        challenge_period: 86400, // 24 hours
        confidence_threshold: config.fraud_proof_confidence_threshold,
        auto_challenge: config.fraud_proof_auto_challenge,
    };

    let fraud_proof_client = if config.fraud_proof_enabled {
        info!("⚖️  Initializing fraud proof client (production mode)...");
        Arc::new(FraudProofClient::with_account(
            fraud_proof_config,
            account_manager.clone(),
        ))
    } else {
        info!("⚠️  Fraud proof client disabled (dev mode)");
        Arc::new(FraudProofClient::new(fraud_proof_config))
    };

    // 3. Initialize Persistence
    let persistence = if config.persistence_enabled {
        info!("💾 Initializing RocksDB persistence...");
        let persistence_config = PersistenceConfig {
            db_path: config.persistence_db_path.clone(),
            enable_compression: true,
            max_results_history: config.max_results_history,
            enable_wal: true,
        };

        Some(Arc::new(
            ConsensusPersistence::new(persistence_config)
                .context("Failed to initialize persistence")?,
        ))
    } else {
        info!("⚠️  Persistence disabled");
        None
    };

    // 4. Initialize StakingClient
    info!("🔒 Initializing staking client...");
    let staking_config = StakingClientConfig {
        rpc_url: config.rpc_url.clone(),
        staking_contract: config.worker_staking_address.clone(),
        timeout: Duration::from_secs(30),
        enabled: true,
    };

    let staking_client = Arc::new(StakingClient::new(staking_config));

    // 5. Initialize Consensus
    info!("🗳️  Initializing SageGuard consensus...");

    // For development, use a test signing key
    // In production, this should be loaded from a secure keystore
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);

    let consensus_config = ConsensusConfig {
        quorum_percentage: config.quorum_percentage as u64,
        vote_timeout: Duration::from_secs(config.vote_timeout_seconds),
        enable_poc_weighting: config.enable_poc_weighting,
        stake_ratio: config.stake_ratio,
        poc_ratio: config.poc_ratio,
        ..Default::default()
    };

    // Initial stake amount (for coordinator as validator)
    let initial_stake = 10_000_000_000_000_000_000_000u128; // 10,000 SAGE

    let consensus = Arc::new(SageGuardConsensus::with_extensions(
        config.deployer_address.clone(),
        signing_key,
        initial_stake,
        consensus_config,
        Some(fraud_proof_client.clone()),
        persistence.clone(),
    ));

    info!("✅ SageGuard consensus system initialized!");
    info!(
        "   Quorum: {}%, PoC weighting: {}, Fraud proofs: {}",
        config.quorum_percentage,
        config.enable_poc_weighting,
        config.fraud_proof_enabled
    );

    Ok(InitializedConsensus {
        consensus,
        staking_client,
        account_manager,
        fraud_proof_client,
        persistence: persistence.unwrap_or_else(|| {
            // Should never happen, but provide a default for safety
            Arc::new(
                ConsensusPersistence::new(PersistenceConfig::default())
                    .expect("Failed to create default persistence"),
            )
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        let config = ConsensusInitConfig::from_env().unwrap();
        assert_eq!(config.quorum_percentage, 67);
        assert!(config.enable_poc_weighting);
        assert_eq!(config.stake_ratio, 0.7);
        assert_eq!(config.poc_ratio, 0.3);
    }
}
