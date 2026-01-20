//! Validator Module for BitSage Network
//!
//! This module provides SageGuard consensus - Byzantine Fault Tolerant validator
//! coordination for proof validation in the BitSage network:
//! - BFT consensus for proof validation
//! - Leader-based round coordination
//! - Stake-weighted voting with SAGE tokens
//! - ECDSA signature verification
//! - View change protocol for leader timeouts
//! - Fraud proof integration for automatic slashing
//! - Proof-of-Compute weighted voting
//! - RocksDB persistence for consensus state

pub mod consensus;
pub mod persistence;
pub mod metrics;

pub use consensus::{
    SageGuardConsensus, ValidatorInfo, Vote, ConsensusResult,
    ConsensusConfig, ProofSubmission,
    View, LeaderProposal, ViewChangeRequest,
    ProofOfComputeMetrics,
    VOTE_TIMEOUT_SECS, QUORUM_PERCENTAGE, MAX_VALIDATORS,
};

pub use persistence::{
    ConsensusPersistence, PersistenceConfig, PersistenceStats,
};
