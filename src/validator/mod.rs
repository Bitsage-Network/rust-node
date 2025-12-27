//! Validator Module for Bitsage Network
//!
//! This module provides validator functionality for the Bitsage network:
//! - BFT consensus for proof validation
//! - Stake-weighted voting
//! - Slashing for invalid votes

pub mod consensus;

pub use consensus::{
    ValidatorConsensus, ValidatorInfo, Vote, ConsensusResult,
    ConsensusConfig, ProofSubmission,
    VOTE_TIMEOUT_SECS, QUORUM_PERCENTAGE, MAX_VALIDATORS,
};
