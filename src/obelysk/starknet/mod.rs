//! Starknet Integration Module
//!
//! This module provides the bridge between Obelysk GPU proofs and Starknet L2 verification.
//! It handles proof serialization to Cairo-compatible format and submission to Starknet.

pub mod proof_serializer;
pub mod starknet_client;
pub mod verifier_contract;

// Proof compression for 30-50% calldata/gas savings
pub mod proof_compression;

pub use proof_serializer::{CairoSerializedProof, ProofSerializer};
pub use starknet_client::{
    StarknetClient, StarknetClientConfig, StarknetNetwork,
    FriConfig, FriLayerCommitment, FriVerificationRequest, FriVerificationResult,
    SubmissionResult, SubmissionStatus, VerificationResult,
};
pub use verifier_contract::VerifierContract;
pub use proof_compression::{
    ProofCompressor, CompressedProof, CompressionLevel, CompressionAlgorithm,
    CompressionStats, BatchCompressor, OnChainCompressedProof,
};

