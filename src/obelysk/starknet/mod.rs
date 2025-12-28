//! Starknet Integration Module
//!
//! This module provides the bridge between Obelysk GPU proofs and Starknet L2 verification.
//! It handles proof serialization to Cairo-compatible format and submission to Starknet.

pub mod proof_serializer;
pub mod starknet_client;
pub mod verifier_contract;

// Proof compression for 30-50% calldata/gas savings
pub mod proof_compression;

// Verifier optimization for reduced on-chain verification costs
pub mod verifier_optimization;

// Staking contract client for worker stake verification
pub mod staking_client;

// Reputation contract client for worker reputation queries
pub mod reputation_client;

// Network configuration, circuit breaker, and metrics
pub mod network;

// Faucet contract client for testnet token distribution
pub mod faucet_client;

pub use proof_serializer::{CairoSerializedProof, ProofSerializer};
pub use starknet_client::{
    StarknetClient, StarknetClientConfig,
    FriConfig, FriLayerCommitment, FriVerificationRequest, FriVerificationResult,
    SubmissionResult, SubmissionStatus, VerificationResult,
};
pub use verifier_contract::VerifierContract;
pub use proof_compression::{
    ProofCompressor, CompressedProof, CompressionLevel, CompressionAlgorithm,
    CompressionStats, BatchCompressor, OnChainCompressedProof,
};
pub use staking_client::{
    StakingClient, StakingClientConfig, GpuTier, WorkerStake,
};
pub use reputation_client::{
    ReputationClient, ReputationClientConfig, ReputationScore,
};
// Export network types for production configuration
pub use network::{
    StarknetNetwork, CircuitBreaker, CircuitBreakerConfig, CircuitState,
    RpcMetrics, RpcMetricsSnapshot, NetworkContracts,
};
// Export faucet types
pub use faucet_client::{
    FaucetClient, FaucetClientConfig, FaucetStatus, ClaimInfo, ClaimResult, FaucetConfig,
};
// Export verifier optimization types
pub use verifier_optimization::{
    // Sparse encoding
    SparseEncoder, SparseEncodedProof,
    // Merkle path optimization
    MerklePathOptimizer, OptimizedMerklePaths, CompactMerklePath,
    // FRI optimization
    FriOptimizer, OptimizedFriProof, OptimizedFriLayer,
    // Cairo hints
    CairoHintsGenerator, CairoVerifierHints, HintMetadata,
    // Batch verification
    BatchOptimizer, BatchVerificationConfig, OptimizedBatch, BatchMetadata,
    // Gas benchmarking
    GasBenchmark, GasBreakdown, OptimizationSavings, OptimizationComparison,
    // Full pipeline
    OptimizationPipeline, OptimizationPipelineConfig, OptimizedProofPackage, OptimizedBatchPackage,
    // Constants
    GAS_PER_FELT, GAS_PER_ZERO_BYTE, GAS_PER_NONZERO_BYTE,
    BASE_VERIFICATION_GAS, PER_LAYER_GAS, PER_QUERY_GAS, PER_MERKLE_HASH_GAS,
};

