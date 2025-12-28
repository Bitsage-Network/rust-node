// Obelysk Protocol - Native Stwo Integration for BitSage Network
// Hybrid TEE+ZK Verification for ML and ETL Workloads
//
// Architecture:
// - OVM (Obelysk Virtual Machine): Register-based VM optimized for M31 field
// - Stwo Prover: Circle STARK proof generation over Mersenne-31
// - TEE Bridge: Proof of Attestation (proving TEE quotes with ZK)
// - ML Gadgets: Optimized circuits for neural network operations
// - ETL Verifier: Data pipeline integrity proofs
// - Starknet: On-chain proof verification on Starknet L2

pub mod vm;           // Obelysk VM (OVM) - M31-optimized execution
pub mod prover;       // Stwo proof generation pipeline
pub mod field;        // Mersenne-31 field operations and helpers
pub mod circuit;      // Circuit building abstractions
pub mod tee_types;    // TEE attestation types (Phase 2) ✅
pub mod tee_verifier; // TEE attestation verification circuit (Phase 2) ✅
pub mod ecdsa;        // ECDSA verification for TEE quotes (Phase 3) ✅
pub mod ml_gadgets;   // ML operations (MatMul, ReLU, etc.) (Phase 3) ✅
pub mod etl;          // ETL verification (Phase 4) ✅
pub mod stwo_adapter; // Real Stwo integration layer (Phase 5) ✅
pub mod gpu;          // GPU acceleration (CUDA/ROCm) (Phase 6) 🚀
pub mod starknet;     // Starknet L2 on-chain verification (Phase 7) ⛓️
pub mod proof_aggregation; // Recursive proof aggregation (80% gas savings) ⛓️
pub mod elgamal;      // ElGamal EC encryption for privacy payments (Phase 8) 🔐
pub mod privacy_client; // Privacy Router contract client (Phase 8) 🔐
pub mod payment_client; // Payment Router contract client (Phase 8) 💰
pub mod worker_keys;    // Worker keypair management (Phase 8) 🔑
pub mod proof_compression; // Proof compression for on-chain submission 📦
pub mod aml_monitor;       // Real-Time AML Monitoring (Phase 9) 🛡️

// Re-exports for convenience
pub use vm::{ObelyskVM, OpCode, Instruction, ExecutionTrace};
pub use prover::{ObelyskProver, ProverConfig, StarkProof, LogLevel};
pub use field::M31;
pub use circuit::{Circuit, CircuitBuilder};
pub use tee_types::{TEEType, TEEQuote, EnclaveWhitelist, MockTEEGenerator};
pub use tee_verifier::{ProofOfAttestation, AttestationCircuit};
pub use ecdsa::{ECDSAVerifier, ECDSASignature, P256Point, U256};
pub use ml_gadgets::Matrix;
pub use etl::{ETLBridge, ETLJob, ETLOpCode};
pub use starknet::{ProofSerializer, CairoSerializedProof, StarknetClient, VerifierContract};
pub use proof_aggregation::{
    ProofAggregator, AggregatorConfig, AggregatedProof, ProofCommitment,
    AggregationWitness, AggregationStats, aggregate_proofs, estimate_savings,
};
pub use elgamal::{
    Felt252, ECPoint, ElGamalCiphertext, EncryptionProof, EncryptedBalance, KeyPair,
    CryptoError, encrypt, decrypt_point, derive_public_key, homomorphic_add, homomorphic_sub,
    create_schnorr_proof, verify_schnorr_proof, create_decryption_proof, verify_decryption_proof,
    generate_randomness, generate_nonce, generate_keypair, encrypt_secure,
    create_decryption_proof_secure,
};
pub use privacy_client::{
    PrivacyRouterClient, WorkerPrivacyManager, PrivateAccount, PrivateWorkerPayment,
    felt252_to_field_element, field_element_to_felt252,
};
pub use payment_client::{
    PaymentRouterClient, PaymentToken, PaymentQuote, PaymentCalculator,
    FeeDistribution, DiscountTiers, OTCConfig,
    ProofGatedPayment, EncryptedPaymentData, PaymentSubmissionResult, ProofPaymentError,
};
pub use worker_keys::{
    WorkerKeyManager, PublicKeyExport, RegistrationSignature,
    generate_worker_keys, verify_registration_signature,
};
pub use proof_compression::{
    ProofCompressor, CompressedProof, CompressionAlgorithm,
    compute_proof_hash, compute_proof_commitment,
    MAX_ONCHAIN_PROOF_SIZE, MAX_UNCOMPRESSED_PROOF_SIZE,
};
pub use aml_monitor::{
    AmlMonitor, AmlMonitorConfig, AmlTransaction, TransactionAmount, TransactionType,
    SuspiciousPattern, PatternDetection, DetectionFactor,
    RiskScore, RiskComponents, RiskLevel, RiskFactor,
    AmlAlert, AlertSeverity, AlertType, AlertStatus, AlertNote,
    UserBehaviorBaseline, AccountStatus, JurisdictionCode,
    TransactionAnalysisResult, RecommendedAction,
    StreamingMonitor, StreamingStats, AlertStatistics,
    ComplianceIntegration,
};
