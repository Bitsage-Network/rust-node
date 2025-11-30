// Obelysk Protocol - Native Stwo Integration for BitSage Network
// Hybrid TEE+ZK Verification for ML and ETL Workloads
//
// Architecture:
// - OVM (Obelysk Virtual Machine): Register-based VM optimized for M31 field
// - Stwo Prover: Circle STARK proof generation over Mersenne-31
// - TEE Bridge: Proof of Attestation (proving TEE quotes with ZK)
// - ML Gadgets: Optimized circuits for neural network operations
// - ETL Verifier: Data pipeline integrity proofs

pub mod vm;           // Obelysk VM (OVM) - M31-optimized execution
pub mod prover;       // Stwo proof generation pipeline
pub mod field;        // Mersenne-31 field operations and helpers
pub mod circuit;      // Circuit building abstractions
pub mod tee_types;    // TEE attestation types (Phase 2) ✅
pub mod tee_verifier; // TEE attestation verification circuit (Phase 2) ✅
pub mod ml_gadgets;   // ML operations (MatMul, ReLU, etc.) (Phase 3) ✅
pub mod etl;          // ETL verification (Phase 4) ✅
pub mod stwo_adapter; // Real Stwo integration layer (Phase 5) ✅
pub mod gpu;          // GPU acceleration (CUDA/ROCm) (Phase 6) 🚀

// Re-exports for convenience
pub use vm::{ObelyskVM, OpCode, Instruction, ExecutionTrace};
pub use prover::{ObelyskProver, ProverConfig, StarkProof, LogLevel};
pub use field::M31;
pub use circuit::{Circuit, CircuitBuilder};
pub use tee_types::{TEEType, TEEQuote, EnclaveWhitelist, MockTEEGenerator};
pub use tee_verifier::{ProofOfAttestation, AttestationCircuit};
pub use ml_gadgets::Matrix;
pub use etl::{ETLBridge, ETLJob, ETLOpCode};
