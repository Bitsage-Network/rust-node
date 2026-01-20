// Stwo Prover Integration
//
// Generates Circle STARK proofs over Mersenne-31 field
// This is the core proving engine for Obelysk

use super::field::M31;
use super::circuit::Circuit;
use super::vm::ExecutionTrace;
use serde::{Serialize, Deserialize};
use std::time::Instant;

/// Prover configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// Security level (in bits)
    pub security_bits: usize,
    
    /// FRI blow-up factor
    pub fri_blowup: usize,
    
    /// Number of FRI queries
    pub fri_queries: usize,
    
    /// Enable GPU acceleration
    pub use_gpu: bool,
    
    /// Log level for debugging
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogLevel {
    Silent,
    Normal,
    Verbose,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            security_bits: 128,        // 128-bit security
            fri_blowup: 8,             // 8x blowup for FRI
            fri_queries: 42,           // Number of random queries
            use_gpu: true,             // Use GPU if available
            log_level: LogLevel::Normal,
        }
    }
}

/// STARK proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProof {
    /// Commitments to trace polynomials
    pub trace_commitment: Vec<u8>,
    
    /// FRI proof components
    pub fri_layers: Vec<FRILayer>,
    
    /// Query openings
    pub openings: Vec<Opening>,
    
    /// Public inputs (for verification)
    pub public_inputs: Vec<M31>,
    
    /// Public outputs (for verification)
    pub public_outputs: Vec<M31>,
    
    /// Proof metadata
    pub metadata: ProofMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FRILayer {
    pub commitment: Vec<u8>,
    pub evaluations: Vec<M31>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opening {
    pub position: usize,
    pub values: Vec<M31>,
    pub merkle_path: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub trace_length: usize,
    pub trace_width: usize,
    pub generation_time_ms: u128,
    pub proof_size_bytes: usize,
    pub prover_version: String,
}

/// Obelysk Prover
pub struct ObelyskProver {
    config: ProverConfig,
}

impl ObelyskProver {
    /// Create a new prover with default config
    pub fn new() -> Self {
        Self {
            config: ProverConfig::default(),
        }
    }
    
    /// Create a prover with custom config
    pub fn with_config(config: ProverConfig) -> Self {
        Self { config }
    }
    
    /// Prove an execution trace
    /// 
    /// This is the main entry point for generating ZK proofs
    pub fn prove_execution(&self, trace: &ExecutionTrace) -> Result<StarkProof, ProverError> {
        let start = Instant::now();
        
        if self.config.log_level as u8 >= LogLevel::Normal as u8 {
            tracing::info!(
                "Starting Stwo proof generation for trace with {} steps",
                trace.steps.len()
            );
        }
        
        // Step 1: Build circuit from trace
        let circuit = super::circuit::CircuitBuilder::from_trace(trace).build();
        
        // Step 2: Generate the proof using Stwo
        let proof = self.prove_circuit(&circuit)?;
        
        let elapsed = start.elapsed();
        
        if self.config.log_level as u8 >= LogLevel::Normal as u8 {
            tracing::info!(
                "Proof generated in {}ms, size: {} bytes",
                elapsed.as_millis(),
                proof.metadata.proof_size_bytes
            );
        }
        
        Ok(proof)
    }
    
    /// Prove a circuit directly using real Stwo
    fn prove_circuit(&self, circuit: &Circuit) -> Result<StarkProof, ProverError> {
        // Use real Stwo prover
        let trace = circuit.execution_trace
            .as_ref()
            .ok_or_else(|| ProverError::InvalidCircuit("Circuit has no execution trace".to_string()))?;
        
        super::stwo_adapter::prove_with_stwo(trace, self.config.security_bits)
    }
    
    /// Estimate proof size based on trace length
    ///
    /// Returns the estimated proof size in bytes for a given trace length.
    /// Useful for pre-allocating buffers and estimating storage requirements.
    pub fn estimate_proof_size(&self, trace_length: usize) -> usize {
        // Typical Stwo proof: ~100KB for small circuits
        // Scales logarithmically with trace length
        let base_size = 100_000;  // 100KB base
        let log_factor = (trace_length as f64).log2() as usize;
        base_size + (log_factor * 10_000)
    }
    
    /// Verify a proof (for testing)
    pub fn verify_proof(&self, proof: &StarkProof) -> Result<bool, ProverError> {
        // NOTE: Mock verification for Phase 1
        // Real Stwo verification will be implemented in Phase 2
        // For now, we validate proof structure and metadata
        
        if proof.metadata.trace_length == 0 {
            return Err(ProverError::InvalidProof("Zero trace length".to_string()));
        }
        
        if proof.public_inputs.len() > 256 {
            return Err(ProverError::InvalidProof("Too many public inputs".to_string()));
        }
        
        Ok(true)
    }
}

impl Default for ObelyskProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Prover errors
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
    
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    
    #[error("Proving failed: {0}")]
    ProvingFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Stwo error: {0}")]
    Stwo(String),
}

// ===== Integration with Stwo (to be implemented) =====

/// NOTE: Stwo Integration Roadmap
/// 
/// **Current Status** (Phase 1): Mock implementation
/// - The prover currently generates mock proofs for testing
/// - All infrastructure (VM, circuits, field ops) is ready
/// - This allows us to develop and test the full BitSage + Obelysk stack
/// 
/// **Next Step** (Phase 1.5): Switch to Rust nightly
/// - Stwo requires nightly Rust features (array_chunks, etc.)
/// - Options:
///   A) Add `rust-toolchain.toml` with `channel = "nightly"`
///   B) Wait for Stwo to stabilize (expected Q1 2026)
/// 
/// **Production** (Phase 2): Real Stwo integration
/// 
/// The real implementation will use:
/// ```rust
/// use stwo_prover::core::prover::prove;
/// use stwo_prover::core::fields::m31::M31 as StwoM31;
/// use stwo_prover::core::circle::{CirclePoint, Coset};
/// use stwo_prover::core::poly::circle::CanonicCoset;
/// 
/// fn build_stwo_proof(circuit: &Circuit) -> StarkProof {
///     // 1. Convert our M31 to Stwo's M31
///     let trace_cols: Vec<Vec<StwoM31>> = build_trace_table(circuit);
///     
///     // 2. Build Circle STARK domain
///     let log_size = circuit.trace_length().trailing_zeros();
///     let domain = CanonicCoset::new(log_size);
///     
///     // 3. Commit to trace using Merkle tree
///     let trace_commitment = commit_to_trace(&trace_cols);
///     
///     // 4. Generate composition polynomial
///     let composition = build_composition_polynomial(&trace_cols, &circuit.constraints);
///     
///     // 5. Run FRI protocol
///     let fri_proof = run_fri_protocol(&composition, &domain);
///     
///     // 6. Generate query openings
///     let openings = generate_openings(&trace_cols, &fri_proof);
///     
///     StarkProof { ... }
/// }
/// ```
/// 
/// **Why This Approach Works**:
/// - We can develop and test the full system now
/// - The mock prover has the exact same interface as the real one
/// - When we're ready, we just replace the implementation (no API changes)
/// - BitSage coordinator, workers, smart contracts all work the same
/// 
/// **Performance Comparison** (once real Stwo is integrated):
/// - Mock: Instant (no actual proving)
/// - Real Stwo: 1-10 seconds for typical ML inference
/// - Giza (Stone): 10-100 seconds for same workload
/// - 10x faster proving = competitive advantage

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::vm::ObelyskVM;

    #[test]
    fn test_basic_proving() {
        use crate::obelysk::vm::{Instruction, OpCode};

        let mut vm = ObelyskVM::new();

        // Larger program to generate sufficient trace for stwo validation
        // This computes: sum = 0; for i = 1 to 16: sum += i
        // Result: 1+2+3+...+16 = 136
        let mut program = Vec::new();

        // Initialize sum in r1 = 0
        program.push(Instruction {
            opcode: OpCode::LoadImm,
            dst: 1,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ZERO),
            address: None,
        });

        // Unrolled loop: add 1 through 16 to sum
        for i in 1..=16 {
            // Load i into r0
            program.push(Instruction {
                opcode: OpCode::LoadImm,
                dst: 0,
                src1: 0,
                src2: 0,
                immediate: Some(M31::new(i)),
                address: None,
            });
            // sum += i
            program.push(Instruction {
                opcode: OpCode::Add,
                dst: 1,
                src1: 1,
                src2: 0,
                immediate: None,
                address: None,
            });
        }

        // Halt
        program.push(Instruction {
            opcode: OpCode::Halt,
            dst: 0,
            src1: 0,
            src2: 0,
            immediate: None,
            address: None,
        });

        vm.load_program(program);
        let trace = vm.execute().unwrap();

        // Verify we have a reasonable trace size (33 steps: 1 init + 16*2 ops)
        assert!(trace.steps.len() >= 32, "Trace too small: {} steps", trace.steps.len());

        // Generate proof
        let prover = ObelyskProver::new();
        let proof = prover.prove_execution(&trace).unwrap();

        // Verify proof structure
        assert!(prover.verify_proof(&proof).unwrap());
        assert!(proof.metadata.trace_length >= 32);
        assert!(!proof.trace_commitment.is_empty());
        assert!(!proof.fri_layers.is_empty());
    }

    #[test]
    fn test_prover_config() {
        let config = ProverConfig::default();
        assert_eq!(config.security_bits, 128);
        assert_eq!(config.fri_blowup, 8);
        assert!(config.use_gpu);
    }
}

