//! IO Binder - Cryptographic binding of proof to inputs and outputs
//!
//! This module ensures that proofs are cryptographically bound to specific
//! inputs and outputs, preventing proof reuse attacks. The io_commitment
//! is embedded in the STARK proof trace and verified on-chain.
//!
//! # Security Model
//!
//! The io_commitment = H(inputs || outputs) is:
//! 1. Computed during trace generation
//! 2. Embedded in the first 8 trace columns of row 0
//! 3. Verified as a public input on-chain
//! 4. Used to gate payment release
//!
//! Any tampering with inputs or outputs will change the commitment,
//! causing verification to fail.

use sha2::{Sha256, Digest};
use crate::obelysk::field::M31;
use serde::{Serialize, Deserialize};

/// IO Commitment size in bytes (SHA-256 output)
pub const IO_COMMITMENT_SIZE: usize = 32;

/// Number of M31 elements needed to store the commitment in trace
/// Each M31 can hold ~31 bits, so 32 bytes / 4 bytes per M31 = 8 M31s
pub const IO_COMMITMENT_M31_COUNT: usize = 8;

/// IOBinder creates a cryptographic commitment binding proof to inputs/outputs
///
/// # Example
///
/// ```ignore
/// let mut binder = IOBinder::new();
/// binder.add_input(&input_bytes);
/// binder.add_vm_inputs(&vm_inputs);
/// binder.add_vm_outputs(&vm_outputs);
/// let commitment = binder.finalize();
/// ```
#[derive(Debug, Clone)]
pub struct IOBinder {
    hasher: Sha256,
    input_count: usize,
    output_count: usize,
}

impl IOBinder {
    /// Create a new IOBinder instance
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        // Domain separation tag to prevent cross-protocol attacks
        hasher.update(b"OBELYSK_IO_COMMITMENT_V1");
        Self {
            hasher,
            input_count: 0,
            output_count: 0,
        }
    }

    /// Add raw input bytes to the commitment
    pub fn add_input(&mut self, data: &[u8]) {
        // Prefix with length to prevent length extension attacks
        self.hasher.update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);
        self.input_count += 1;
    }

    /// Add raw output bytes to the commitment
    pub fn add_output(&mut self, data: &[u8]) {
        // Domain separator between inputs and outputs
        if self.output_count == 0 {
            self.hasher.update(b"__OUTPUTS__");
        }
        // Prefix with length
        self.hasher.update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);
        self.output_count += 1;
    }

    /// Add VM input registers to the commitment
    pub fn add_vm_inputs(&mut self, inputs: &[M31]) {
        self.hasher.update(b"__VM_INPUTS__");
        self.hasher.update(&(inputs.len() as u64).to_le_bytes());
        for input in inputs {
            self.hasher.update(&input.value().to_le_bytes());
        }
    }

    /// Add VM output registers to the commitment
    pub fn add_vm_outputs(&mut self, outputs: &[M31]) {
        self.hasher.update(b"__VM_OUTPUTS__");
        self.hasher.update(&(outputs.len() as u64).to_le_bytes());
        for output in outputs {
            self.hasher.update(&output.value().to_le_bytes());
        }
    }

    /// Add execution trace metadata to strengthen binding
    pub fn add_trace_metadata(&mut self, trace_length: usize, trace_width: usize) {
        self.hasher.update(b"__TRACE_META__");
        self.hasher.update(&(trace_length as u64).to_le_bytes());
        self.hasher.update(&(trace_width as u64).to_le_bytes());
    }

    /// Add job ID for replay protection
    pub fn add_job_id(&mut self, job_id: &str) {
        self.hasher.update(b"__JOB_ID__");
        self.hasher.update(&(job_id.len() as u64).to_le_bytes());
        self.hasher.update(job_id.as_bytes());
    }

    /// Add worker ID for attribution
    pub fn add_worker_id(&mut self, worker_id: &str) {
        self.hasher.update(b"__WORKER__");
        self.hasher.update(&(worker_id.len() as u64).to_le_bytes());
        self.hasher.update(worker_id.as_bytes());
    }

    /// Add timestamp for freshness
    pub fn add_timestamp(&mut self, timestamp_secs: u64) {
        self.hasher.update(b"__TIMESTAMP__");
        self.hasher.update(&timestamp_secs.to_le_bytes());
    }

    /// Finalize and return the 32-byte io_commitment
    pub fn finalize(self) -> [u8; 32] {
        let mut commitment = [0u8; 32];
        let result = self.hasher.finalize();
        commitment.copy_from_slice(&result);
        commitment
    }

    /// Finalize and return the commitment as M31 elements for trace embedding
    ///
    /// The 32-byte commitment is split into 8 M31 elements (4 bytes each),
    /// which can be embedded in trace columns for constraint verification.
    pub fn finalize_as_m31(self) -> [M31; IO_COMMITMENT_M31_COUNT] {
        let commitment = self.finalize();
        commitment_to_m31_array(&commitment)
    }
}

impl Default for IOBinder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a 32-byte commitment to 8 M31 elements
///
/// Each M31 element holds 4 bytes (truncated to 31 bits).
/// This allows embedding the commitment in trace columns.
pub fn commitment_to_m31_array(commitment: &[u8; 32]) -> [M31; IO_COMMITMENT_M31_COUNT] {
    let mut m31_array = [M31::ZERO; IO_COMMITMENT_M31_COUNT];

    for (i, chunk) in commitment.chunks(4).enumerate() {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(chunk);
        // Mask to ensure value is < 2^31 - 1 (M31 prime)
        let value = u32::from_le_bytes(bytes) & 0x7FFFFFFF;
        m31_array[i] = M31::from_u32(value);
    }

    m31_array
}

/// Convert 8 M31 elements back to a 32-byte commitment
pub fn m31_array_to_commitment(m31_array: &[M31; IO_COMMITMENT_M31_COUNT]) -> [u8; 32] {
    let mut commitment = [0u8; 32];

    for (i, m31) in m31_array.iter().enumerate() {
        let bytes = m31.value().to_le_bytes();
        commitment[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    commitment
}

/// IO Commitment result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOCommitment {
    /// The 32-byte commitment hash
    pub commitment: [u8; 32],

    /// Commitment as M31 elements for trace embedding
    pub commitment_m31: [M31; IO_COMMITMENT_M31_COUNT],

    /// Number of inputs included
    pub input_count: usize,

    /// Number of outputs included
    pub output_count: usize,

    /// Optional job ID
    pub job_id: Option<String>,

    /// Timestamp when commitment was created
    pub created_at: u64,
}

impl IOCommitment {
    /// Create a commitment for the given inputs and outputs
    pub fn from_io(
        raw_inputs: &[u8],
        vm_inputs: &[M31],
        vm_outputs: &[M31],
        job_id: Option<&str>,
    ) -> Self {
        let mut binder = IOBinder::new();

        // Add raw inputs
        binder.add_input(raw_inputs);

        // Add VM inputs/outputs
        binder.add_vm_inputs(vm_inputs);
        binder.add_vm_outputs(vm_outputs);

        // Add job ID if provided
        if let Some(id) = job_id {
            binder.add_job_id(id);
        }

        // Add timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        binder.add_timestamp(timestamp);

        let input_count = binder.input_count;
        let output_count = binder.output_count;

        let commitment = binder.finalize();
        let commitment_m31 = commitment_to_m31_array(&commitment);

        Self {
            commitment,
            commitment_m31,
            input_count,
            output_count,
            job_id: job_id.map(String::from),
            created_at: timestamp,
        }
    }

    /// Verify that a given commitment matches expected inputs/outputs
    pub fn verify(
        expected: &[u8; 32],
        raw_inputs: &[u8],
        vm_inputs: &[M31],
        vm_outputs: &[M31],
        job_id: Option<&str>,
        timestamp: Option<u64>,
    ) -> bool {
        let mut binder = IOBinder::new();

        binder.add_input(raw_inputs);
        binder.add_vm_inputs(vm_inputs);
        binder.add_vm_outputs(vm_outputs);

        if let Some(id) = job_id {
            binder.add_job_id(id);
        }

        if let Some(ts) = timestamp {
            binder.add_timestamp(ts);
        }

        let computed = binder.finalize();
        computed == *expected
    }

    /// Convert commitment to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.commitment)
    }
}

/// Builder for creating IO commitments with various options
pub struct IOCommitmentBuilder {
    binder: IOBinder,
    input_count: usize,
    output_count: usize,
    job_id: Option<String>,
    timestamp: Option<u64>,
}

impl IOCommitmentBuilder {
    pub fn new() -> Self {
        Self {
            binder: IOBinder::new(),
            input_count: 0,
            output_count: 0,
            job_id: None,
            timestamp: None,
        }
    }

    /// Add raw input bytes
    pub fn with_raw_input(mut self, data: &[u8]) -> Self {
        self.binder.add_input(data);
        self.input_count += 1;
        self
    }

    /// Add raw output bytes
    pub fn with_raw_output(mut self, data: &[u8]) -> Self {
        self.binder.add_output(data);
        self.output_count += 1;
        self
    }

    /// Add VM input registers
    pub fn with_vm_inputs(mut self, inputs: &[M31]) -> Self {
        self.binder.add_vm_inputs(inputs);
        self
    }

    /// Add VM output registers
    pub fn with_vm_outputs(mut self, outputs: &[M31]) -> Self {
        self.binder.add_vm_outputs(outputs);
        self
    }

    /// Add trace metadata
    pub fn with_trace_metadata(mut self, trace_length: usize, trace_width: usize) -> Self {
        self.binder.add_trace_metadata(trace_length, trace_width);
        self
    }

    /// Set job ID for replay protection
    pub fn with_job_id(mut self, job_id: &str) -> Self {
        self.binder.add_job_id(job_id);
        self.job_id = Some(job_id.to_string());
        self
    }

    /// Set worker ID
    pub fn with_worker_id(mut self, worker_id: &str) -> Self {
        self.binder.add_worker_id(worker_id);
        self
    }

    /// Set explicit timestamp
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.binder.add_timestamp(timestamp);
        self.timestamp = Some(timestamp);
        self
    }

    /// Build the final commitment
    pub fn build(self) -> IOCommitment {
        let timestamp = self.timestamp.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let commitment = self.binder.finalize();
        let commitment_m31 = commitment_to_m31_array(&commitment);

        IOCommitment {
            commitment,
            commitment_m31,
            input_count: self.input_count,
            output_count: self.output_count,
            job_id: self.job_id,
            created_at: timestamp,
        }
    }
}

impl Default for IOCommitmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_binder_basic() {
        let mut binder = IOBinder::new();
        binder.add_input(b"hello");
        binder.add_output(b"world");
        let commitment = binder.finalize();

        // Commitment should be deterministic
        let mut binder2 = IOBinder::new();
        binder2.add_input(b"hello");
        binder2.add_output(b"world");
        let commitment2 = binder2.finalize();

        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_io_binder_different_inputs() {
        let mut binder1 = IOBinder::new();
        binder1.add_input(b"hello");
        let commitment1 = binder1.finalize();

        let mut binder2 = IOBinder::new();
        binder2.add_input(b"world");
        let commitment2 = binder2.finalize();

        // Different inputs should produce different commitments
        assert_ne!(commitment1, commitment2);
    }

    #[test]
    fn test_vm_inputs_outputs() {
        let inputs = vec![M31::from_u32(1), M31::from_u32(2), M31::from_u32(3)];
        let outputs = vec![M31::from_u32(6)]; // sum

        let mut binder = IOBinder::new();
        binder.add_vm_inputs(&inputs);
        binder.add_vm_outputs(&outputs);
        let commitment = binder.finalize();

        // Should produce non-zero commitment
        assert!(!commitment.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_m31_conversion_roundtrip() {
        let commitment = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
            0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        ];

        let m31_array = commitment_to_m31_array(&commitment);
        let recovered = m31_array_to_commitment(&m31_array);

        // Note: Not exact roundtrip due to M31 masking (top bit cleared)
        // But the M31 representation should be consistent
        let m31_array2 = commitment_to_m31_array(&recovered);
        assert_eq!(m31_array, m31_array2);
    }

    #[test]
    fn test_io_commitment_builder() {
        let inputs = vec![M31::from_u32(10), M31::from_u32(20)];
        let outputs = vec![M31::from_u32(30)];

        let commitment = IOCommitmentBuilder::new()
            .with_raw_input(b"test_payload")
            .with_vm_inputs(&inputs)
            .with_vm_outputs(&outputs)
            .with_job_id("job-123")
            .with_timestamp(1234567890)
            .build();

        assert_eq!(commitment.job_id, Some("job-123".to_string()));
        assert_eq!(commitment.created_at, 1234567890);
        assert!(!commitment.commitment.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_io_commitment_from_io() {
        let raw_inputs = b"input_data";
        let vm_inputs = vec![M31::from_u32(1), M31::from_u32(2)];
        let vm_outputs = vec![M31::from_u32(3)];

        let commitment = IOCommitment::from_io(
            raw_inputs,
            &vm_inputs,
            &vm_outputs,
            Some("job-456"),
        );

        assert_eq!(commitment.job_id, Some("job-456".to_string()));
        assert!(!commitment.to_hex().is_empty());
    }

    #[test]
    fn test_commitment_uniqueness() {
        // Ensure that even small changes produce different commitments
        let base_inputs = vec![M31::from_u32(100)];
        let base_outputs = vec![M31::from_u32(200)];

        let c1 = IOCommitmentBuilder::new()
            .with_vm_inputs(&base_inputs)
            .with_vm_outputs(&base_outputs)
            .with_timestamp(1000)
            .build();

        // Different input
        let c2 = IOCommitmentBuilder::new()
            .with_vm_inputs(&[M31::from_u32(101)])
            .with_vm_outputs(&base_outputs)
            .with_timestamp(1000)
            .build();

        // Different output
        let c3 = IOCommitmentBuilder::new()
            .with_vm_inputs(&base_inputs)
            .with_vm_outputs(&[M31::from_u32(201)])
            .with_timestamp(1000)
            .build();

        // Different timestamp
        let c4 = IOCommitmentBuilder::new()
            .with_vm_inputs(&base_inputs)
            .with_vm_outputs(&base_outputs)
            .with_timestamp(1001)
            .build();

        // All commitments should be different
        assert_ne!(c1.commitment, c2.commitment);
        assert_ne!(c1.commitment, c3.commitment);
        assert_ne!(c1.commitment, c4.commitment);
        assert_ne!(c2.commitment, c3.commitment);
    }
}
