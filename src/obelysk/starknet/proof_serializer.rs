//! Proof Serializer for Starknet On-Chain Verification
//!
//! This module converts STWO proofs from our GPU prover into Cairo-compatible format
//! that can be verified on Starknet L2 using the stwo-cairo-verifier.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     Proof Serialization Pipeline                         │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │   GPU Prover Output                                                      │
//! │        │                                                                 │
//! │        ▼                                                                 │
//! │   ┌─────────────────┐                                                   │
//! │   │ StarkProof<H>   │  Rust native proof structure                      │
//! │   │ - commitments   │                                                   │
//! │   │ - sampled_values│                                                   │
//! │   │ - fri_proof     │                                                   │
//! │   └────────┬────────┘                                                   │
//! │            │                                                             │
//! │            ▼                                                             │
//! │   ┌─────────────────┐                                                   │
//! │   │ ProofSerializer │  Convert to felt252 array                         │
//! │   │ - serialize_m31 │                                                   │
//! │   │ - serialize_qm31│                                                   │
//! │   │ - serialize_hash│                                                   │
//! │   └────────┬────────┘                                                   │
//! │            │                                                             │
//! │            ▼                                                             │
//! │   ┌─────────────────┐                                                   │
//! │   │ CairoSerializedProof │  Cairo-compatible format                     │
//! │   │ - Array<felt252>│                                                   │
//! │   └────────┬────────┘                                                   │
//! │            │                                                             │
//! │            ▼                                                             │
//! │   ┌─────────────────┐                                                   │
//! │   │ Starknet TX     │  Submit to L2                                     │
//! │   └─────────────────┘                                                   │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

/// A felt252 value (Starknet's native field element)
/// The Cairo field is ~252 bits: p = 2^251 + 17 * 2^192 + 1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Felt252(pub [u8; 32]);

impl Felt252 {
    pub const ZERO: Self = Self([0u8; 32]);
    pub const ONE: Self = Self({
        let mut arr = [0u8; 32];
        arr[31] = 1;
        arr
    });

    /// Create from a u32 value
    pub fn from_u32(value: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// Create from a u64 value
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// Create from raw bytes (big-endian)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        arr[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
        Self(arr)
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Felt252 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<u32> for Felt252 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<u64> for Felt252 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

/// Cairo-serialized proof ready for on-chain verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CairoSerializedProof {
    /// The proof data as an array of felt252 elements
    pub data: Vec<Felt252>,
    /// Metadata about the proof
    pub metadata: ProofMetadata,
}

/// Metadata about the serialized proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Original proof size in bytes
    pub original_size_bytes: usize,
    /// Serialized size (number of felt252 elements)
    pub serialized_elements: usize,
    /// Hash of the public inputs
    pub public_input_hash: Felt252,
    /// Configuration used for proof generation
    pub config: ProofConfig,
    /// Timestamp of proof generation
    pub generated_at: u64,
}

/// Proof configuration parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofConfig {
    /// Log of the blowup factor
    pub log_blowup_factor: u32,
    /// Log of the last layer degree bound
    pub log_last_layer_degree_bound: u32,
    /// Number of FRI queries
    pub n_queries: usize,
    /// Proof of work bits
    pub pow_bits: u32,
}

/// Proof serializer that converts STWO proofs to Cairo format
pub struct ProofSerializer {
    /// Buffer for serialized output
    output: Vec<Felt252>,
}

impl ProofSerializer {
    /// Create a new proof serializer
    pub fn new() -> Self {
        Self { output: Vec::new() }
    }

    /// Clear the output buffer
    pub fn clear(&mut self) {
        self.output.clear();
    }

    /// Get the serialized output
    pub fn output(&self) -> &[Felt252] {
        &self.output
    }

    /// Take ownership of the output
    pub fn take_output(&mut self) -> Vec<Felt252> {
        std::mem::take(&mut self.output)
    }

    // =========================================================================
    // Primitive Serialization
    // =========================================================================

    /// Serialize a u32 value
    pub fn serialize_u32(&mut self, value: u32) {
        self.output.push(Felt252::from_u32(value));
    }

    /// Serialize a u64 value
    pub fn serialize_u64(&mut self, value: u64) {
        self.output.push(Felt252::from_u64(value));
    }

    /// Serialize a usize value
    pub fn serialize_usize(&mut self, value: usize) {
        self.output.push(Felt252::from_u64(value as u64));
    }

    // =========================================================================
    // M31 Field Element Serialization
    // =========================================================================

    /// Serialize a Mersenne-31 field element
    /// M31 elements fit in a single felt252
    pub fn serialize_m31(&mut self, value: u32) {
        // M31 values are < 2^31 - 1, so they fit directly in felt252
        self.output.push(Felt252::from_u32(value));
    }

    /// Serialize an array of M31 elements
    pub fn serialize_m31_array(&mut self, values: &[u32]) {
        self.serialize_usize(values.len());
        for &value in values {
            self.serialize_m31(value);
        }
    }

    // =========================================================================
    // QM31 (Secure Field) Serialization
    // =========================================================================

    /// Serialize a QM31 element (4 M31 components)
    /// QM31 = CM31 x CM31 = M31^4
    pub fn serialize_qm31(&mut self, components: [u32; 4]) {
        for component in components {
            self.serialize_m31(component);
        }
    }

    /// Serialize an array of QM31 elements
    pub fn serialize_qm31_array(&mut self, values: &[[u32; 4]]) {
        self.serialize_usize(values.len());
        for value in values {
            self.serialize_qm31(*value);
        }
    }

    // =========================================================================
    // Hash Serialization
    // =========================================================================

    /// Serialize a Blake2s hash as a single felt252
    /// felt252 can hold ~252 bits, so we take the first 31 bytes of the 32-byte hash
    /// Cairo verifier expects single felt252 values for commitments
    pub fn serialize_blake2s_hash(&mut self, hash: &[u8; 32]) {
        // Take first 31 bytes (248 bits) to fit in felt252 (~252 bits)
        // This truncation is safe for commitment comparisons
        let mut bytes = [0u8; 32];
        bytes[1..32].copy_from_slice(&hash[0..31]);
        self.output.push(Felt252(bytes));
    }

    /// Serialize an array of Blake2s hashes (no length prefix for commitments)
    /// Cairo verifier expects commitments directly after config, without length prefix
    pub fn serialize_blake2s_hash_array_no_prefix(&mut self, hashes: &[[u8; 32]]) {
        for hash in hashes {
            self.serialize_blake2s_hash(hash);
        }
    }

    /// Serialize an array of Blake2s hashes with length prefix (for Merkle paths)
    pub fn serialize_blake2s_hash_array(&mut self, hashes: &[[u8; 32]]) {
        self.serialize_usize(hashes.len());
        for hash in hashes {
            self.serialize_blake2s_hash(hash);
        }
    }

    // =========================================================================
    // IO Commitment Serialization
    // =========================================================================

    /// Serialize a 32-byte IO commitment as a single felt252
    ///
    /// The IO commitment binds the proof to specific inputs/outputs.
    /// It is placed at position [4] in the proof array for Cairo verification.
    pub fn serialize_io_commitment(&mut self, commitment: &[u8; 32]) {
        // Convert 32-byte commitment to felt252 (take first 31 bytes to fit)
        let mut bytes = [0u8; 32];
        bytes[1..32].copy_from_slice(&commitment[0..31]);
        self.output.push(Felt252(bytes));
    }

    /// Serialize IO commitment from optional value
    ///
    /// If commitment is None, serializes zero (no binding).
    pub fn serialize_io_commitment_optional(&mut self, commitment: Option<&[u8; 32]>) {
        match commitment {
            Some(c) => self.serialize_io_commitment(c),
            None => self.output.push(Felt252::ZERO),
        }
    }

    // =========================================================================
    // FRI Configuration Serialization
    // =========================================================================

    /// Serialize FRI configuration
    pub fn serialize_fri_config(&mut self, config: &FriConfigData) {
        self.serialize_u32(config.log_blowup_factor);
        self.serialize_u32(config.log_last_layer_degree_bound);
        self.serialize_usize(config.n_queries);
    }

    /// Serialize PCS configuration
    pub fn serialize_pcs_config(&mut self, config: &PcsConfigData) {
        self.serialize_u32(config.pow_bits);
        self.serialize_fri_config(&config.fri_config);
    }

    // =========================================================================
    // Merkle Decommitment Serialization
    // =========================================================================

    /// Serialize a Merkle decommitment
    pub fn serialize_merkle_decommitment(&mut self, decommitment: &MerkleDecommitmentData) {
        // Hash witness (authentication path)
        self.serialize_blake2s_hash_array(&decommitment.hash_witness);
        // Column witness (leaf values)
        self.serialize_m31_array(&decommitment.column_witness);
    }

    /// Serialize an array of Merkle decommitments
    pub fn serialize_merkle_decommitment_array(&mut self, decommitments: &[MerkleDecommitmentData]) {
        self.serialize_usize(decommitments.len());
        for decommitment in decommitments {
            self.serialize_merkle_decommitment(decommitment);
        }
    }

    // =========================================================================
    // FRI Proof Serialization
    // =========================================================================

    /// Serialize a FRI layer proof
    pub fn serialize_fri_layer_proof(&mut self, layer: &FriLayerProofData) {
        // FRI witness values
        self.serialize_qm31_array(&layer.fri_witness);
        // Merkle decommitment
        self.serialize_merkle_decommitment(&layer.decommitment);
        // Commitment (Merkle root)
        self.serialize_blake2s_hash(&layer.commitment);
    }

    /// Serialize the complete FRI proof
    pub fn serialize_fri_proof(&mut self, fri_proof: &FriProofData) {
        // First layer
        self.serialize_fri_layer_proof(&fri_proof.first_layer);
        
        // Inner layers
        self.serialize_usize(fri_proof.inner_layers.len());
        for layer in &fri_proof.inner_layers {
            self.serialize_fri_layer_proof(layer);
        }
        
        // Last layer polynomial coefficients
        self.serialize_qm31_array(&fri_proof.last_layer_poly);
        self.serialize_u32(fri_proof.last_layer_log_size);
    }

    // =========================================================================
    // Complete Proof Serialization
    // =========================================================================

    /// Serialize the complete commitment scheme proof
    pub fn serialize_commitment_scheme_proof(&mut self, proof: &CommitmentSchemeProofData) {
        // Configuration
        self.serialize_pcs_config(&proof.config);

        // Commitments (Merkle roots for each tree) - NO LENGTH PREFIX
        // Cairo verifier expects: proof_data[4] = trace_commitment, proof_data[5] = composition_commitment
        self.serialize_blake2s_hash_array_no_prefix(&proof.commitments);
        
        // Sampled values (OODS evaluations)
        self.serialize_sampled_values(&proof.sampled_values);
        
        // Merkle decommitments
        self.serialize_merkle_decommitment_array(&proof.decommitments);
        
        // Queried values
        self.serialize_queried_values(&proof.queried_values);

        // FRI proof
        self.serialize_fri_proof(&proof.fri_proof);

        // Proof of work nonce - MUST BE LAST
        // Cairo verifier expects PoW nonce at proof_data[proof_len - 1]
        self.serialize_u64(proof.proof_of_work);
    }

    /// Serialize sampled values (nested structure)
    fn serialize_sampled_values(&mut self, sampled_values: &SampledValuesData) {
        // Tree count
        self.serialize_usize(sampled_values.trees.len());
        
        for tree in &sampled_values.trees {
            // Column count
            self.serialize_usize(tree.columns.len());
            
            for column in &tree.columns {
                // Sample count
                self.serialize_usize(column.samples.len());
                
                for sample in &column.samples {
                    self.serialize_qm31(*sample);
                }
            }
        }
    }

    /// Serialize queried values
    fn serialize_queried_values(&mut self, queried_values: &[Vec<u32>]) {
        self.serialize_usize(queried_values.len());
        for tree_values in queried_values {
            self.serialize_m31_array(tree_values);
        }
    }

    /// Serialize a complete STARK proof
    pub fn serialize_stark_proof(&mut self, proof: &StarkProofData) -> CairoSerializedProof {
        self.clear();
        self.serialize_commitment_scheme_proof(&proof.commitment_scheme_proof);

        let data = self.take_output();
        let serialized_elements = data.len();

        CairoSerializedProof {
            data,
            metadata: ProofMetadata {
                original_size_bytes: proof.original_size_bytes,
                serialized_elements,
                public_input_hash: proof.public_input_hash,
                config: ProofConfig {
                    log_blowup_factor: proof.commitment_scheme_proof.config.fri_config.log_blowup_factor,
                    log_last_layer_degree_bound: proof.commitment_scheme_proof.config.fri_config.log_last_layer_degree_bound,
                    n_queries: proof.commitment_scheme_proof.config.fri_config.n_queries,
                    pow_bits: proof.commitment_scheme_proof.config.pow_bits,
                },
                generated_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        }
    }

    /// Serialize a STARK proof with IO commitment binding
    ///
    /// This version embeds the IO commitment at position [4] in the proof array,
    /// which is verified on-chain by the Cairo verifier.
    ///
    /// # Cairo Proof Format with IO Binding:
    /// ```text
    /// [0-3]:   PCS Config (pow_bits, blowup, last_layer, n_queries)
    /// [4]:     IO Commitment (CRITICAL: binds proof to inputs/outputs)
    /// [5]:     Trace Commitment
    /// [6]:     Composition Commitment
    /// [7+]:    FRI Layers, Decommitments, etc.
    /// [last]:  PoW Nonce
    /// ```
    pub fn serialize_proof_with_io_binding(
        &mut self,
        proof: &StarkProofData,
        io_commitment: &[u8; 32],
    ) -> CairoSerializedProof {
        self.clear();

        // 1. Serialize PCS config first [0-3]
        self.serialize_pcs_config(&proof.commitment_scheme_proof.config);

        // 2. Serialize IO commitment at position [4]
        // This is the CRITICAL binding that prevents proof reuse
        self.serialize_io_commitment(io_commitment);

        // 3. Serialize commitments (trace at [5], composition at [6])
        self.serialize_blake2s_hash_array_no_prefix(&proof.commitment_scheme_proof.commitments);

        // 4. Serialize sampled values
        self.serialize_sampled_values(&proof.commitment_scheme_proof.sampled_values);

        // 5. Serialize Merkle decommitments
        self.serialize_merkle_decommitment_array(&proof.commitment_scheme_proof.decommitments);

        // 6. Serialize queried values
        self.serialize_queried_values(&proof.commitment_scheme_proof.queried_values);

        // 7. Serialize FRI proof
        self.serialize_fri_proof(&proof.commitment_scheme_proof.fri_proof);

        // 8. Serialize PoW nonce (MUST BE LAST)
        self.serialize_u64(proof.commitment_scheme_proof.proof_of_work);

        let data = self.take_output();
        let serialized_elements = data.len();

        CairoSerializedProof {
            data,
            metadata: ProofMetadata {
                original_size_bytes: proof.original_size_bytes,
                serialized_elements,
                public_input_hash: proof.public_input_hash,
                config: ProofConfig {
                    log_blowup_factor: proof.commitment_scheme_proof.config.fri_config.log_blowup_factor,
                    log_last_layer_degree_bound: proof.commitment_scheme_proof.config.fri_config.log_last_layer_degree_bound,
                    n_queries: proof.commitment_scheme_proof.config.fri_config.n_queries,
                    pow_bits: proof.commitment_scheme_proof.config.pow_bits,
                },
                generated_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        }
    }
}

impl Default for ProofSerializer {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Data Structures for Proof Conversion
// =============================================================================

/// FRI configuration data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriConfigData {
    pub log_blowup_factor: u32,
    pub log_last_layer_degree_bound: u32,
    pub n_queries: usize,
}

/// PCS configuration data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcsConfigData {
    pub pow_bits: u32,
    pub fri_config: FriConfigData,
}

/// Merkle decommitment data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleDecommitmentData {
    pub hash_witness: Vec<[u8; 32]>,
    pub column_witness: Vec<u32>,
}

/// FRI layer proof data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriLayerProofData {
    pub fri_witness: Vec<[u32; 4]>,
    pub decommitment: MerkleDecommitmentData,
    pub commitment: [u8; 32],
}

/// Complete FRI proof data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriProofData {
    pub first_layer: FriLayerProofData,
    pub inner_layers: Vec<FriLayerProofData>,
    pub last_layer_poly: Vec<[u32; 4]>,
    pub last_layer_log_size: u32,
}

/// Column samples data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColumnSamplesData {
    pub samples: Vec<[u32; 4]>,
}

/// Tree samples data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeSamplesData {
    pub columns: Vec<ColumnSamplesData>,
}

/// Sampled values data (nested structure)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SampledValuesData {
    pub trees: Vec<TreeSamplesData>,
}

/// Complete commitment scheme proof data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentSchemeProofData {
    pub config: PcsConfigData,
    pub commitments: Vec<[u8; 32]>,
    pub sampled_values: SampledValuesData,
    pub decommitments: Vec<MerkleDecommitmentData>,
    pub queried_values: Vec<Vec<u32>>,
    pub proof_of_work: u64,
    pub fri_proof: FriProofData,
}

/// Complete STARK proof data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProofData {
    pub commitment_scheme_proof: CommitmentSchemeProofData,
    pub public_input_hash: Felt252,
    pub original_size_bytes: usize,
}

// =============================================================================
// Conversion from STWO native types
// =============================================================================

/// Trait for converting STWO types to our data structures
pub trait FromStwo<T> {
    fn from_stwo(value: &T) -> Self;
}

/// Convert from stwo_prover M31 to u32
pub fn m31_to_u32(m31: &stwo_prover::core::fields::m31::BaseField) -> u32 {
    m31.0
}

/// Convert from stwo_prover QM31 to [u32; 4]
pub fn qm31_to_array(qm31: &stwo_prover::core::fields::qm31::SecureField) -> [u32; 4] {
    let arr = qm31.to_m31_array();
    [arr[0].0, arr[1].0, arr[2].0, arr[3].0]
}

/// Convert from Blake2sHash to [u8; 32]
pub fn blake2s_hash_to_bytes(hash: &stwo_prover::core::vcs::blake2_hash::Blake2sHash) -> [u8; 32] {
    hash.0
}

// =============================================================================
// JSON Export for Cairo
// =============================================================================

impl CairoSerializedProof {
    /// Export to JSON format suitable for Cairo serde
    pub fn to_cairo_json(&self) -> String {
        // Cairo expects an array of decimal strings
        let felt_strings: Vec<String> = self.data.iter()
            .map(|f| {
                // Convert bytes to big integer string
                let value = num_bigint::BigUint::from_bytes_be(&f.0);
                value.to_string()
            })
            .collect();
        
        serde_json::to_string_pretty(&felt_strings).unwrap()
    }

    /// Export to hex format
    pub fn to_hex_array(&self) -> Vec<String> {
        self.data.iter().map(|f| f.to_hex()).collect()
    }

    /// Get estimated gas cost for on-chain verification
    pub fn estimate_gas_cost(&self) -> u64 {
        // Rough estimate: ~500 gas per felt252 for calldata
        // Plus ~100k base cost for verification logic
        let calldata_gas = self.data.len() as u64 * 500;
        let base_gas = 100_000;
        calldata_gas + base_gas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt252_from_u32() {
        let felt = Felt252::from_u32(42);
        assert_eq!(felt.0[31], 42);
        assert_eq!(felt.0[30], 0);
    }

    #[test]
    fn test_felt252_from_u64() {
        let felt = Felt252::from_u64(0x123456789ABCDEF0);
        let expected = 0x123456789ABCDEF0u64.to_be_bytes();
        assert_eq!(&felt.0[24..32], &expected);
    }

    #[test]
    fn test_serialize_m31() {
        let mut serializer = ProofSerializer::new();
        serializer.serialize_m31(0x7FFFFFFF); // Max M31 value
        assert_eq!(serializer.output().len(), 1);
        assert_eq!(serializer.output()[0], Felt252::from_u32(0x7FFFFFFF));
    }

    #[test]
    fn test_serialize_qm31() {
        let mut serializer = ProofSerializer::new();
        serializer.serialize_qm31([1, 2, 3, 4]);
        assert_eq!(serializer.output().len(), 4);
    }

    #[test]
    fn test_serialize_blake2s_hash() {
        let mut serializer = ProofSerializer::new();
        let hash = [0u8; 32];
        serializer.serialize_blake2s_hash(&hash);
        // Blake2s hash is now serialized as a single felt252
        assert_eq!(serializer.output().len(), 1);
    }

    #[test]
    fn test_serialize_blake2s_hash_truncation() {
        // Verify that first 31 bytes are preserved
        let mut hash = [0u8; 32];
        for i in 0..32 {
            hash[i] = (i + 1) as u8;
        }
        let mut serializer = ProofSerializer::new();
        serializer.serialize_blake2s_hash(&hash);
        let felt = &serializer.output()[0];
        // First byte should be 0 (padding), bytes 1-31 should be hash[0-30]
        assert_eq!(felt.0[0], 0);
        assert_eq!(felt.0[1], 1);  // hash[0]
        assert_eq!(felt.0[31], 31); // hash[30]
    }

    #[test]
    fn test_serialize_m31_array() {
        let mut serializer = ProofSerializer::new();
        serializer.serialize_m31_array(&[1, 2, 3]);
        // 1 for length + 3 for values
        assert_eq!(serializer.output().len(), 4);
    }

    /// Integration test: Verify serialized proof format matches Cairo verifier expectations
    /// Cairo stwo_verifier.cairo expects:
    /// - [0-3]: PCS config (pow_bits, log_blowup_factor, log_last_layer_degree_bound, n_queries)
    /// - [4]: trace_commitment (single felt252)
    /// - [5]: composition_commitment (single felt252)
    /// - [...]: sampled values, decommitments, queried values, FRI proof
    /// - [last]: PoW nonce
    #[test]
    fn test_cairo_proof_format_compatibility() {
        // Create minimal valid proof data
        let trace_commit = [0xABu8; 32];
        let comp_commit = [0xCDu8; 32];

        let proof = CommitmentSchemeProofData {
            config: PcsConfigData {
                pow_bits: 16,
                fri_config: FriConfigData {
                    log_blowup_factor: 4,
                    log_last_layer_degree_bound: 2,
                    n_queries: 20,
                },
            },
            commitments: vec![trace_commit, comp_commit],
            sampled_values: SampledValuesData { trees: vec![] },
            decommitments: vec![],
            queried_values: vec![],
            proof_of_work: 0x123456789ABCDEF0,
            fri_proof: FriProofData {
                first_layer: FriLayerProofData {
                    fri_witness: vec![],
                    decommitment: MerkleDecommitmentData {
                        hash_witness: vec![],
                        column_witness: vec![],
                    },
                    commitment: [0u8; 32],
                },
                inner_layers: vec![],
                last_layer_poly: vec![],
                last_layer_log_size: 0,
            },
        };

        let mut serializer = ProofSerializer::new();
        serializer.serialize_commitment_scheme_proof(&proof);
        let output = serializer.output();

        // Verify Cairo-expected format:
        // [0] = pow_bits
        assert_eq!(output[0], Felt252::from_u32(16));
        // [1] = log_blowup_factor
        assert_eq!(output[1], Felt252::from_u32(4));
        // [2] = log_last_layer_degree_bound
        assert_eq!(output[2], Felt252::from_u32(2));
        // [3] = n_queries
        assert_eq!(output[3], Felt252::from_u64(20));

        // [4] = trace_commitment (single felt252, not 8 u32s)
        // Verify it's a single element (Blake2s hash truncated to felt252)
        let trace_felt = &output[4];
        assert_eq!(trace_felt.0[1], 0xAB); // First byte of hash at position 1

        // [5] = composition_commitment
        let comp_felt = &output[5];
        assert_eq!(comp_felt.0[1], 0xCD);

        // PoW nonce should be LAST element
        let last_idx = output.len() - 1;
        let pow_felt = &output[last_idx];
        assert_eq!(*pow_felt, Felt252::from_u64(0x123456789ABCDEF0));

        println!("Cairo format verification passed!");
        println!("  - PCS config at indices [0-3]: ✓");
        println!("  - Trace commitment at [4]: ✓");
        println!("  - Composition commitment at [5]: ✓");
        println!("  - PoW nonce at [{}] (last): ✓", last_idx);
    }
}

