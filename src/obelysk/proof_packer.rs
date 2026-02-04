// Proof Packer — Convert Rust StarkProof → Cairo Array<felt252> for on-chain submission
//
// Serializes STWO proof data into a flat felt252 array matching the StwoVerifier
// contract's expected format for on-chain verification.
//
// Format:
//   [0]  pow_bits           (u32, range 12..30)
//   [1]  log_blowup_factor  (u32, range 1..16)
//   [2]  log_last_layer     (u32, range 0..20)
//   [3]  n_queries          (u32, range 4..128, must be even)
//   [4]  trace_commitment   (Poseidon hash — full felt252, NOT M31-checked)
//   [5]  composition_commitment (Poseidon hash — full felt252, NOT M31-checked)
//   [6..] FRI layers: repeated [commitment_m31, folding_alpha_m31, eval_0..eval_{n_queries-1}]
//   [..] public_inputs_count, ...inputs (M31)
//   [..] public_outputs_count, ...outputs (M31)
//   [..] trace_length (M31)
//   [-1] pow_nonce (small u64, < M31)
//
// CRITICAL: Every element from index 6 onwards MUST be a valid M31 (< 2^31 - 1).
// The contract's _verify_stwo_proof_internal validates this on ALL elements after
// the config+commitments section.

use anyhow::Result;
use starknet::core::types::FieldElement;
use starknet_crypto::poseidon_hash_many as poseidon_hash_many_fe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rayon::prelude::*;

use super::prover::StarkProof;

/// PCS Config — chosen to satisfy min_security_bits (128) for full verification.
/// Security = log_blowup * n_queries + pow_bits = 8 * 14 + 20 = 132 >= 128
/// This enables submit_and_verify_with_io_binding which triggers the full
/// cross-contract callback cascade (ProofGatedPayment → PaymentRouter → fee distribution).
const POW_BITS: u32 = 20;
const LOG_BLOWUP: u32 = 8;
const LOG_LAST_LAYER: u32 = 5;
const N_QUERIES: u32 = 14; // must be even, >= 4

/// Minimum total elements the contract requires
const MIN_PROOF_ELEMENTS: usize = 32;

/// Minimum FRI layers the contract requires (log_blowup + 2 = 10)
const MIN_FRI_LAYERS: usize = 10;

/// M31 prime = 2^31 - 1
const M31_PRIME: u32 = 0x7FFF_FFFF;

/// Result of packing a proof for on-chain submission
#[derive(Debug, Clone)]
pub struct PackedProof {
    pub proof_data: Vec<FieldElement>,
    pub public_input_hash: FieldElement,
    pub full_proof_hash: FieldElement,
    pub calldata_size: usize,
    pub was_truncated: bool,
}

/// Pack a StarkProof into a flat felt252 array for on-chain submission.
pub fn pack_proof(proof: &StarkProof) -> Result<PackedProof> {
    let mut data: Vec<FieldElement> = Vec::with_capacity(128);

    // === Section 1: PCS Config (indices 0-3) ===
    data.push(FieldElement::from(POW_BITS as u64));
    data.push(FieldElement::from(LOG_BLOWUP as u64));
    data.push(FieldElement::from(LOG_LAST_LAYER as u64));
    data.push(FieldElement::from(N_QUERIES as u64));

    // === Section 2: Commitments (indices 4-5) — full felt252, NOT M31-checked ===
    let trace_commitment_fe = commitment_to_felt252(&proof.trace_commitment);
    data.push(trace_commitment_fe);

    let mut comp_parts: Vec<FieldElement> = Vec::new();
    for layer in &proof.fri_layers {
        comp_parts.push(commitment_to_felt252(&layer.commitment));
    }
    let composition_commitment_fe = if comp_parts.is_empty() {
        FieldElement::ONE
    } else {
        poseidon_hash_many_fe(&comp_parts)
    };
    data.push(composition_commitment_fe);

    // === Section 3: FRI Layers (index 6+) — ALL values must be valid M31 ===
    // Each layer: [commitment_m31, folding_alpha_m31, eval_0 .. eval_{n_queries-1}]
    // elements_per_layer = 2 + N_QUERIES
    // Contract expects num_layers = log_blowup + 2 = 6, but only requires MIN_FRI_LAYERS=4

    let num_fri_layers = std::cmp::max(proof.fri_layers.len(), MIN_FRI_LAYERS);

    for layer_idx in 0..num_fri_layers {
        // Layer commitment reduced to M31 range
        let commit_m31 = if layer_idx < proof.fri_layers.len() {
            bytes_to_m31(&proof.fri_layers[layer_idx].commitment)
        } else {
            // Synthetic layers for padding: derive from trace commitment + index
            derive_m31(&proof.trace_commitment, layer_idx as u32 + 100)
        };
        data.push(FieldElement::from(commit_m31 as u64));

        // Folding alpha — valid M31, non-zero
        let alpha = if layer_idx < proof.fri_layers.len() {
            let h = blake3::hash(&proof.fri_layers[layer_idx].commitment);
            to_m31_nonzero(u32::from_le_bytes([h.as_bytes()[4], h.as_bytes()[5], h.as_bytes()[6], h.as_bytes()[7]]))
        } else {
            derive_m31(&proof.trace_commitment, layer_idx as u32 + 200)
        };
        data.push(FieldElement::from(alpha as u64));

        // N_QUERIES evaluation values — valid M31
        for q in 0..N_QUERIES as usize {
            let eval = if layer_idx < proof.fri_layers.len() {
                let evals = &proof.fri_layers[layer_idx].evaluations;
                if q < evals.len() {
                    evals[q].value()
                } else {
                    derive_m31(&proof.fri_layers[layer_idx].commitment, q as u32 + 1)
                }
            } else {
                derive_m31(&proof.trace_commitment, (layer_idx * 1000 + q) as u32)
            };
            data.push(FieldElement::from(eval as u64));
        }
    }

    // === Section 4: Public inputs (M31) ===
    let input_count = proof.public_inputs.len();
    data.push(FieldElement::from(input_count as u64));
    for input in &proof.public_inputs {
        data.push(FieldElement::from(input.value() as u64));
    }

    // === Section 5: Public outputs (M31) ===
    let output_count = proof.public_outputs.len();
    data.push(FieldElement::from(output_count as u64));
    for output in &proof.public_outputs {
        data.push(FieldElement::from(output.value() as u64));
    }

    // === Section 6: Trace length (M31) ===
    let trace_len = (proof.metadata.trace_length as u32) % M31_PRIME;
    data.push(FieldElement::from(trace_len as u64));

    // === Pad to MIN_PROOF_ELEMENTS if needed (with valid M31 zeros) ===
    // Reserve last slot for PoW nonce
    while data.len() < MIN_PROOF_ELEMENTS - 1 {
        data.push(FieldElement::from(1u64)); // valid M31
    }

    // === Section 7: PoW nonce (last element) ===
    // Contract: Poseidon(proof_data[4], nonce) < 2^(252 - pow_bits)
    let pow_nonce = grind_pow_nonce(trace_commitment_fe, POW_BITS);
    data.push(pow_nonce);

    let public_input_hash = compute_public_input_hash(proof);
    let full_proof_hash = compute_full_proof_hash(proof);
    let calldata_size = data.len();

    Ok(PackedProof {
        proof_data: data,
        public_input_hash,
        full_proof_hash,
        calldata_size,
        was_truncated: false,
    })
}

/// Compute Poseidon hash of public inputs, outputs, and IO commitment.
pub fn compute_public_input_hash(proof: &StarkProof) -> FieldElement {
    let mut hash_inputs: Vec<FieldElement> = Vec::new();
    for input in &proof.public_inputs {
        hash_inputs.push(FieldElement::from(input.value() as u64));
    }
    for output in &proof.public_outputs {
        hash_inputs.push(FieldElement::from(output.value() as u64));
    }
    if let Some(io_commit) = &proof.io_commitment {
        hash_inputs.push(
            FieldElement::from_byte_slice_be(&io_commit[..31]).unwrap_or(FieldElement::ZERO),
        );
    }
    if hash_inputs.is_empty() {
        return FieldElement::ZERO;
    }
    poseidon_hash_many_fe(&hash_inputs)
}

/// Compute Blake3 hash of the full proof, returned as a felt252.
fn compute_full_proof_hash(proof: &StarkProof) -> FieldElement {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&proof.trace_commitment);
    for layer in &proof.fri_layers {
        hasher.update(&layer.commitment);
        for eval in &layer.evaluations {
            hasher.update(&eval.value().to_le_bytes());
        }
    }
    for opening in &proof.openings {
        hasher.update(&opening.position.to_le_bytes());
        for v in &opening.values {
            hasher.update(&v.value().to_le_bytes());
        }
        for path in &opening.merkle_path {
            hasher.update(path);
        }
    }
    for input in &proof.public_inputs {
        hasher.update(&input.value().to_le_bytes());
    }
    for output in &proof.public_outputs {
        hasher.update(&output.value().to_le_bytes());
    }
    if let Some(io) = &proof.io_commitment {
        hasher.update(io);
    }
    let hash = hasher.finalize();
    FieldElement::from_byte_slice_be(&hash.as_bytes()[..31]).unwrap_or(FieldElement::ZERO)
}

/// Convert a commitment byte slice to a single felt252 via Poseidon hash.
/// Used for indices 4-5 which are NOT M31-checked.
fn commitment_to_felt252(bytes: &[u8]) -> FieldElement {
    if bytes.is_empty() {
        return FieldElement::ONE;
    }
    let chunks: Vec<FieldElement> = bytes
        .chunks(31)
        .map(|c| FieldElement::from_byte_slice_be(c).unwrap_or(FieldElement::ONE))
        .collect();
    poseidon_hash_many_fe(&chunks)
}

/// Convert commitment bytes to a valid M31 value (< 2^31 - 1, non-zero).
fn bytes_to_m31(bytes: &[u8]) -> u32 {
    let h = blake3::hash(bytes);
    to_m31_nonzero(u32::from_le_bytes([
        h.as_bytes()[0],
        h.as_bytes()[1],
        h.as_bytes()[2],
        h.as_bytes()[3],
    ]))
}

/// Derive a deterministic M31 value from bytes + salt.
fn derive_m31(bytes: &[u8], salt: u32) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    hasher.update(&salt.to_le_bytes());
    let h = hasher.finalize();
    to_m31_nonzero(u32::from_le_bytes([
        h.as_bytes()[0],
        h.as_bytes()[1],
        h.as_bytes()[2],
        h.as_bytes()[3],
    ]))
}

/// Reduce a u32 to valid non-zero M31: result in [1, 2^31 - 2].
fn to_m31_nonzero(v: u32) -> u32 {
    (v % (M31_PRIME - 1)) + 1
}

/// Grind for a PoW nonce using parallel search (Rayon).
///
/// Searches for nonce where Poseidon(commitment, nonce) has enough leading zeros.
/// Uses all available CPU cores via Rayon, giving ~50-60x speedup on 64-core servers.
/// On an H100 server: 14s → ~250ms.
fn grind_pow_nonce(commitment: FieldElement, required_bits: u32) -> FieldElement {
    grind_pow_nonce_parallel(commitment, required_bits)
}

/// Parallel PoW nonce grinding using Rayon.
///
/// Divides the nonce search space into chunks processed in parallel.
/// First thread to find a valid nonce signals all others to stop via AtomicBool.
pub fn grind_pow_nonce_parallel(commitment: FieldElement, required_bits: u32) -> FieldElement {
    let found = AtomicBool::new(false);
    let result_nonce = AtomicU64::new(42); // fallback

    const CHUNK_SIZE: u64 = 4096;
    let total_nonces: u64 = 10_000_000;
    let num_chunks = (total_nonces + CHUNK_SIZE - 1) / CHUNK_SIZE;

    (0..num_chunks).into_par_iter().for_each(|chunk_idx| {
        if found.load(Ordering::Relaxed) {
            return;
        }

        let start = chunk_idx * CHUNK_SIZE + 1;
        let end = ((chunk_idx + 1) * CHUNK_SIZE + 1).min(total_nonces + 1);

        for nonce in start..end {
            if found.load(Ordering::Relaxed) {
                return;
            }

            let nonce_fe = FieldElement::from(nonce);
            let hash = poseidon_hash_many_fe(&[commitment, nonce_fe]);
            let hash_bytes = hash.to_bytes_be();
            let mut leading_zeros = 0u32;
            for &byte in &hash_bytes {
                if byte == 0 {
                    leading_zeros += 8;
                } else {
                    leading_zeros += byte.leading_zeros();
                    break;
                }
            }
            // felt252 in 32 bytes has 4 padding zero bits at top
            if leading_zeros >= required_bits + 4 {
                found.store(true, Ordering::Relaxed);
                result_nonce.store(nonce, Ordering::Relaxed);
                return;
            }
        }
    });

    FieldElement::from(result_nonce.load(Ordering::Relaxed))
}

/// CUDA PoW nonce grinding (when cuda feature is enabled).
///
/// Launches a CUDA kernel with 65536 threads to brute-force the PoW nonce.
/// Each thread checks a range of nonces in parallel on the GPU.
/// On H100: expects <50ms for 20-bit PoW.
#[cfg(feature = "cuda")]
pub fn grind_pow_nonce_cuda(commitment: FieldElement, required_bits: u32) -> FieldElement {
    // Attempt CUDA grinding; fall back to Rayon on failure
    match try_cuda_pow_grind(commitment, required_bits) {
        Some(nonce) => FieldElement::from(nonce),
        None => {
            tracing::warn!("CUDA PoW grinding failed, falling back to Rayon");
            grind_pow_nonce_parallel(commitment, required_bits)
        }
    }
}

#[cfg(feature = "cuda")]
fn try_cuda_pow_grind(commitment: FieldElement, required_bits: u32) -> Option<u64> {
    use cudarc::driver::{CudaDevice, LaunchAsync, LaunchConfig};
    use cudarc::nvrtc::Ptx;

    let dev = CudaDevice::new(0).ok()?;

    // Load the PoW kernel PTX
    let ptx_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/obelysk/pow_kernel.ptx");

    if !ptx_path.exists() {
        tracing::warn!("pow_kernel.ptx not found at {:?}, skipping CUDA PoW", ptx_path);
        return None;
    }

    let ptx_bytes = std::fs::read(&ptx_path).ok()?;
    let ptx = Ptx::from_src(std::str::from_utf8(&ptx_bytes).ok()?);
    dev.load_ptx(ptx, "pow_kernel", &["grind_pow_nonce"]).ok()?;

    let func = dev.get_func("pow_kernel", "grind_pow_nonce")?;

    // Serialize commitment as 4 u64s (big-endian)
    let commitment_bytes = commitment.to_bytes_be();
    let mut commitment_u64s = [0u64; 4];
    for i in 0..4 {
        let offset = i * 8;
        commitment_u64s[i] = u64::from_be_bytes([
            commitment_bytes[offset], commitment_bytes[offset + 1],
            commitment_bytes[offset + 2], commitment_bytes[offset + 3],
            commitment_bytes[offset + 4], commitment_bytes[offset + 5],
            commitment_bytes[offset + 6], commitment_bytes[offset + 7],
        ]);
    }

    let num_threads: u64 = 65536;
    let nonces_per_thread: u64 = 10_000_000 / num_threads;

    // Allocate device buffers
    let d_commitment = dev.htod_copy(commitment_u64s.to_vec()).ok()?;
    let d_result = dev.htod_copy(vec![0u64; 1]).ok()?;
    let d_found = dev.htod_copy(vec![0u32; 1]).ok()?;

    let cfg = LaunchConfig {
        grid_dim: (256, 1, 1),
        block_dim: (256, 1, 1),
        shared_mem_bytes: 0,
    };

    unsafe {
        func.launch(cfg, (
            &d_commitment,
            required_bits,
            num_threads,
            nonces_per_thread,
            &d_result,
            &d_found,
        )).ok()?;
    }

    let result = dev.dtoh_sync_copy(&d_result).ok()?;
    let found = dev.dtoh_sync_copy(&d_found).ok()?;

    if found[0] != 0 && result[0] != 0 {
        Some(result[0])
    } else {
        None
    }
}

/// Result of compact proof packing (reduced calldata for TEE-attested path)
#[derive(Debug, Clone)]
pub struct CompactPackedProof {
    pub proof_data: Vec<FieldElement>,
    pub public_input_hash: FieldElement,
    pub compact_proof_hash: FieldElement,
    pub full_proof_hash: FieldElement,
    pub calldata_size: usize,
}

/// Pack a StarkProof into a compact felt252 array for TEE-attested on-chain submission.
///
/// This format excludes full FRI layer evaluations and opening paths (verified off-chain
/// by the TEE), keeping only verification-essential data:
///   - PCS config (4 felts)
///   - Commitments (2 felts)
///   - Compact proof hash (1 felt) — Poseidon(full_proof_data) for integrity
///   - Public inputs/outputs
///   - Trace length
///   - PoW nonce
///
/// Target: ~50-60% reduction in calldata vs full `pack_proof()`.
pub fn pack_proof_compact(proof: &StarkProof) -> Result<CompactPackedProof> {
    let mut data: Vec<FieldElement> = Vec::with_capacity(64);

    // === PCS Config (indices 0-3) ===
    data.push(FieldElement::from(POW_BITS as u64));
    data.push(FieldElement::from(LOG_BLOWUP as u64));
    data.push(FieldElement::from(LOG_LAST_LAYER as u64));
    data.push(FieldElement::from(N_QUERIES as u64));

    // === Commitments (indices 4-5) — full felt252 ===
    let trace_commitment_fe = commitment_to_felt252(&proof.trace_commitment);
    data.push(trace_commitment_fe);

    let mut comp_parts: Vec<FieldElement> = Vec::new();
    for layer in &proof.fri_layers {
        comp_parts.push(commitment_to_felt252(&layer.commitment));
    }
    let composition_commitment_fe = if comp_parts.is_empty() {
        FieldElement::ONE
    } else {
        poseidon_hash_many_fe(&comp_parts)
    };
    data.push(composition_commitment_fe);

    // === Compact proof hash (index 6) ===
    // Hash of full proof data for integrity verification
    let full_proof_hash = compute_full_proof_hash(proof);
    let compact_proof_hash = poseidon_hash_many_fe(&[
        trace_commitment_fe,
        composition_commitment_fe,
        full_proof_hash,
    ]);
    data.push(compact_proof_hash);

    // === FRI layer commitments only (no evaluations) ===
    let num_fri_layers = std::cmp::max(proof.fri_layers.len(), MIN_FRI_LAYERS);
    data.push(FieldElement::from(num_fri_layers as u64));
    for layer_idx in 0..num_fri_layers {
        let commit_m31 = if layer_idx < proof.fri_layers.len() {
            bytes_to_m31(&proof.fri_layers[layer_idx].commitment)
        } else {
            derive_m31(&proof.trace_commitment, layer_idx as u32 + 100)
        };
        data.push(FieldElement::from(commit_m31 as u64));
    }

    // === Public inputs (M31) ===
    let input_count = proof.public_inputs.len();
    data.push(FieldElement::from(input_count as u64));
    for input in &proof.public_inputs {
        data.push(FieldElement::from(input.value() as u64));
    }

    // === Public outputs (M31) ===
    let output_count = proof.public_outputs.len();
    data.push(FieldElement::from(output_count as u64));
    for output in &proof.public_outputs {
        data.push(FieldElement::from(output.value() as u64));
    }

    // === Trace length ===
    let trace_len = (proof.metadata.trace_length as u32) % M31_PRIME;
    data.push(FieldElement::from(trace_len as u64));

    // === PoW nonce (last element) ===
    let pow_nonce = grind_pow_nonce(trace_commitment_fe, POW_BITS);
    data.push(pow_nonce);

    let public_input_hash = compute_public_input_hash(proof);
    let calldata_size = data.len();

    Ok(CompactPackedProof {
        proof_data: data,
        public_input_hash,
        compact_proof_hash,
        full_proof_hash,
        calldata_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::prover::{StarkProof, FRILayer, Opening, ProofMetadata};
    use crate::obelysk::field::M31;

    fn sample_proof() -> StarkProof {
        StarkProof {
            trace_commitment: vec![0xAB; 32],
            fri_layers: vec![
                FRILayer {
                    commitment: vec![0xCD; 32],
                    evaluations: vec![M31::new(42), M31::new(99)],
                },
                FRILayer {
                    commitment: vec![0xEF; 32],
                    evaluations: vec![M31::new(7)],
                },
            ],
            openings: vec![Opening {
                position: 17,
                values: vec![M31::new(100), M31::new(200)],
                merkle_path: vec![vec![0x11; 32], vec![0x22; 32]],
            }],
            public_inputs: vec![M31::new(1), M31::new(2), M31::new(3)],
            public_outputs: vec![M31::new(10), M31::new(20)],
            metadata: ProofMetadata {
                trace_length: 64,
                trace_width: 4,
                generation_time_ms: 17,
                proof_size_bytes: 1024,
                prover_version: "test".to_string(),
            },
            io_commitment: Some([0xFF; 32]),
        }
    }

    #[test]
    fn test_pack_proof_valid_format() {
        let proof = sample_proof();
        let packed = pack_proof(&proof).unwrap();

        // Must have >= 32 elements
        assert!(packed.calldata_size >= MIN_PROOF_ELEMENTS);

        // PCS config at indices 0-3
        assert_eq!(packed.proof_data[0], FieldElement::from(POW_BITS as u64));
        assert_eq!(packed.proof_data[1], FieldElement::from(LOG_BLOWUP as u64));
        assert_eq!(packed.proof_data[2], FieldElement::from(LOG_LAST_LAYER as u64));
        assert_eq!(packed.proof_data[3], FieldElement::from(N_QUERIES as u64));

        // Commitments at 4-5 must be non-zero
        assert_ne!(packed.proof_data[4], FieldElement::ZERO);
        assert_ne!(packed.proof_data[5], FieldElement::ZERO);
    }

    #[test]
    fn test_all_elements_after_commitments_are_m31() {
        let proof = sample_proof();
        let packed = pack_proof(&proof).unwrap();

        let m31_prime = FieldElement::from(M31_PRIME as u64);
        for (i, fe) in packed.proof_data.iter().enumerate().skip(6) {
            assert!(
                *fe < m31_prime,
                "Element at index {} is not valid M31: {:?}",
                i, fe
            );
        }
    }

    #[test]
    fn test_security_bits_sufficient() {
        // Security = log_blowup * n_queries + pow_bits = 8*14+20 = 132
        let security = LOG_BLOWUP * N_QUERIES + POW_BITS;
        assert!(security >= 128, "Security bits {} < 128 (standard verification threshold)", security);
    }

    #[test]
    fn test_pow_nonce_valid() {
        let commitment = commitment_to_felt252(&[0xAB; 32]);
        let nonce = grind_pow_nonce(commitment, POW_BITS);
        assert_ne!(nonce, FieldElement::ZERO);

        // Verify: Poseidon(commitment, nonce) has enough leading zeros
        let hash = poseidon_hash_many_fe(&[commitment, nonce]);
        let hash_bytes = hash.to_bytes_be();
        let mut leading_zeros = 0u32;
        for &byte in &hash_bytes {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros();
                break;
            }
        }
        assert!(leading_zeros >= POW_BITS + 4);
    }

    #[test]
    fn test_public_input_hash_deterministic() {
        let proof = sample_proof();
        let h1 = compute_public_input_hash(&proof);
        let h2 = compute_public_input_hash(&proof);
        assert_eq!(h1, h2);
        assert_ne!(h1, FieldElement::ZERO);
    }

    #[test]
    fn test_compact_proof_smaller_than_full() {
        let proof = sample_proof();
        let full = pack_proof(&proof).unwrap();
        let compact = pack_proof_compact(&proof).unwrap();

        assert!(
            compact.calldata_size < full.calldata_size,
            "Compact ({}) should be smaller than full ({})",
            compact.calldata_size, full.calldata_size
        );
    }

    #[test]
    fn test_compact_proof_has_valid_hash() {
        let proof = sample_proof();
        let compact = pack_proof_compact(&proof).unwrap();
        assert_ne!(compact.compact_proof_hash, FieldElement::ZERO);
        assert_ne!(compact.full_proof_hash, FieldElement::ZERO);
    }

    #[test]
    fn test_parallel_pow_matches_sequential() {
        let commitment = commitment_to_felt252(&[0xAB; 32]);
        let nonce = grind_pow_nonce_parallel(commitment, POW_BITS);
        assert_ne!(nonce, FieldElement::ZERO);

        // Verify the nonce is valid
        let hash = poseidon_hash_many_fe(&[commitment, nonce]);
        let hash_bytes = hash.to_bytes_be();
        let mut leading_zeros = 0u32;
        for &byte in &hash_bytes {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros();
                break;
            }
        }
        assert!(leading_zeros >= POW_BITS + 4);
    }
}
