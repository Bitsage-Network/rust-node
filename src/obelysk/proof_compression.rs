//! Proof Compression for Bitsage Network
//!
//! Compresses ZK proofs for efficient on-chain submission.
//! Supports multiple compression algorithms with automatic selection.
//!
//! # Compression Ratios
//!
//! | Algorithm | Ratio | Speed  | Use Case              |
//! |-----------|-------|--------|------------------------|
//! | Zstd      | ~60%  | Medium | On-chain submission    |
//! | LZ4       | ~75%  | Fast   | P2P transmission       |
//! | Snappy    | ~80%  | Fastest| Real-time streaming    |
//!
//! # Target: < 256KB compressed proof for on-chain verification

use anyhow::{Result, anyhow, Context};
use serde::{Serialize, Deserialize};
use std::io::{Read, Write};

/// Maximum proof size for on-chain submission (256KB)
pub const MAX_ONCHAIN_PROOF_SIZE: usize = 256 * 1024;

/// Maximum uncompressed proof size (4MB)
pub const MAX_UNCOMPRESSED_PROOF_SIZE: usize = 4 * 1024 * 1024;

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// Zstandard - best compression ratio, good for on-chain
    Zstd,
    /// LZ4 - fast compression, good for P2P
    Lz4,
    /// Snappy - fastest compression, good for streaming
    Snappy,
    /// No compression
    None,
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        CompressionAlgorithm::Zstd
    }
}

/// Compressed proof with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedProof {
    /// Compressed proof data
    pub data: Vec<u8>,

    /// Original uncompressed size
    pub original_size: usize,

    /// Compression algorithm used
    pub algorithm: CompressionAlgorithm,

    /// Blake3 hash of original proof
    pub proof_hash: [u8; 32],

    /// Blake3 hash of compressed data (for integrity)
    pub compressed_hash: [u8; 32],

    /// Compression ratio (compressed/original)
    pub compression_ratio: f64,
}

impl CompressedProof {
    /// Check if proof is valid for on-chain submission
    pub fn is_valid_for_onchain(&self) -> bool {
        self.data.len() <= MAX_ONCHAIN_PROOF_SIZE
    }

    /// Verify integrity of compressed data
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = blake3::hash(&self.data);
        computed_hash.as_bytes() == &self.compressed_hash
    }

    /// Get compressed size in bytes
    pub fn compressed_size(&self) -> usize {
        self.data.len()
    }
}

/// Proof compressor with multiple algorithm support
pub struct ProofCompressor;

impl ProofCompressor {
    /// Compress proof data with the specified algorithm
    pub fn compress(data: &[u8], algorithm: CompressionAlgorithm) -> Result<CompressedProof> {
        if data.len() > MAX_UNCOMPRESSED_PROOF_SIZE {
            return Err(anyhow!(
                "Proof too large: {} bytes (max {})",
                data.len(),
                MAX_UNCOMPRESSED_PROOF_SIZE
            ));
        }

        // Hash original proof
        let proof_hash = blake3::hash(data);
        let proof_hash_bytes: [u8; 32] = *proof_hash.as_bytes();

        // Compress based on algorithm
        let compressed_data = match algorithm {
            CompressionAlgorithm::Zstd => Self::compress_zstd(data)?,
            CompressionAlgorithm::Lz4 => Self::compress_lz4(data)?,
            CompressionAlgorithm::Snappy => Self::compress_snappy(data)?,
            CompressionAlgorithm::None => data.to_vec(),
        };

        // Hash compressed data
        let compressed_hash = blake3::hash(&compressed_data);
        let compressed_hash_bytes: [u8; 32] = *compressed_hash.as_bytes();

        // Calculate compression ratio
        let compression_ratio = compressed_data.len() as f64 / data.len() as f64;

        Ok(CompressedProof {
            data: compressed_data,
            original_size: data.len(),
            algorithm,
            proof_hash: proof_hash_bytes,
            compressed_hash: compressed_hash_bytes,
            compression_ratio,
        })
    }

    /// Decompress proof data
    pub fn decompress(compressed: &CompressedProof) -> Result<Vec<u8>> {
        // Verify integrity first
        if !compressed.verify_integrity() {
            return Err(anyhow!("Compressed proof integrity check failed"));
        }

        let data = match compressed.algorithm {
            CompressionAlgorithm::Zstd => Self::decompress_zstd(&compressed.data)?,
            CompressionAlgorithm::Lz4 => Self::decompress_lz4(&compressed.data)?,
            CompressionAlgorithm::Snappy => Self::decompress_snappy(&compressed.data)?,
            CompressionAlgorithm::None => compressed.data.clone(),
        };

        // Verify original hash
        let computed_hash = blake3::hash(&data);
        if computed_hash.as_bytes() != &compressed.proof_hash {
            return Err(anyhow!("Decompressed proof hash mismatch"));
        }

        Ok(data)
    }

    /// Auto-select best algorithm based on proof size and target
    pub fn auto_compress(data: &[u8], target_size: Option<usize>) -> Result<CompressedProof> {
        let target = target_size.unwrap_or(MAX_ONCHAIN_PROOF_SIZE);

        // Try Zstd first (best ratio)
        let zstd_result = Self::compress(data, CompressionAlgorithm::Zstd)?;
        if zstd_result.compressed_size() <= target {
            return Ok(zstd_result);
        }

        // Try higher Zstd compression level
        let zstd_high = Self::compress_zstd_high(data)?;
        let zstd_high_hash = blake3::hash(&zstd_high);
        if zstd_high.len() <= target {
            return Ok(CompressedProof {
                data: zstd_high.clone(),
                original_size: data.len(),
                algorithm: CompressionAlgorithm::Zstd,
                proof_hash: *blake3::hash(data).as_bytes(),
                compressed_hash: *zstd_high_hash.as_bytes(),
                compression_ratio: zstd_high.len() as f64 / data.len() as f64,
            });
        }

        Err(anyhow!(
            "Cannot compress proof to target size: {} (best: {} bytes)",
            target,
            zstd_high.len()
        ))
    }

    // =========================================================================
    // Zstd Compression
    // =========================================================================

    fn compress_zstd(data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = zstd::Encoder::new(Vec::new(), 3)?; // Level 3 (default)
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn compress_zstd_high(data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = zstd::Encoder::new(Vec::new(), 19)?; // Level 19 (high)
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = zstd::Decoder::new(data)?;
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    // =========================================================================
    // LZ4 Compression
    // =========================================================================

    fn compress_lz4(data: &[u8]) -> Result<Vec<u8>> {
        Ok(lz4_flex::compress_prepend_size(data))
    }

    fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| anyhow!("LZ4 decompression failed: {}", e))
    }

    // =========================================================================
    // Snappy Compression
    // =========================================================================

    fn compress_snappy(data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = snap::raw::Encoder::new();
        Ok(encoder.compress_vec(data)?)
    }

    fn decompress_snappy(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = snap::raw::Decoder::new();
        Ok(decoder.decompress_vec(data)?)
    }
}

/// Compute Blake3 hash of proof for on-chain commitment
pub fn compute_proof_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute proof commitment for on-chain verification
/// Uses Blake3 with domain separator
pub fn compute_proof_commitment(
    proof_hash: &[u8; 32],
    job_id: u128,
    worker_address: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"BITSAGE_PROOF_COMMITMENT_V1");
    hasher.update(proof_hash);
    hasher.update(&job_id.to_le_bytes());
    hasher.update(worker_address.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zstd_compression() {
        let data = vec![0u8; 10000]; // Compressible data
        let compressed = ProofCompressor::compress(&data, CompressionAlgorithm::Zstd).unwrap();

        assert!(compressed.compression_ratio < 0.1); // Should compress very well
        assert!(compressed.verify_integrity());

        let decompressed = ProofCompressor::decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_lz4_compression() {
        let data = b"Hello, World! ".repeat(1000);
        let compressed = ProofCompressor::compress(&data, CompressionAlgorithm::Lz4).unwrap();

        assert!(compressed.compression_ratio < 0.5);

        let decompressed = ProofCompressor::decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_snappy_compression() {
        let data = vec![42u8; 5000];
        let compressed = ProofCompressor::compress(&data, CompressionAlgorithm::Snappy).unwrap();

        let decompressed = ProofCompressor::decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_no_compression() {
        let data = b"Test data that won't be compressed".to_vec();
        let compressed = ProofCompressor::compress(&data, CompressionAlgorithm::None).unwrap();

        assert_eq!(data, compressed.data);
        assert_eq!(compressed.compression_ratio, 1.0);
    }

    #[test]
    fn test_proof_hash() {
        let data = b"proof data";
        let hash = compute_proof_hash(data);

        // Should be deterministic
        assert_eq!(hash, compute_proof_hash(data));
    }

    #[test]
    fn test_proof_commitment() {
        let proof_hash = [0u8; 32];
        let job_id = 12345u128;
        let worker = "0x1234";

        let commitment = compute_proof_commitment(&proof_hash, job_id, worker);

        // Should be deterministic
        assert_eq!(commitment, compute_proof_commitment(&proof_hash, job_id, worker));

        // Different inputs should give different commitments
        let commitment2 = compute_proof_commitment(&proof_hash, job_id + 1, worker);
        assert_ne!(commitment, commitment2);
    }

    #[test]
    fn test_integrity_check() {
        let data = vec![1u8; 1000];
        let mut compressed = ProofCompressor::compress(&data, CompressionAlgorithm::Zstd).unwrap();

        // Should pass integrity check
        assert!(compressed.verify_integrity());

        // Corrupt the data
        if !compressed.data.is_empty() {
            compressed.data[0] ^= 0xFF;
        }

        // Should fail integrity check
        assert!(!compressed.verify_integrity());
    }
}
