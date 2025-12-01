//! Security Module
//!
//! Provides TEE attestation and secure GPU proof generation.
//!
//! ## Components
//!
//! - `tee`: TEE hardware attestation (TDX, SEV-SNP)
//! - `gpu_tee`: GPU-accelerated secure proof generation

pub mod tee;
pub mod gpu_tee;

pub use tee::*;
pub use gpu_tee::{
    GpuSecureProver, GpuTeeConfig, SessionKey, EncryptedPayload,
    SecureProofResult, SecureProofMetrics,
};

