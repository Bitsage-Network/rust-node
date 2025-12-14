//! Starknet Integration Module
//!
//! This module provides the bridge between Obelysk GPU proofs and Starknet L2 verification.
//! It handles proof serialization to Cairo-compatible format and submission to Starknet.

pub mod proof_serializer;
pub mod starknet_client;
pub mod verifier_contract;

pub use proof_serializer::{CairoSerializedProof, ProofSerializer};
pub use starknet_client::StarknetClient;
pub use verifier_contract::VerifierContract;

