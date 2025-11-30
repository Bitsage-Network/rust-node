//! # Blockchain Integration
//!
//! This module handles integration with Starknet blockchain.

pub mod client;
pub mod contracts;
pub mod events;
pub mod types;
pub mod worker_bridge;

pub use client::StarknetClient;
pub use contracts::JobManagerContract;
pub use worker_bridge::{WorkerBridge, OnChainJob, hash_execution_result, hash_matrix_result};
pub use types::*; 