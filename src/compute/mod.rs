//! # Compute Engine
//!
//! This module handles job execution and compute resource management.
//!
//! ## Obelysk Integration
//!
//! The `obelysk_executor` module provides GPU-accelerated ZK proof generation
//! for compute jobs. This enables verifiable computation with 50-174x speedup
//! over CPU-based proving.

pub mod executor;
pub mod containers;
pub mod gpu;
pub mod verification;
pub mod data_executor;
pub mod model_executor;
pub mod job_executor;
pub mod obelysk_executor;

pub use executor::ComputeExecutor;
pub use job_executor::{JobExecutor, JobExecutionRequest, JobExecutionResult};
pub use obelysk_executor::{
    ObelyskExecutor, ObelyskExecutorConfig, ObelyskJobResult, 
    ObelyskJobStatus, ExecutionMetrics, TeeAttestation,
    BatchObelyskExecutor,
};
