//! # Compute Engine
//!
//! This module handles job execution and compute resource management.

pub mod executor;
pub mod containers;
pub mod gpu;
pub mod verification;
pub mod data_executor;
pub mod model_executor;
pub mod job_executor;

pub use executor::ComputeExecutor;
pub use job_executor::{JobExecutor, JobExecutionRequest, JobExecutionResult};
