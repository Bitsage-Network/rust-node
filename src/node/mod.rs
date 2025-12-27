//! # Node Management
//!
//! This module contains the core node functionality including coordinators and workers.

pub mod coordinator;
pub mod worker;
pub mod health;

pub use coordinator::JobCoordinator;
pub use worker::{Worker, WorkerConfig, WorkerStats, WorkerEvent, HealthStatus}; 