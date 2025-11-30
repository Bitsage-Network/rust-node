//! # Bitsage Network Worker/Coordinator
//!
//! This library provides the core functionality for the Bitsage Network distributed compute system.
//! It includes both worker nodes that execute compute tasks and coordinator nodes that manage
//! job distribution and result assembly.

pub mod types;
pub mod node;
pub mod compute;
pub mod network;
pub mod blockchain;
pub mod storage;
pub mod utils;
pub mod ai;
pub mod coordinator;
// TODO: coordinator_main is now a separate binary
// pub mod coordinator_main;

pub mod ingest;
pub mod security;
pub mod cloud;
pub mod api;
pub mod obelysk;  // Obelysk Protocol: Native Stwo integration for zkML

// Re-export commonly used types
pub use types::{
    JobId, TaskId, WorkerId, NetworkAddress, StarknetAddress, BitsageAmount,
    ResourceRequirements, Priority, BitsageError, BitsageResult,
};

// Re-export main coordinator functionality
pub use node::coordinator::{
    JobCoordinator, JobType, JobRequest, JobResult, JobStatus,
    Task, TaskStatus, TaskResult, WorkerInfo, WorkerCapabilities,
    ParallelizationStrategy,
};

// Re-export enhanced coordinator functionality
pub use coordinator::{
    EnhancedCoordinator, CoordinatorStatus,
};
pub use coordinator::config::CoordinatorConfig;
pub use coordinator::kafka::KafkaCoordinator;
pub use coordinator::network_coordinator::NetworkCoordinatorService;
pub use coordinator::job_processor::JobProcessor;

// Re-export worker functionality
pub use node::worker::Worker;

// Re-export compute engine
pub use compute::executor::ComputeExecutor;

// Re-export networking
pub use network::p2p::NetworkClient;

// Re-export blockchain integration
pub use blockchain::client::StarknetClient;

// Re-export storage
pub use storage::database_simple::SimpleDatabase;

// Re-export Obelysk (zkML with Stwo)
pub use obelysk::{
    ObelyskVM, OpCode, ExecutionTrace,
    ObelyskProver, ProverConfig, StarkProof, LogLevel,
    M31, Matrix,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Initialize the Bitsage Network library
pub fn init() -> BitsageResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Initialize other components as needed
    Ok(())
} 