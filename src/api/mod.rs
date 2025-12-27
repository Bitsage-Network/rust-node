//! # REST API Module
//!
//! Provides HTTP/REST API endpoints for the BitSage Network

pub mod job_monitoring;
pub mod job_submission;
pub mod faucet;

pub use job_monitoring::{create_monitoring_router, MonitoringApiState};
pub use job_submission::{create_submission_router, SubmissionApiState};
pub use faucet::{faucet_routes, FaucetApiState};

