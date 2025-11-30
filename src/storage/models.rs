//! Database models for Bitsage Network
//!
//! This module contains the database models that correspond to the PostgreSQL schema.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Job record in the database
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: Uuid,
    pub job_id: String,
    pub job_type: String,
    pub status: String,
    pub priority: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    
    // Job parameters and metadata (stored as JSON)
    pub parameters: serde_json::Value,
    pub metadata: serde_json::Value,
    
    // Resource requirements
    pub cpu_cores: Option<i32>,
    pub memory_mb: Option<i32>,
    pub gpu_memory_mb: Option<i32>,
    pub storage_gb: Option<i32>,
    
    // Results and outputs
    pub result: Option<serde_json::Value>,
    pub output_files: Option<Vec<String>>,
    pub error_message: Option<String>,
    
    // Performance metrics
    pub total_tasks: i32,
    pub completed_tasks: i32,
    pub failed_tasks: i32,
    pub processing_time_ms: Option<i64>,
    
    // Parallelization strategy
    pub parallelization_strategy: Option<String>,
    pub chunk_size: Option<i32>,
}

/// Worker record in the database
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WorkerRecord {
    pub id: Uuid,
    pub worker_id: String,
    pub status: String,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    
    // Worker capabilities (stored as JSON)
    pub capabilities: serde_json::Value,
    pub cpu_cores: i32,
    pub memory_mb: i32,
    pub gpu_memory_mb: i32,
    pub storage_gb: i32,
    
    // Network information
    pub ip_address: Option<String>,
    pub port: Option<i32>,
    pub public_key: Option<String>,
    
    // Performance metrics
    pub jobs_completed: i32,
    pub jobs_failed: i32,
    pub total_compute_time_ms: i64,
    pub average_response_time_ms: i32,
    pub reputation_score: rust_decimal::Decimal,
    
    // Worker metadata
    pub version: Option<String>,
    pub os_info: Option<String>,
    pub hardware_info: serde_json::Value,
}

/// Task record in the database
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: Uuid,
    pub task_id: String,
    pub job_id: String,
    pub worker_id: Option<String>,
    
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    
    // Task specifics
    pub task_type: String,
    pub sequence_number: i32,
    pub dependencies: Option<Vec<String>>,
    
    // Task parameters and data (stored as JSON)
    pub parameters: serde_json::Value,
    pub input_data: Option<serde_json::Value>,
    pub output_data: Option<serde_json::Value>,
    
    // Resource usage
    pub cpu_usage_percent: Option<rust_decimal::Decimal>,
    pub memory_usage_mb: Option<i32>,
    pub gpu_usage_percent: Option<rust_decimal::Decimal>,
    pub processing_time_ms: Option<i64>,
    
    // Error handling
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub max_retries: i32,
}

/// System state record in the database
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SystemStateRecord {
    pub id: Uuid,
    pub coordinator_id: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    
    // System metrics
    pub active_jobs: i32,
    pub active_workers: i32,
    pub total_jobs_processed: i32,
    pub total_tasks_processed: i32,
    
    // Configuration (stored as JSON)
    pub configuration: serde_json::Value,
    
    // Performance metrics
    pub average_job_completion_time_ms: i64,
    pub system_load_percent: rust_decimal::Decimal,
}

/// Job history record for analytics
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct JobHistoryRecord {
    pub id: Uuid,
    pub job_id: String,
    pub archived_at: DateTime<Utc>,
    
    // Historical data (stored as JSON)
    pub job_data: serde_json::Value,
    pub performance_metrics: serde_json::Value,
    
    // Indexing for analytics
    pub job_type: String,
    pub completion_time_ms: Option<i64>,
    pub total_tasks: Option<i32>,
    pub worker_count: Option<i32>,
}

/// Input structure for creating a new job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateJobInput {
    pub job_id: String,
    pub job_type: String,
    pub priority: String,
    pub parameters: serde_json::Value,
    pub metadata: serde_json::Value,
    pub cpu_cores: Option<i32>,
    pub memory_mb: Option<i32>,
    pub gpu_memory_mb: Option<i32>,
    pub storage_gb: Option<i32>,
    pub parallelization_strategy: Option<String>,
    pub chunk_size: Option<i32>,
}

/// Input structure for creating a new worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWorkerInput {
    pub worker_id: String,
    pub capabilities: serde_json::Value,
    pub cpu_cores: i32,
    pub memory_mb: i32,
    pub gpu_memory_mb: i32,
    pub storage_gb: i32,
    pub ip_address: Option<String>,
    pub port: Option<i32>,
    pub public_key: Option<String>,
    pub version: Option<String>,
    pub os_info: Option<String>,
    pub hardware_info: serde_json::Value,
}

/// Input structure for creating a new task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTaskInput {
    pub task_id: String,
    pub job_id: String,
    pub task_type: String,
    pub sequence_number: i32,
    pub dependencies: Option<Vec<String>>,
    pub parameters: serde_json::Value,
    pub input_data: Option<serde_json::Value>,
    pub max_retries: Option<i32>,
}

/// Input structure for updating task status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTaskStatusInput {
    pub status: String,
    pub worker_id: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output_data: Option<serde_json::Value>,
    pub cpu_usage_percent: Option<rust_decimal::Decimal>,
    pub memory_usage_mb: Option<i32>,
    pub gpu_usage_percent: Option<rust_decimal::Decimal>,
    pub processing_time_ms: Option<i64>,
    pub error_message: Option<String>,
}

/// Input structure for updating worker status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateWorkerStatusInput {
    pub status: String,
    pub last_heartbeat: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub jobs_completed: Option<i32>,
    pub jobs_failed: Option<i32>,
    pub total_compute_time_ms: Option<i64>,
    pub average_response_time_ms: Option<i32>,
    pub reputation_score: Option<rust_decimal::Decimal>,
}

/// Database query filters
#[derive(Debug, Clone, Default)]
pub struct JobFilter {
    pub status: Option<String>,
    pub job_type: Option<String>,
    pub priority: Option<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkerFilter {
    pub status: Option<String>,
    pub min_cpu_cores: Option<i32>,
    pub min_memory_mb: Option<i32>,
    pub min_gpu_memory_mb: Option<i32>,
    pub min_reputation: Option<rust_decimal::Decimal>,
}

#[derive(Debug, Clone, Default)]
pub struct TaskFilter {
    pub status: Option<String>,
    pub job_id: Option<String>,
    pub worker_id: Option<String>,
    pub task_type: Option<String>,
}

// Re-export commonly used types
pub use rust_decimal::Decimal; 