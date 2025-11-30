//! # Simple Database Layer (No Macros)
//!
//! This module provides a simplified database implementation that doesn't use sqlx macros
//! for initial testing and development.

use crate::node::coordinator::{JobState, WorkerInfo, TaskStatus};
use crate::storage::models::*;
use crate::blockchain::events::CiroEvent;
use anyhow::{Result, Context};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use tracing::info;

/// Simple database interface for Bitsage Network
#[derive(Debug)]
pub struct SimpleDatabase {
    pool: PgPool,
}

impl SimpleDatabase {
    /// Create a new database instance with connection pool
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url)
            .await
            .context("Failed to connect to PostgreSQL database")?;
        
        info!("Successfully connected to PostgreSQL database");
        Ok(Self { pool })
    }

    /// Initialize minimal database schema required for the indexer (events table only)
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing database schema...");

        // Ensure UUID extension exists (safe if missing; no-op otherwise)
        sqlx::query(r#"CREATE EXTENSION IF NOT EXISTS "uuid-ossp";"#)
            .execute(&self.pool)
            .await
            .context("Failed to ensure uuid-ossp extension")?;

        // Create only the events table needed by the indexer
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                contract_address VARCHAR(66) NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                block_number BIGINT NOT NULL,
                timestamp BIGINT NOT NULL,
                data JSONB NOT NULL DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create events table")?;

        // Indexes to speed up queries
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_events_contract_address ON events (contract_address);",
            "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);",
            "CREATE INDEX IF NOT EXISTS idx_events_block_number ON events (block_number);",
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at);",
        ] {
            sqlx::query(stmt)
                .execute(&self.pool)
                .await
                .with_context(|| format!("Failed to create index with statement: {}", stmt))?;
        }

        info!("Database schema initialized successfully");
        Ok(())
    }

    /// Health check for database connection
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("Database health check failed")?;
        Ok(())
    }

    /// Store job state in the database (simplified)
    pub async fn store_job(&self, job_state: &JobState) -> Result<()> {
        let job_id = job_state.job_id.to_string();
        let job_type = format!("{:?}", job_state.request.job_type);
        let priority = job_state.request.priority.to_string();
        let status = "pending";
        let parameters = serde_json::to_value(&job_state.request.job_type)?;
        let metadata = serde_json::json!({
            "max_cost": job_state.request.max_cost,
            "deadline": job_state.request.deadline,
            "client_address": job_state.request.client_address,
            "callback_url": job_state.request.callback_url
        });

        sqlx::query(
            r#"
            INSERT INTO jobs (job_id, job_type, status, priority, parameters, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&job_id)
        .bind(&job_type)
        .bind(status)
        .bind(&priority)
        .bind(&parameters)
        .bind(&metadata)
        .execute(&self.pool)
        .await
        .context("Failed to store job")?;

        info!("Stored job {} in database", job_id);
        Ok(())
    }

    /// Store worker information in the database (simplified)
    pub async fn store_worker(&self, worker_info: &WorkerInfo) -> Result<()> {
        let worker_id = worker_info.worker_id.to_string();
        let capabilities = serde_json::to_value(&worker_info.capabilities)?;
        let cpu_cores = worker_info.capabilities.cpu_cores as i32;
        let memory_mb = (worker_info.capabilities.ram_gb * 1024) as i32;
        let gpu_memory_mb = (worker_info.capabilities.gpu_memory / 1024 / 1024) as i32;
        let storage_gb = 100i32; // Default storage
        let status = "offline";
        let hardware_info = serde_json::json!({
            "gpu_memory": worker_info.capabilities.gpu_memory,
            "cpu_cores": worker_info.capabilities.cpu_cores,
            "ram_gb": worker_info.capabilities.ram_gb,
            "supported_job_types": worker_info.capabilities.supported_job_types,
            "docker_enabled": worker_info.capabilities.docker_enabled,
            "max_parallel_tasks": worker_info.capabilities.max_parallel_tasks
        });

        sqlx::query(
            r#"
            INSERT INTO workers (worker_id, capabilities, cpu_cores, memory_mb, gpu_memory_mb, storage_gb, status, hardware_info)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (worker_id) DO UPDATE SET
                capabilities = EXCLUDED.capabilities,
                cpu_cores = EXCLUDED.cpu_cores,
                memory_mb = EXCLUDED.memory_mb,
                gpu_memory_mb = EXCLUDED.gpu_memory_mb,
                storage_gb = EXCLUDED.storage_gb,
                hardware_info = EXCLUDED.hardware_info,
                last_heartbeat = NOW(),
                last_seen = NOW()
            "#,
        )
        .bind(&worker_id)
        .bind(&capabilities)
        .bind(cpu_cores)
        .bind(memory_mb)
        .bind(gpu_memory_mb)
        .bind(storage_gb)
        .bind(status)
        .bind(&hardware_info)
        .execute(&self.pool)
        .await
        .context("Failed to store worker")?;

        info!("Stored worker {} in database", worker_id);
        Ok(())
    }

    /// Update task status in the database (simplified)
    pub async fn update_task_status(&self, task_id: &str, input: UpdateTaskStatusInput) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE tasks 
            SET status = $1,
                worker_id = COALESCE($2, worker_id),
                started_at = COALESCE($3, started_at),
                completed_at = COALESCE($4, completed_at),
                output_data = COALESCE($5, output_data),
                memory_usage_mb = COALESCE($6, memory_usage_mb),
                processing_time_ms = COALESCE($7, processing_time_ms),
                error_message = COALESCE($8, error_message),
                updated_at = NOW()
            WHERE task_id = $9
            "#,
        )
        .bind(&input.status)
        .bind(&input.worker_id)
        .bind(&input.started_at)
        .bind(&input.completed_at)
        .bind(&input.output_data)
        .bind(&input.memory_usage_mb)
        .bind(&input.processing_time_ms)
        .bind(&input.error_message)
        .bind(task_id)
        .execute(&self.pool)
        .await
        .context("Failed to update task status")?;

        info!("Updated task {} status to {}", task_id, input.status);
        Ok(())
    }

    /// Get job ID for a given task (simplified)
    pub async fn get_job_id_for_task(&self, task_id: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT job_id FROM tasks WHERE task_id = $1")
            .bind(task_id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to get job ID for task")?;

        Ok(row.map(|r| r.get("job_id")))
    }

    /// Get system metrics (simplified)
    pub async fn get_system_metrics(&self) -> Result<HashMap<String, i64>> {
        let mut metrics = HashMap::new();

        // Get total counts
        let job_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
            .fetch_one(&self.pool)
            .await
            .context("Failed to get job count")?;

        let worker_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workers")
            .fetch_one(&self.pool)
            .await
            .context("Failed to get worker count")?;

        let task_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(&self.pool)
            .await
            .context("Failed to get task count")?;

        metrics.insert("total_jobs".to_string(), job_count);
        metrics.insert("total_workers".to_string(), worker_count);
        metrics.insert("total_tasks".to_string(), task_count);

        Ok(metrics)
    }

    /// Close database connection pool
    pub async fn close(&self) {
        self.pool.close().await;
        info!("Database connection pool closed");
    }

    // ==================== EVENT STORAGE METHODS ====================

    /// Store a blockchain event in the database
    pub async fn store_event(&self, event: &CiroEvent) -> Result<()> {
        sqlx::query(
            "INSERT INTO events (contract_address, event_type, block_number, timestamp, data) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(&event.contract_address)
        .bind(&event.event_type)
        .bind(event.block_number as i64)
        .bind(event.timestamp as i64)
        .bind(&event.data)
        .execute(&self.pool)
        .await
        .context("Failed to store event in database")?;

        Ok(())
    }

    /// Get recent events with optional limit
    pub async fn get_recent_events(&self, limit: i64) -> Result<Vec<CiroEvent>> {
        let rows = sqlx::query(
            "SELECT contract_address, event_type, block_number, timestamp, data 
             FROM events 
             ORDER BY created_at DESC 
             LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch recent events")?;

        let mut events = Vec::new();
        for row in rows {
            events.push(CiroEvent {
                contract_address: row.get("contract_address"),
                event_type: row.get("event_type"),
                block_number: row.get::<i64, _>("block_number") as u64,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                data: row.get("data"),
            });
        }

        Ok(events)
    }

    /// Get events with optional contract and event type filters
    pub async fn get_events_filtered(
        &self,
        contract: Option<&str>,
        event_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CiroEvent>> {
        // Normalize a provided hex address to compare independent of left padding
        // We compare on lowercase hex without the 0x prefix and with leading zeros trimmed
        let norm = |addr: &str| -> String {
            let s = addr.trim().to_lowercase();
            let s = s.strip_prefix("0x").unwrap_or(&s).to_string();
            let trimmed = s.trim_start_matches('0');
            if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
        };

        let rows = match (contract, event_type) {
            (Some(addr), Some(ev_type)) => {
                sqlx::query(
                    "SELECT contract_address, event_type, block_number, timestamp, data \
                     FROM events \
                      WHERE ltrim(replace(lower(contract_address), '0x',''),'0') = $1 AND event_type = $2 \
                      ORDER BY created_at DESC \
                      LIMIT $3 OFFSET $4",
                )
                .bind(norm(addr))
                .bind(ev_type)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch filtered events (contract + type)")?
            }
            (Some(addr), None) => {
                sqlx::query(
                    "SELECT contract_address, event_type, block_number, timestamp, data \
                     FROM events \
                      WHERE ltrim(replace(lower(contract_address), '0x',''),'0') = $1 \
                      ORDER BY created_at DESC \
                      LIMIT $2 OFFSET $3",
                )
                .bind(norm(addr))
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch filtered events (contract only)")?
            }
            (None, Some(ev_type)) => {
                sqlx::query(
                    "SELECT contract_address, event_type, block_number, timestamp, data \
                     FROM events \
                     WHERE event_type = $1 \
                      ORDER BY created_at DESC \
                      LIMIT $2 OFFSET $3",
                )
                .bind(ev_type)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch filtered events (type only)")?
            }
            (None, None) => {
                let rows = sqlx::query(
                    "SELECT contract_address, event_type, block_number, timestamp, data \
                     FROM events \
                     ORDER BY created_at DESC \
                     LIMIT $1 OFFSET $2"
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch recent events with pagination")?;

                let mut events = Vec::new();
                for row in rows {
                    events.push(CiroEvent {
                        contract_address: row.get("contract_address"),
                        event_type: row.get("event_type"),
                        block_number: row.get::<i64, _>("block_number") as u64,
                        timestamp: row.get::<i64, _>("timestamp") as u64,
                        data: row.get("data"),
                    });
                }
                return Ok(events);
            }
        };

        let mut events = Vec::new();
        for row in rows {
            events.push(CiroEvent {
                contract_address: row.get("contract_address"),
                event_type: row.get("event_type"),
                block_number: row.get::<i64, _>("block_number") as u64,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                data: row.get("data"),
            });
        }

        Ok(events)
    }

    /// Get events for a specific contract
    pub async fn get_contract_events(&self, contract_address: &str, limit: i64) -> Result<Vec<CiroEvent>> {
        let rows = sqlx::query(
            "SELECT contract_address, event_type, block_number, timestamp, data 
             FROM events 
             WHERE contract_address = $1 
             ORDER BY created_at DESC 
             LIMIT $2"
        )
        .bind(contract_address)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch contract events")?;

        let mut events = Vec::new();
        for row in rows {
            events.push(CiroEvent {
                contract_address: row.get("contract_address"),
                event_type: row.get("event_type"),
                block_number: row.get::<i64, _>("block_number") as u64,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                data: row.get("data"),
            });
        }

        Ok(events)
    }

    /// Get event statistics for the dashboard
    pub async fn get_event_stats(&self) -> Result<(i64, HashMap<String, i64>, HashMap<String, i64>)> {
        // Total events
        let total_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(&self.pool)
            .await
            .context("Failed to get total events count")?;

        // Events by type
        let type_rows = sqlx::query(
            "SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type"
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to get events by type")?;

        let mut events_by_type = HashMap::new();
        for row in type_rows {
            let event_type: String = row.get("event_type");
            let count: i64 = row.get("count");
            events_by_type.insert(event_type, count);
        }

        // Events by contract
        let contract_rows = sqlx::query(
            "SELECT contract_address, COUNT(*) as count FROM events GROUP BY contract_address"
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to get events by contract")?;

        let mut events_by_contract = HashMap::new();
        for row in contract_rows {
            let contract_address: String = row.get("contract_address");
            let count: i64 = row.get("count");
            events_by_contract.insert(contract_address, count);
        }

        Ok((total_events, events_by_type, events_by_contract))
    }

    /// Get simple block stats for dashboard metrics: (last_block, total_distinct_blocks)
    pub async fn get_block_stats(&self) -> Result<(i64, i64)> {
        // Last (max) block number we've seen in events
        let last_block: Option<i64> = sqlx::query_scalar("SELECT MAX(block_number) FROM events")
            .fetch_one(&self.pool)
            .await
            .context("Failed to get last block number")?;

        let last_block = last_block.unwrap_or(0);

        // Count of distinct blocks that have at least one event
        let total_blocks: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT block_number) FROM events")
            .fetch_one(&self.pool)
            .await
            .context("Failed to get total distinct blocks")?;

        Ok((last_block, total_blocks))
    }
}

// Helper function to convert our types to database types
impl From<&TaskStatus> for &str {
    fn from(status: &TaskStatus) -> Self {
        match status {
            TaskStatus::Pending => "pending",
            TaskStatus::Queued => "pending",
            TaskStatus::Assigned => "assigned",
            TaskStatus::Running => "processing",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
        }
    }
}

impl From<TaskStatus> for String {
    fn from(status: TaskStatus) -> Self {
        let str_status: &str = (&status).into();
        str_status.to_string()
    }
}

// For compatibility with existing code, we'll alias the simple database
pub use SimpleDatabase as Database; 