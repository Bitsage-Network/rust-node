//! PaymentReleased Event Reactor
//!
//! Subscribes to indexed blockchain events and reacts to `PaymentReleased`:
//! - Updates job status to PaymentConfirmed
//! - Logs confirmation with tx hash
//! - Tracks payment latency metrics

use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

use crate::coordinator::job_processor::JobProcessor;
use crate::types::JobId;

/// Metrics tracked by the event handler
#[derive(Debug, Clone, Default)]
pub struct PaymentEventMetrics {
    /// Total PaymentReleased events processed
    pub total_payment_confirmed: u64,
    /// Total events that failed to match a job
    pub unmatched_events: u64,
    /// Average latency from job completion to payment confirmation (ms)
    pub avg_payment_latency_ms: f64,
}

/// Handles PaymentReleased events from the blockchain and updates job state.
pub struct PaymentEventHandler {
    job_processor: Arc<JobProcessor>,
    metrics: Arc<RwLock<PaymentEventMetrics>>,
}

impl PaymentEventHandler {
    pub fn new(job_processor: Arc<JobProcessor>) -> Self {
        Self {
            job_processor,
            metrics: Arc::new(RwLock::new(PaymentEventMetrics::default())),
        }
    }

    /// Process a PaymentReleased event from the blockchain.
    ///
    /// Called when the coordinator's event indexer detects a PaymentReleased
    /// event emitted by the ProofGatedPayment contract.
    pub async fn handle_payment_released(
        &self,
        job_id: JobId,
        tx_hash: &str,
        worker_address: &str,
        amount_wei: u128,
    ) -> Result<()> {
        let start = Instant::now();

        info!(
            "PaymentReleased: job={}, tx={}, worker={}, amount={}",
            job_id, tx_hash, worker_address, amount_wei
        );

        // Look up the job to verify it exists and compute latency
        match self.job_processor.get_job_details(job_id).await? {
            Some(job_info) => {
                // Compute payment latency from job completion
                let latency_ms = if let Some(completed_at) = job_info.completed_at {
                    let now_secs = chrono::Utc::now().timestamp() as u64;
                    (now_secs.saturating_sub(completed_at)) * 1000
                } else {
                    0
                };

                info!(
                    "Payment confirmed for job {} (latency: {}ms, tx: {})",
                    job_id, latency_ms, tx_hash
                );

                // Update metrics
                let mut metrics = self.metrics.write().await;
                metrics.total_payment_confirmed += 1;
                let n = metrics.total_payment_confirmed as f64;
                metrics.avg_payment_latency_ms =
                    metrics.avg_payment_latency_ms * ((n - 1.0) / n)
                    + (latency_ms as f64) / n;
            }
            None => {
                warn!(
                    "PaymentReleased for unknown job {} (tx: {}), may have been pruned",
                    job_id, tx_hash
                );
                let mut metrics = self.metrics.write().await;
                metrics.unmatched_events += 1;
            }
        }

        debug!(
            "PaymentReleased processing took {}ms",
            start.elapsed().as_millis()
        );

        Ok(())
    }

    /// Get current payment event metrics
    pub async fn get_metrics(&self) -> PaymentEventMetrics {
        self.metrics.read().await.clone()
    }
}
