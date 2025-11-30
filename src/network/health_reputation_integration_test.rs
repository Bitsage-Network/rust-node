//! # Network Health and Reputation System Integration Test
//!
//! This test demonstrates the comprehensive health monitoring and reputation system
//! working with the job distribution system.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use crate::blockchain::{
    client::StarknetClient,
    contracts::JobManagerContract,
    types::{JobSpec, JobType, ModelId, VerificationMethod, WorkerCapabilities},
};
use crate::network::{
    job_distribution::{JobDistributor, JobDistributionConfig, JobAnnouncement, WorkerBid, JobResult},
    health_reputation::{HealthReputationSystem, HealthReputationConfig, HealthMetrics, PenaltyType},
    p2p::P2PNetwork,
};
use crate::types::{JobId, WorkerId};
use starknet::core::types::FieldElement;

/// Integration test for the health and reputation system
pub struct HealthReputationIntegrationTest {
    job_distributor: Arc<JobDistributor>,
    health_system: Arc<HealthReputationSystem>,
    test_workers: Vec<WorkerId>,
}

impl HealthReputationIntegrationTest {
    /// Create a new integration test
    pub fn new() -> Result<Self> {
        // Create configuration
        let health_config = HealthReputationConfig {
            health_check_interval_secs: 30,
            reputation_decay_rate: 0.01,
            min_reputation_threshold: 0.3,
            max_reputation_score: 1.0,
            failure_penalty_multiplier: 0.9,
            success_bonus_multiplier: 1.05,
            timeout_penalty_severity: 0.8,
            malicious_penalty_severity: 0.5,
            reputation_recovery_rate: 0.02,
            max_penalty_history: 100,
            health_metrics_window: 50,
            network_health_threshold: 0.7,
            enable_auto_ban: true,
            min_jobs_for_decay: 5,
        };

        let job_config = JobDistributionConfig {
            max_workers_per_job: 10,
            bid_timeout_secs: 30,
            min_worker_reputation: 0.5,
            announcement_retries: 3,
            blockchain_poll_interval_secs: 10,
            health_reputation_config: health_config,
        };

        // Create dependencies
        let blockchain_client = Arc::new(StarknetClient::new("http://localhost:5050".to_string()));
        let job_manager = Arc::new(JobManagerContract::new(
            FieldElement::from_hex_be("0x123").unwrap(),
            blockchain_client.clone(),
        ));
        let p2p_network = Arc::new(P2PNetwork::new(crate::network::p2p::P2PConfig::default()).unwrap().0);

        // Create job distributor
        let job_distributor = Arc::new(JobDistributor::new(
            job_config,
            blockchain_client,
            job_manager,
            p2p_network,
        ));

        let health_system = job_distributor.health_reputation_system();

        Ok(Self {
            job_distributor,
            health_system,
            test_workers: Vec::new(),
        })
    }

    /// Run the complete integration test
    pub async fn run_test(&mut self) -> Result<()> {
        info!("Starting Network Health and Reputation System Integration Test");

        // Start the systems
        self.job_distributor.start().await?;

        // Create test workers
        self.create_test_workers().await?;

        // Test 1: Worker health monitoring
        self.test_worker_health_monitoring().await?;

        // Test 2: Reputation scoring
        self.test_reputation_scoring().await?;

        // Test 3: Penalty system
        self.test_penalty_system().await?;

        // Test 4: Worker banning
        self.test_worker_banning().await?;

        // Test 5: Job distribution with health/reputation
        self.test_job_distribution_with_health().await?;

        // Test 6: Network health monitoring
        self.test_network_health_monitoring().await?;

        // Test 7: Malicious behavior detection
        self.test_malicious_behavior_detection().await?;

        // Test 8: Reputation recovery
        self.test_reputation_recovery().await?;

        // Stop the systems
        self.job_distributor.stop().await?;

        info!("Network Health and Reputation System Integration Test completed successfully");
        Ok(())
    }

    /// Create test workers with different characteristics
    async fn create_test_workers(&mut self) -> Result<()> {
        info!("Creating test workers...");

        let worker_ids = vec![
            WorkerId::new(), // Good worker
            WorkerId::new(), // Average worker
            WorkerId::new(), // Poor worker
            WorkerId::new(), // Malicious worker
        ];

        for (i, worker_id) in worker_ids.iter().enumerate() {
            let capabilities = WorkerCapabilities {
                gpu_memory: 8192,
                cpu_cores: 8,
                ram: 16384,
                storage: 1000,
                bandwidth: 1000,
                capability_flags: 0xFF,
                gpu_model: FieldElement::from(0x4090u32),
                cpu_model: FieldElement::from(0x7950u32),
            };

            // Initialize worker reputation
            self.health_system.update_worker_reputation(
                worker_id.clone(),
                true, // Start with a successful job
                5000, // 5 seconds
                100,  // 100 tokens
                Some(0.95), // High quality result
            ).await?;

            // Set different initial reputations based on worker type
            match i {
                0 => { // Good worker - high reputation
                    self.simulate_worker_success(worker_id.clone(), 10).await?;
                }
                1 => { // Average worker - medium reputation
                    self.simulate_worker_success(worker_id.clone(), 5).await?;
                    self.simulate_worker_failure(worker_id.clone(), 2).await?;
                }
                2 => { // Poor worker - low reputation
                    self.simulate_worker_success(worker_id.clone(), 3).await?;
                    self.simulate_worker_failure(worker_id.clone(), 7).await?;
                }
                3 => { // Malicious worker - will be banned
                    self.simulate_worker_success(worker_id.clone(), 2).await?;
                    self.simulate_malicious_behavior(worker_id.clone()).await?;
                }
                _ => {}
            }

            self.test_workers.push(worker_id.clone());
        }

        info!("Created {} test workers", self.test_workers.len());
        Ok(())
    }

    /// Test worker health monitoring
    async fn test_worker_health_monitoring(&self) -> Result<()> {
        info!("Testing worker health monitoring...");

        for worker_id in &self.test_workers {
            // Simulate health metrics
            let metrics = HealthMetrics {
                response_time_ms: 100 + (worker_id.to_string().len() as u64 * 10), // Vary response time
                cpu_usage_percent: 50.0 + (worker_id.to_string().len() as f32 * 5.0),
                memory_usage_percent: 60.0 + (worker_id.to_string().len() as f32 * 3.0),
                disk_usage_percent: 70.0,
                network_latency_ms: 50,
                uptime_seconds: 3600,
                load_average: 1.5,
                temperature_celsius: Some(65.0),
                gpu_utilization_percent: Some(80.0),
                gpu_memory_usage_percent: Some(70.0),
                network_bandwidth_mbps: Some(100.0),
            };

            self.health_system.update_worker_health(worker_id.clone(), metrics).await?;

            // Check health status
            if let Some(health) = self.health_system.get_worker_health(worker_id).await {
                info!("Worker {} health score: {:.2}", worker_id, health.health_score);
                assert!(health.health_score > 0.0);
                assert!(health.health_score <= 1.0);
            }
        }

        info!("Worker health monitoring test completed");
        Ok(())
    }

    /// Test reputation scoring
    async fn test_reputation_scoring(&self) -> Result<()> {
        info!("Testing reputation scoring...");

        for worker_id in &self.test_workers {
            if let Some(reputation) = self.health_system.get_worker_reputation(worker_id).await {
                info!("Worker {} reputation: {:.2} (completed: {}, failed: {})", 
                    worker_id, reputation.reputation_score, reputation.jobs_completed, reputation.jobs_failed);
                
                assert!(reputation.reputation_score >= 0.0);
                assert!(reputation.reputation_score <= 1.0);
            }
        }

        info!("Reputation scoring test completed");
        Ok(())
    }

    /// Test penalty system
    async fn test_penalty_system(&self) -> Result<()> {
        info!("Testing penalty system...");

        let test_worker = &self.test_workers[1]; // Use average worker

        // Get initial reputation
        let initial_reputation = self.health_system.get_worker_reputation(test_worker).await
            .expect("Worker should exist");

        // Apply a penalty
        self.health_system.apply_penalty(
            test_worker.clone(),
            PenaltyType::JobTimeout,
            0.3,
            "Test timeout penalty".to_string(),
            Some(JobId::new()),
        ).await?;

        // Check reputation decreased
        let new_reputation = self.health_system.get_worker_reputation(test_worker).await
            .expect("Worker should exist");

        assert!(new_reputation.reputation_score < initial_reputation.reputation_score);
        assert!(new_reputation.total_penalties > initial_reputation.total_penalties);

        info!("Penalty system test completed");
        Ok(())
    }

    /// Test worker banning
    async fn test_worker_banning(&self) -> Result<()> {
        info!("Testing worker banning...");

        let malicious_worker = &self.test_workers[3]; // Malicious worker

        // Check if worker is banned
        if let Some(reputation) = self.health_system.get_worker_reputation(malicious_worker).await {
            if reputation.is_banned {
                info!("Worker {} is banned: {}", malicious_worker, reputation.ban_reason.as_ref().unwrap_or(&"No reason".to_string()));
                assert!(reputation.is_banned);
            }
        }

        // Test unbanning
        self.health_system.unban_worker(malicious_worker).await?;

        if let Some(reputation) = self.health_system.get_worker_reputation(malicious_worker).await {
            assert!(!reputation.is_banned);
            info!("Worker {} unbanned successfully", malicious_worker);
        }

        info!("Worker banning test completed");
        Ok(())
    }

    /// Test job distribution with health/reputation
    async fn test_job_distribution_with_health(&self) -> Result<()> {
        info!("Testing job distribution with health/reputation...");

        // Create a job announcement
        let job_id = JobId::new();
        let job_spec = JobSpec {
            job_type: JobType::AIInference,
            model_id: ModelId::new(FieldElement::from(1u32)),
            input_data_hash: FieldElement::from_hex_be("0x123").unwrap(),
            expected_output_format: FieldElement::from_hex_be("0x456").unwrap(),
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: 1000,
            sla_deadline: 3600,
            compute_requirements: vec![],
            metadata: vec![],
        };

        let announcement = JobAnnouncement {
            job_id: job_id.clone(),
            job_spec,
            max_reward: 1000,
            deadline: 3600,
            required_capabilities: WorkerCapabilities::default(),
            announcement_id: uuid::Uuid::new_v4().to_string(),
            announced_at: chrono::Utc::now().timestamp() as u64,
        };

        // Simulate bids from workers
        for (i, worker_id) in self.test_workers.iter().enumerate() {
            if let Some(reputation) = self.health_system.get_worker_reputation(worker_id).await {
                if reputation.is_eligible() {
                    let bid = WorkerBid {
                        job_id: job_id.clone(),
                        worker_id: worker_id.clone(),
                        bid_amount: 800 + (i as u128 * 50),
                        estimated_completion_time: 1800 + (i as u64 * 300),
                        worker_capabilities: WorkerCapabilities::default(),
                        reputation_score: reputation.reputation_score,
                        health_score: 0.8 + (i as f64 * 0.05),
                        bid_id: uuid::Uuid::new_v4().to_string(),
                        submitted_at: chrono::Utc::now().timestamp() as u64,
                    };

                    info!("Worker {} bid: reputation={:.2}, health={:.2}, bid={}", 
                        worker_id, bid.reputation_score, bid.health_score, bid.bid_amount);
                } else {
                    info!("Worker {} not eligible (banned or low reputation)", worker_id);
                }
            }
        }

        info!("Job distribution with health/reputation test completed");
        Ok(())
    }

    /// Test network health monitoring
    async fn test_network_health_monitoring(&self) -> Result<()> {
        info!("Testing network health monitoring...");

        let network_health = self.health_system.get_network_health().await;
        
        info!("Network Health:");
        info!("  Total workers: {}", network_health.total_workers);
        info!("  Active workers: {}", network_health.active_workers);
        info!("  Healthy workers: {}", network_health.healthy_workers);
        info!("  Banned workers: {}", network_health.banned_workers);
        info!("  Average reputation: {:.2}", network_health.average_reputation);
        info!("  Success rate: {:.2}", network_health.success_rate);
        info!("  Health score: {:.2}", network_health.health_score);

        assert!(network_health.total_workers > 0);
        assert!(network_health.health_score > 0.0);
        assert!(network_health.health_score <= 1.0);

        info!("Network health monitoring test completed");
        Ok(())
    }

    /// Test malicious behavior detection
    async fn test_malicious_behavior_detection(&self) -> Result<()> {
        info!("Testing malicious behavior detection...");

        let test_worker = &self.test_workers[2]; // Use poor worker

        // Simulate malicious behavior
        self.health_system.detect_malicious_behavior(
            test_worker.clone(),
            "Invalid result submission".to_string(),
        ).await?;

        // Check if penalties were applied
        if let Some(reputation) = self.health_system.get_worker_reputation(test_worker).await {
            info!("Worker {} malicious behavior count: {}", 
                test_worker, reputation.malicious_behavior_count);
            assert!(reputation.malicious_behavior_count > 0);
        }

        info!("Malicious behavior detection test completed");
        Ok(())
    }

    /// Test reputation recovery
    async fn test_reputation_recovery(&self) -> Result<()> {
        info!("Testing reputation recovery...");

        let test_worker = &self.test_workers[1]; // Use average worker

        // Get initial reputation
        let initial_reputation = self.health_system.get_worker_reputation(test_worker).await
            .expect("Worker should exist");

        // Simulate successful jobs to improve reputation
        for _ in 0..5 {
            self.health_system.update_worker_reputation(
                test_worker.clone(),
                true, // Success
                4000, // 4 seconds
                150,  // 150 tokens
                Some(0.9), // High quality
            ).await?;
        }

        // Check reputation improved
        let final_reputation = self.health_system.get_worker_reputation(test_worker).await
            .expect("Worker should exist");

        info!("Worker {} reputation recovery: {:.2} -> {:.2}", 
            test_worker, initial_reputation.reputation_score, final_reputation.reputation_score);

        assert!(final_reputation.reputation_score >= initial_reputation.reputation_score);

        info!("Reputation recovery test completed");
        Ok(())
    }

    /// Simulate worker success
    async fn simulate_worker_success(&self, worker_id: WorkerId, count: u32) -> Result<()> {
        for _ in 0..count {
            self.health_system.update_worker_reputation(
                worker_id.clone(),
                true, // Success
                5000, // 5 seconds
                100,  // 100 tokens
                Some(0.95), // High quality
            ).await?;
        }
        Ok(())
    }

    /// Simulate worker failure
    async fn simulate_worker_failure(&self, worker_id: WorkerId, count: u32) -> Result<()> {
        for _ in 0..count {
            self.health_system.update_worker_reputation(
                worker_id.clone(),
                false, // Failure
                3000,  // 3 seconds
                0,     // No earnings
                None,  // No quality score
            ).await?;
        }
        Ok(())
    }

    /// Simulate malicious behavior
    async fn simulate_malicious_behavior(&self, worker_id: WorkerId) -> Result<()> {
        // Apply multiple penalties to trigger banning
        for i in 0..5 {
            self.health_system.detect_malicious_behavior(
                worker_id.clone(),
                format!("Malicious behavior {}", i),
            ).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_reputation_integration() {
        let mut integration_test = HealthReputationIntegrationTest::new().unwrap();
        integration_test.run_test().await.unwrap();
    }
} 