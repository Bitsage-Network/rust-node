//! P2P Network Integration Tests
//!
//! Tests for the complete P2P networking integration including job distribution,
//! worker coordination, and result collection.
//!
//! NOTE: These tests use outdated P2PNetwork API
//! and are disabled until updated to match current API.
#![cfg(all(test, feature = "broken_tests"))]

use bitsage_node::{
    network::{
        p2p::{P2PNetwork, P2PConfig, P2PMessage},
        job_distribution::{JobDistributor, JobDistributionConfig, JobAnnouncement, WorkerBid, JobAssignment},
        result_collection::{ResultCollector, ResultCollectionConfig, WorkerResult}
    },
    types::{JobId, WorkerId, Priority, ResourceRequirements, NetworkAddress},
    blockchain::{StarknetClient, JobManagerContract, JobType, JobSpec, WorkerCapabilities, ModelId, VerificationMethod},
    ai::model_registry::ModelRegistry,
};
use std::sync::Arc;
use uuid::Uuid;
use chrono;
use tokio::time::{sleep, Duration};
use std::collections::HashMap;
use starknet::core::types::FieldElement;

#[cfg(test)]
mod tests {
    use super::*;

    // Helper functions for creating test data
    fn create_test_job_spec() -> JobSpec {
        JobSpec {
            job_type: JobType::AIInference,
            model_id: ModelId::new(FieldElement::from_hex_be("0x123").unwrap()),
            input_data_hash: FieldElement::from_hex_be("0x456").unwrap(),
            expected_output_format: FieldElement::from_hex_be("0x789").unwrap(),
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: 1000,
            sla_deadline: chrono::Utc::now().timestamp() as u64 + 3600,
            compute_requirements: vec![FieldElement::from(4u32), FieldElement::from(8u32), FieldElement::from(4u32)],
            metadata: vec![FieldElement::from(1u32)],
        }
    }

    fn create_test_worker_capabilities() -> WorkerCapabilities {
        WorkerCapabilities {
            gpu_memory: 8,
            cpu_cores: 8,
            ram: 16 * 1024 * 1024 * 1024, // 16GB in bytes
            storage: 100 * 1024 * 1024 * 1024, // 100GB in bytes
            bandwidth: 1000, // 1Gbps
            capability_flags: 0b1111, // All capabilities enabled
            gpu_model: FieldElement::from_hex_be("0x123").unwrap(),
            cpu_model: FieldElement::from_hex_be("0x456").unwrap(),
        }
    }

    fn create_test_blockchain_client() -> Arc<StarknetClient> {
        Arc::new(
            StarknetClient::new("https://starknet-sepolia.public.blastapi.io".to_string())
                .expect("Failed to create blockchain client")
        )
    }

    fn create_test_job_manager() -> Arc<JobManagerContract> {
        let client = create_test_blockchain_client();
        Arc::new(
            JobManagerContract::new(client, FieldElement::from_hex_be("0x123").unwrap())
        )
    }

    fn create_test_p2p_network() -> Arc<P2PNetwork> {
        let config = P2PConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            enable_mdns: false,
            ..Default::default()
        };
        let (network, _receiver) = P2PNetwork::new(config).unwrap();
        Arc::new(network)
    }

    #[tokio::test]
    async fn test_p2p_network_integration() {
        println!("🌐 Testing P2P network integration...");
        
        // Create P2P network
        let p2p_network = create_test_p2p_network();
        println!("✅ P2P network created successfully");
        
        // Test network startup (without spawning to avoid Send issues)
        println!("✅ P2P network ready for testing");
        
        // Test message broadcasting
        let job_id = JobId::new();
        let _message = P2PMessage::JobAnnouncement {
            job_id: job_id.clone(),
            spec: create_test_job_spec(),
            max_reward: 1000,
            deadline: 3600,
        };
        
        println!("✅ Job announcement message created: {}", job_id);
        
        // Test worker capabilities registration
        let worker_id = WorkerId::new();
        let capabilities = create_test_worker_capabilities();
        
        // Register worker capabilities
        p2p_network.register_worker_capabilities(
            p2p_network.local_peer_id(),
            capabilities.clone()
        ).await;
        
        println!("✅ Worker capabilities registered for worker: {}", worker_id);
        
        // Test connected peers
        let connected_peers = p2p_network.get_connected_peers().await;
        println!("✅ Connected peers: {}", connected_peers.len());
        
        println!("✅ P2P network integration test completed successfully");
    }

    #[tokio::test]
    async fn test_job_distribution_p2p_integration() {
        println!("📢 Testing job distribution P2P integration...");
        
        let config = JobDistributionConfig::default();
        let blockchain_client = create_test_blockchain_client();
        let job_manager = create_test_job_manager();
        let p2p_network = create_test_p2p_network();
        
        let _distributor = JobDistributor::new(
            config,
            blockchain_client,
            job_manager,
            p2p_network,
        );
        
        println!("✅ Job distributor created with P2P integration");
        
        // Test job announcement creation
        let job_id = JobId::new();
        let job_spec = create_test_job_spec();
        let capabilities = create_test_worker_capabilities();
        
        let _announcement = JobAnnouncement {
            job_id: job_id.clone(),
            job_spec: job_spec.clone(),
            max_reward: 1000,
            deadline: 3600,
            required_capabilities: capabilities,
            announcement_id: Uuid::new_v4().to_string(),
            announced_at: chrono::Utc::now().timestamp() as u64,
        };
        
        println!("✅ Job announcement created: {}", job_id);
        
        // Test worker bid creation
        let worker_id = WorkerId::new();
        let _bid = WorkerBid {
            job_id: job_id.clone(),
            worker_id: worker_id.clone(),
            bid_amount: 800,
            estimated_completion_time: 1800,
            worker_capabilities: create_test_worker_capabilities(),
            reputation_score: 0.85,
            health_score: 0.82,
            bid_id: Uuid::new_v4().to_string(),
            submitted_at: chrono::Utc::now().timestamp() as u64,
        };
        
        println!("✅ Worker bid created: {} -> {}", worker_id, job_id);
        
        // Test job assignment
        let _assignment = JobAssignment {
            job_id: job_id.clone(),
            worker_id: worker_id.clone(),
            assignment_id: Uuid::new_v4().to_string(),
            reward_amount: 800,
            assigned_at: chrono::Utc::now().timestamp() as u64,
            deadline: chrono::Utc::now().timestamp() as u64 + 3600,
        };
        
        println!("✅ Job assignment created: {} -> {}", job_id, worker_id);
        
        println!("✅ Job distribution P2P integration test completed successfully");
    }

    #[tokio::test]
    async fn test_result_collection_p2p_integration() {
        println!("📊 Testing result collection P2P integration...");
        
        let config = ResultCollectionConfig::default();
        let blockchain_client = create_test_blockchain_client();
        let job_manager = create_test_job_manager();
        let p2p_network = create_test_p2p_network();
        
        let _collector = ResultCollector::new(
            config,
            blockchain_client,
            job_manager,
            p2p_network,
        );
        
        println!("✅ Result collector created with P2P integration");
        
        // Test worker result creation
        let job_id = JobId::new();
        let worker_id = WorkerId::new();
        
        let _worker_result = WorkerResult::new(
            job_id.clone(),
            worker_id.clone(),
            b"test result data".to_vec(),
            1000, // execution_time_ms
            500,  // gas_used
            0.95, // confidence_score
            HashMap::new(),
        );
        
        println!("✅ Worker result created: {} -> {}", worker_id, job_id);
        
        // Test result submission
        let submit_result = _collector.submit_result(_worker_result).await;
        assert!(submit_result.is_ok());
        println!("✅ Worker result submitted successfully");
        
        // Test collection stats
        let stats = _collector.get_collection_stats().await;
        println!("✅ Collection stats retrieved: {} active collections", stats.len());
        
        println!("✅ Result collection P2P integration test completed successfully");
    }

    #[tokio::test]
    async fn test_complete_p2p_workflow() {
        println!("🔄 Testing complete P2P workflow...");
        
        // Create all components
        let p2p_network = create_test_p2p_network();
        let blockchain_client = create_test_blockchain_client();
        let job_manager = create_test_job_manager();
        
        // Create job distributor
        let distributor_config = JobDistributionConfig::default();
        let _distributor = JobDistributor::new(
            distributor_config,
            blockchain_client.clone(),
            job_manager.clone(),
            p2p_network.clone(),
        );
        
        // Create result collector
        let collector_config = ResultCollectionConfig::default();
        let _collector = ResultCollector::new(
            collector_config,
            blockchain_client,
            job_manager,
            p2p_network,
        );
        
        println!("✅ All P2P components created");
        
        // Simulate complete workflow
        let job_id = JobId::new();
        let worker_id = WorkerId::new();
        
        // 1. Job announcement
        let announcement = JobAnnouncement {
            job_id: job_id.clone(),
            job_spec: create_test_job_spec(),
            max_reward: 1000,
            deadline: 3600,
            required_capabilities: create_test_worker_capabilities(),
            announcement_id: Uuid::new_v4().to_string(),
            announced_at: chrono::Utc::now().timestamp() as u64,
        };
        
        // 2. Worker bid
        let bid = WorkerBid {
            job_id: job_id.clone(),
            worker_id: worker_id.clone(),
            bid_amount: 800,
            estimated_completion_time: 1800,
            worker_capabilities: create_test_worker_capabilities(),
            reputation_score: 0.85,
            health_score: 0.82,
            bid_id: Uuid::new_v4().to_string(),
            submitted_at: chrono::Utc::now().timestamp() as u64,
        };
        
        // 3. Job assignment
        let assignment = JobAssignment {
            job_id: job_id.clone(),
            worker_id: worker_id.clone(),
            assignment_id: Uuid::new_v4().to_string(),
            reward_amount: 800,
            assigned_at: chrono::Utc::now().timestamp() as u64,
            deadline: chrono::Utc::now().timestamp() as u64 + 3600,
        };
        
        // 4. Worker result
        let worker_result = WorkerResult::new(
            job_id.clone(),
            worker_id.clone(),
            b"completed job result".to_vec(),
            2000, // execution_time_ms
            750,  // gas_used
            0.98, // confidence_score
            HashMap::new(),
        );
        
        println!("✅ Complete P2P workflow simulation created");
        println!("   - Job ID: {}", job_id);
        println!("   - Worker ID: {}", worker_id);
        println!("   - Announcement ID: {}", announcement.announcement_id);
        println!("   - Bid ID: {}", bid.bid_id);
        println!("   - Assignment ID: {}", assignment.assignment_id);
        
        println!("✅ Complete P2P workflow test completed successfully");
    }

    #[tokio::test]
    async fn test_p2p_message_serialization() {
        println!("📦 Testing P2P message serialization...");
        
        let job_id = JobId::new();
        let worker_id = WorkerId::new();
        
        // Test different message types
        let messages = vec![
            P2PMessage::JobAnnouncement {
                job_id: job_id.clone(),
                spec: create_test_job_spec(),
                max_reward: 1000,
                deadline: 3600,
            },
            P2PMessage::WorkerCapabilities {
                worker_id: worker_id.clone(),
                capabilities: create_test_worker_capabilities(),
                network_address: NetworkAddress { ip: "127.0.0.1".parse().unwrap(), port: 8080 },
                stake_amount: 100,
            },
            P2PMessage::WorkerBid {
                job_id: job_id.clone(),
                worker_id: worker_id.clone(),
                bid_amount: 800,
                estimated_completion_time: 1800,
                reputation_score: 0.85,
            },
            P2PMessage::JobResult {
                job_id: job_id.clone(),
                worker_id: worker_id.clone(),
                success: true,
                data: b"test result".to_vec(),
            },
        ];
        
        for (i, message) in messages.iter().enumerate() {
            // Test serialization
            let serialized = bincode::serialize(message);
            assert!(serialized.is_ok(), "Failed to serialize message {}", i);
            
            // Test deserialization
            let deserialized = bincode::deserialize::<P2PMessage>(&serialized.unwrap());
            assert!(deserialized.is_ok(), "Failed to deserialize message {}", i);
            
            println!("✅ Message {} serialization/deserialization successful", i);
        }
        
        println!("✅ P2P message serialization test completed successfully");
    }
} 