#[cfg(test)]
mod tests {
    use sage_worker::storage::database_simple::*;
    use sage_worker::storage::models::*;
    use sage_worker::node::coordinator::*;
    use sage_worker::types::*;

    // Helper function to create test data
    fn create_test_job_state() -> JobState {
        let request = JobRequest {
            job_type: JobType::Custom {
                docker_image: "test-image".to_string(),
                command: vec!["echo".to_string(), "hello".to_string()],
                input_files: vec!["input.txt".to_string()],
                parallelizable: true,
            },
            priority: 5,
            max_cost: 100,
            deadline: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            client_address: "0x123".to_string(),
            callback_url: Some("http://callback.example.com".to_string()),
            data: vec![1, 2, 3],
            max_duration_secs: 3600,
        };
        
        JobState {
            job_id: JobId::new(),
            request,
            tasks: vec![],
            status: JobStatus::Queued,
            created_at: chrono::Utc::now(),
            estimated_completion: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        }
    }

    fn create_test_worker_info() -> WorkerInfo {
        WorkerInfo {
            worker_id: WorkerId::new(),
            node_id: NodeId::new(),
            capabilities: WorkerCapabilities {
                gpu_memory: 8192,
                cpu_cores: 8,
                ram_gb: 16,
                supported_job_types: vec!["custom".to_string()],
                docker_enabled: true,
                max_parallel_tasks: 4,
                supported_frameworks: vec!["pytorch".to_string(), "tensorflow".to_string()],
                ai_accelerators: vec!["cuda".to_string()],
                specialized_hardware: vec!["rtx_3070".to_string()],
                model_cache_size_gb: 50,
                max_model_size_gb: 10,
                supports_fp16: true,
                supports_int8: true,
                cuda_compute_capability: Some("8.6".to_string()),
            },
            current_load: 0.5,
            reputation: 8.5,
            last_seen: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_job_state_creation() {
        let job_state = create_test_job_state();
        assert!(job_state.job_id.to_string().len() > 0);
        assert_eq!(job_state.request.priority, 5);
        assert_eq!(job_state.request.max_cost, 100);
        assert_eq!(job_state.request.client_address, "0x123");
        println!("✅ Job state creation test passed!");
    }

    #[test]
    fn test_worker_info_creation() {
        let worker_info = create_test_worker_info();
        assert!(worker_info.worker_id.to_string().len() > 0);
        assert_eq!(worker_info.capabilities.cpu_cores, 8);
        assert_eq!(worker_info.capabilities.ram_gb, 16);
        assert_eq!(worker_info.capabilities.gpu_memory, 8192);
        assert!(worker_info.capabilities.docker_enabled);
        assert_eq!(worker_info.current_load, 0.5);
        assert_eq!(worker_info.reputation, 8.5);
        println!("✅ Worker info creation test passed!");
    }

    #[test]
    fn test_update_task_status_input_creation() {
        let status_update = UpdateTaskStatusInput {
            status: "processing".to_string(),
            worker_id: Some("test-worker-001".to_string()),
            started_at: Some(chrono::Utc::now()),
            completed_at: None,
            output_data: None,
            cpu_usage_percent: Some(rust_decimal::Decimal::new(755, 1)),
            memory_usage_mb: Some(4096),
            gpu_usage_percent: Some(rust_decimal::Decimal::new(900, 1)),
            processing_time_ms: None,
            error_message: None,
        };

        assert_eq!(status_update.status, "processing");
        assert_eq!(status_update.worker_id, Some("test-worker-001".to_string()));
        assert_eq!(status_update.memory_usage_mb, Some(4096));
        println!("✅ Update task status input creation test passed!");
    }

    #[test]
    fn test_job_types_serialization() {
        let job_type = JobType::Custom {
            docker_image: "test-image".to_string(),
            command: vec!["echo".to_string(), "hello".to_string()],
            input_files: vec!["input.txt".to_string()],
            parallelizable: true,
        };

        // Test that we can serialize/deserialize job types
        let json = serde_json::to_string(&job_type).expect("Failed to serialize job type");
        let deserialized: JobType = serde_json::from_str(&json).expect("Failed to deserialize job type");
        
        match deserialized {
            JobType::Custom { docker_image, .. } => {
                assert_eq!(docker_image, "test-image");
            }
            _ => panic!("Unexpected job type after deserialization"),
        }
        
        println!("✅ Job type serialization test passed!");
    }

    #[test]
    fn test_task_status_conversion() {
        let status = TaskStatus::Completed;
        let status_string: String = status.into();
        assert_eq!(status_string, "completed");
        
        let status = TaskStatus::Failed;
        let status_string: String = status.into();
        assert_eq!(status_string, "failed");
        
        println!("✅ Task status conversion test passed!");
    }

    #[test]
    fn test_resource_requirements() {
        let resources = ResourceRequirements {
            cpu_cores: 8,
            memory_gb: 16,
            gpu_memory_gb: Some(8),
            storage_gb: 100,
            network_bandwidth_mbps: 1000,
        };
        
        assert_eq!(resources.cpu_cores, 8);
        assert_eq!(resources.memory_gb, 16);
        assert_eq!(resources.gpu_memory_gb, Some(8));
        assert_eq!(resources.storage_gb, 100);
        assert_eq!(resources.network_bandwidth_mbps, 1000);
        
        println!("✅ Resource requirements test passed!");
    }

    #[test]
    fn test_integration_data_structures() {
        println!("🔄 Running integration data structure test...");
        
        // 1. Create job state
        let job_state = create_test_job_state();
        println!("✅ Step 1: Job state created successfully");
        
        // 2. Create worker info
        let worker_info = create_test_worker_info();
        println!("✅ Step 2: Worker info created successfully");
        
        // 3. Create task status update
        let status_update = UpdateTaskStatusInput {
            status: "processing".to_string(),
            worker_id: Some(worker_info.worker_id.to_string()),
            started_at: Some(chrono::Utc::now()),
            completed_at: None,
            output_data: None,
            cpu_usage_percent: Some(rust_decimal::Decimal::new(755, 1)),
            memory_usage_mb: Some(4096),
            gpu_usage_percent: Some(rust_decimal::Decimal::new(900, 1)),
            processing_time_ms: None,
            error_message: None,
        };
        println!("✅ Step 3: Task status update created successfully");
        
        // 4. Test serialization
        let job_json = serde_json::to_string(&job_state.request.job_type).expect("Failed to serialize job type");
        let worker_json = serde_json::to_string(&worker_info.capabilities).expect("Failed to serialize worker capabilities");
        
        assert!(job_json.len() > 0);
        assert!(worker_json.len() > 0);
        println!("✅ Step 4: Serialization test passed");
        
        println!("🎉 Integration data structure test completed successfully!");
        println!("📊 Summary:");
        println!("   - Job ID: {}", job_state.job_id);
        println!("   - Worker ID: {}", worker_info.worker_id);
        println!("   - Job Type: {:?}", job_state.request.job_type);
        println!("   - Worker Capabilities: {} CPU cores, {} GB RAM, {} GPU memory", 
                 worker_info.capabilities.cpu_cores, 
                 worker_info.capabilities.ram_gb, 
                 worker_info.capabilities.gpu_memory);
    }
} 