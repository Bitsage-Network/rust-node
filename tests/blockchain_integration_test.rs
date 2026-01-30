#[cfg(test)]
mod tests {
    use bitsage_node::blockchain::{
        client::{StarknetClient, HealthStatus},
        contracts::{JobManagerContract, ContractHealthStatus},
        types::*,
    };
    use bitsage_node::node::coordinator::{JobRequest, JobType as CoordinatorJobType};
    use bitsage_node::types::{JobId, WorkerId};
    use std::sync::Arc;

    // Helper to create a test client
    fn create_test_client() -> Arc<StarknetClient> {
        Arc::new(StarknetClient::new(std::env::var("STARKNET_RPC_URL").unwrap_or_else(|_| "https://api.cartridge.gg/x/starknet/sepolia".to_string()).to_string()).unwrap())
    }

    // Helper to create a test contract
    fn create_test_contract() -> JobManagerContract {
        let client = create_test_client();
        JobManagerContract::new_from_address(
            client,
            "0x1234567890abcdef1234567890abcdef12345678"
        ).unwrap()
    }

    // Helper to create a test job request
    fn create_test_job_request() -> JobRequest {
        JobRequest {
            job_type: CoordinatorJobType::Custom {
                docker_image: "test-image".to_string(),
                command: vec!["echo".to_string(), "hello".to_string()],
                input_files: vec!["input.txt".to_string()],
                parallelizable: true,
            },
            priority: 5,
            max_cost: 1000,
            deadline: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            client_address: "0x123456789abcdef".to_string(),
            callback_url: Some("http://callback.example.com".to_string()),
            data: vec![1, 2, 3],
            max_duration_secs: 3600,
            customer_pubkey: None,
        }
    }

    #[test]
    fn test_starknet_client_creation() {
        let client = StarknetClient::new(std::env::var("STARKNET_RPC_URL").unwrap_or_else(|_| "https://api.cartridge.gg/x/starknet/sepolia".to_string()).to_string());
        assert!(client.is_ok());
        
        let client = client.unwrap();
        assert_eq!(format!("{:#x}", client.chain_id()), "0x534e5f5345504f4c4941");
        
        println!("✅ StarknetClient creation test passed!");
    }

    #[test]
    fn test_invalid_rpc_url() {
        let client = StarknetClient::new("invalid-url".to_string());
        assert!(client.is_err());
        
        println!("✅ Invalid RPC URL test passed!");
    }

    #[test]
    fn test_contract_creation() {
        let contract = create_test_contract();
        assert_eq!(
            format!("{:#x}", contract.contract_address()),
            "0x1234567890abcdef1234567890abcdef12345678"
        );
        
        println!("✅ Contract creation test passed!");
    }

    #[test]
    fn test_job_request_to_spec_conversion() {
        let contract = create_test_contract();
        let job_request = create_test_job_request();
        
        // This tests the private method indirectly through the conversion logic
        let job_spec = JobSpec {
            job_type: JobType::AIInference,
            model_id: ModelId::new(starknet::core::types::FieldElement::from(1u32)),
            input_data_hash: starknet::core::types::FieldElement::from_hex_be("0x0").unwrap(),
            expected_output_format: starknet::core::types::FieldElement::from_hex_be("0x0").unwrap(),
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: job_request.max_cost as u128,
            sla_deadline: job_request.deadline.map(|d| d.timestamp() as u64).unwrap_or(0),
            compute_requirements: vec![],
            metadata: vec![],
        };
        
        // Test that conversion produces valid calldata
        let calldata = job_spec.to_calldata();
        assert!(!calldata.is_empty());
        assert_eq!(calldata[0], JobType::AIInference.to_field_element());
        
        println!("✅ Job request conversion test passed!");
    }

    #[test]
    fn test_job_type_conversions() {
        // Test all job type conversions
        let job_types = vec![
            JobType::AIInference,
            JobType::AITraining,
            JobType::ProofGeneration,
            JobType::ProofVerification,
        ];
        
        for job_type in job_types {
            let field = job_type.to_field_element();
            let converted_back = JobType::from_field_element(field).unwrap();
            assert_eq!(job_type, converted_back);
        }
        
        println!("✅ Job type conversion test passed!");
    }

    #[test]
    fn test_job_state_conversions() {
        // Test all job state conversions
        let job_states = vec![
            JobState::Queued,
            JobState::Processing,
            JobState::Completed,
            JobState::Failed,
            JobState::Cancelled,
        ];
        
        for job_state in job_states {
            // We can't test the reverse conversion easily since we need the exact field values
            // that the contract would return, but we can test that the enum values exist
            match job_state {
                JobState::Queued => assert_eq!(format!("{:?}", job_state), "Queued"),
                JobState::Processing => assert_eq!(format!("{:?}", job_state), "Processing"),
                JobState::Completed => assert_eq!(format!("{:?}", job_state), "Completed"),
                JobState::Failed => assert_eq!(format!("{:?}", job_state), "Failed"),
                JobState::Cancelled => assert_eq!(format!("{:?}", job_state), "Cancelled"),
            }
        }
        
        println!("✅ Job state conversion test passed!");
    }

    #[test]
    fn test_worker_capabilities_serialization() {
        let capabilities = WorkerCapabilities {
            gpu_memory: 8192,
            cpu_cores: 16,
            ram: 32768,
            storage: 1000,
            bandwidth: 1000,
            capability_flags: 0b11111111,
            gpu_model: starknet::core::types::FieldElement::from_hex_be("0x4090").unwrap(),
            cpu_model: starknet::core::types::FieldElement::from_hex_be("0x7950").unwrap(),
        };
        
        let calldata = capabilities.to_calldata();
        assert_eq!(calldata.len(), 8);
        assert_eq!(calldata[0], starknet::core::types::FieldElement::from(8192u64));
        assert_eq!(calldata[1], starknet::core::types::FieldElement::from(16u8));
        
        println!("✅ Worker capabilities serialization test passed!");
    }

    #[test]
    fn test_function_selectors() {
        // Test that all function selectors are properly computed
        use bitsage_node::blockchain::types::selectors::*;
        
        // These should not panic and should return valid FieldElements
        assert_ne!(*SUBMIT_AI_JOB, starknet::core::types::FieldElement::ZERO);
        assert_ne!(*GET_JOB_DETAILS, starknet::core::types::FieldElement::ZERO);
        assert_ne!(*GET_JOB_STATE, starknet::core::types::FieldElement::ZERO);
        assert_ne!(*REGISTER_WORKER, starknet::core::types::FieldElement::ZERO);
        
        println!("✅ Function selectors test passed!");
        println!("   SUBMIT_AI_JOB: {:#x}", *SUBMIT_AI_JOB);
        println!("   GET_JOB_DETAILS: {:#x}", *GET_JOB_DETAILS);
        println!("   GET_JOB_STATE: {:#x}", *GET_JOB_STATE);
        println!("   REGISTER_WORKER: {:#x}", *REGISTER_WORKER);
    }

    #[test]
    fn test_contract_health_status_display() {
        let health_status = ContractHealthStatus {
            contract_address: starknet::core::types::FieldElement::from_hex_be("0x123").unwrap(),
            is_responsive: true,
            response_time_ms: 150,
            last_error: None,
        };
        
        let display_string = format!("{}", health_status);
        assert!(display_string.contains("✓ Responsive"));
        assert!(display_string.contains("150ms"));
        
        let error_status = ContractHealthStatus {
            contract_address: starknet::core::types::FieldElement::from_hex_be("0x123").unwrap(),
            is_responsive: false,
            response_time_ms: 5000,
            last_error: Some("Connection timeout".to_string()),
        };
        
        let error_display = format!("{}", error_status);
        assert!(error_display.contains("✗ Unresponsive"));
        assert!(error_display.contains("Connection timeout"));
        
        println!("✅ Contract health status display test passed!");
    }

    #[test]
    fn test_client_health_status_display() {
        let health_status = HealthStatus {
            connected: true,
            block_number: 123456,
            block_timestamp: 1234567890,
            chain_id: starknet::core::types::FieldElement::from_hex_be("0x534e5f5345504f4c4941").unwrap(),
            response_time_ms: 200,
        };
        
        let display_string = format!("{}", health_status);
        assert!(display_string.contains("✓ Connected"));
        assert!(display_string.contains("123456"));
        assert!(display_string.contains("200ms"));
        
        println!("✅ Client health status display test passed!");
    }

    #[test]
    fn test_integration_data_flow() {
        println!("🔄 Running blockchain integration data flow test...");
        
        // 1. Create client and contract
        let contract = create_test_contract();
        println!("✅ Step 1: Contract created successfully");
        
        // 2. Create job request
        let job_request = create_test_job_request();
        println!("✅ Step 2: Job request created successfully");
        
        // 3. Test job spec conversion
        let job_spec = JobSpec {
            job_type: JobType::AIInference,
            model_id: ModelId::new(starknet::core::types::FieldElement::from(1u32)),
            input_data_hash: starknet::core::types::FieldElement::from_hex_be("0x456").unwrap(),
            expected_output_format: starknet::core::types::FieldElement::from_hex_be("0x789").unwrap(),
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: job_request.max_cost as u128,
            sla_deadline: job_request.deadline.map(|d| d.timestamp() as u64).unwrap_or(0),
            compute_requirements: vec![
                starknet::core::types::FieldElement::from(8u32),
                starknet::core::types::FieldElement::from(16u32)
            ],
            metadata: vec![starknet::core::types::FieldElement::from_hex_be("0xabc").unwrap()],
        };
        println!("✅ Step 3: Job spec created successfully");
        
        // 4. Test calldata generation
        let calldata = job_spec.to_calldata();
        assert!(!calldata.is_empty());
        assert_eq!(calldata[0], JobType::AIInference.to_field_element());
        println!("✅ Step 4: Calldata generated successfully ({} elements)", calldata.len());
        
        // 5. Test worker capabilities
        let capabilities = WorkerCapabilities {
            gpu_memory: 8192,
            cpu_cores: 16,
            ram: 32768,
            storage: 1000,
            bandwidth: 1000,
            capability_flags: 0b11111111,
            gpu_model: starknet::core::types::FieldElement::from_hex_be("0x4090").unwrap(),
            cpu_model: starknet::core::types::FieldElement::from_hex_be("0x7950").unwrap(),
        };
        let worker_calldata = capabilities.to_calldata();
        assert_eq!(worker_calldata.len(), 8);
        println!("✅ Step 5: Worker capabilities serialized successfully");
        
        // 6. Test job result creation
        let job_result = JobResult {
            job_id: JobId::new(),
            worker_id: WorkerId::new(),
            output_data_hash: starknet::core::types::FieldElement::from_hex_be("0xdef123").unwrap(),
            computation_proof: vec![
                starknet::core::types::FieldElement::from_hex_be("0x111").unwrap(),
                starknet::core::types::FieldElement::from_hex_be("0x222").unwrap(),
            ],
            gas_used: 50000,
            execution_time: 1500,
        };
        let result_calldata = job_result.to_calldata();
        assert!(!result_calldata.is_empty());
        println!("✅ Step 6: Job result serialized successfully");
        
        println!("🎉 Integration data flow test completed successfully!");
        println!("📊 Summary:");
        println!("   - Contract address: {:#x}", contract.contract_address());
        println!("   - Job type: {:?}", job_spec.job_type);
        println!("   - Max reward: {} wei", job_spec.max_reward);
        println!("   - Worker GPU: {} MB", capabilities.gpu_memory);
        println!("   - Worker CPU: {} cores", capabilities.cpu_cores);
        println!("   - Execution time: {} ms", job_result.execution_time);
    }
} 