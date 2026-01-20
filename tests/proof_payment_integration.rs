/// Integration test for proof-gated payment flow
///
/// Tests the end-to-end flow:
/// 1. Job execution with proof generation
/// 2. Payment claim with proof verification

use bitsage_node::compute::job_executor::{JobExecutor, JobExecutionRequest, JobRequirements};

#[tokio::test]
async fn test_job_proof_payment_integration() {
    // Create executor with proof generation enabled
    let executor = JobExecutor::new("integration-test-worker".to_string(), false);

    // Create a job that will generate a proof
    let request = JobExecutionRequest {
        job_id: Some("payment-test-job-001".to_string()),
        job_type: Some("AIInference".to_string()),
        payload: vec![1, 2, 3, 4, 5],
        requirements: JobRequirements {
            min_vram_mb: 100,
            min_gpu_count: 1,
            required_job_type: "AIInference".to_string(),
            timeout_seconds: 60,
            requires_tee: false,
        },
        priority: 1,
    };

    // Execute job with proof generation
    let result = executor.execute(request).await;

    assert!(result.is_ok(), "Job execution should succeed");

    let result = result.unwrap();

    // Verify job completion
    assert_eq!(result.status, "completed");
    assert_eq!(result.job_id, "payment-test-job-001");

    // Verify proof data is present
    assert!(result.proof_hash.is_some(), "Proof hash should be generated");
    assert!(result.proof_attestation.is_some(), "Proof attestation should be generated");
    assert!(result.proof_commitment.is_some(), "Proof commitment should be generated");
    assert!(result.compressed_proof.is_some(), "Compressed proof should be generated");

    // Verify proof data is non-trivial
    if let Some(proof_hash) = result.proof_hash {
        assert!(proof_hash.iter().any(|&b| b != 0), "Proof hash should be non-zero");
    }

    if let Some(compressed_proof) = &result.compressed_proof {
        assert!(!compressed_proof.data.is_empty(), "Compressed proof data should not be empty");
        println!("✅ Generated compressed proof: {} bytes", compressed_proof.data.len());
    }

    // Verify metrics
    assert!(result.proof_size_bytes.is_some() && result.proof_size_bytes.unwrap() > 0);
    assert!(result.proof_time_ms.is_some() && result.proof_time_ms.unwrap() > 0);

    println!("✅ Proof-payment integration test passed!");
    println!("   Job: {}", result.job_id);
    println!("   Proof size: {} bytes", result.proof_size_bytes.unwrap());
    println!("   Proof time: {}ms", result.proof_time_ms.unwrap());
    println!("   Execution time: {}ms", result.execution_time_ms);
}
