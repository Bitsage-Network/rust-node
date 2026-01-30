/// Integration test for proof generation pipeline
///
/// Tests the end-to-end flow: Job execution → Proof generation → Result with proof

use bitsage_node::compute::job_executor::{JobExecutor, JobExecutionRequest, JobRequirements};

#[tokio::test]
async fn test_job_execution_generates_proof() {
    // Create executor with proof generation enabled
    let executor = JobExecutor::new("test-worker-1".to_string(), false);

    // Create a simple AI inference job
    let request = JobExecutionRequest {
        job_id: Some("test-job-123".to_string()),
        job_type: Some("AIInference".to_string()),
        payload: vec![1, 2, 3, 4, 5], // Simple test payload
        requirements: JobRequirements {
            min_vram_mb: 100,
            min_gpu_count: 1,
            required_job_type: "AIInference".to_string(),
            timeout_seconds: 60,
            requires_tee: false,
        },
        priority: 1,
        customer_pubkey: None,
    };

    // Execute job with proof generation
    let result = executor.execute(request).await;

    assert!(result.is_ok(), "Job execution failed: {:?}", result.err());

    let result = result.unwrap();

    // Verify basic job completion
    assert_eq!(result.status, "completed");
    assert_eq!(result.job_id, "test-job-123");
    assert!(!result.output_hash.is_empty());

    // Verify proof was generated
    assert!(result.proof_hash.is_some(), "Proof hash should be generated");
    assert!(result.proof_attestation.is_some(), "Proof attestation should be generated");
    assert!(result.proof_commitment.is_some(), "Proof commitment should be generated");
    assert!(result.proof_size_bytes.is_some(), "Proof size should be recorded");
    assert!(result.proof_time_ms.is_some(), "Proof time should be recorded");

    // Verify proof hash is non-zero
    if let Some(proof_hash) = result.proof_hash {
        assert!(proof_hash.iter().any(|&b| b != 0), "Proof hash should be non-zero");
    }

    // Verify proof attestation is non-zero
    if let Some(proof_attestation) = result.proof_attestation {
        assert!(proof_attestation.iter().any(|&b| b != 0), "Proof attestation should be non-zero");
    }

    println!("✅ Proof generated successfully!");
    println!("   Job ID: {}", result.job_id);
    println!("   Proof size: {} bytes", result.proof_size_bytes.unwrap_or(0));
    println!("   Proof time: {}ms", result.proof_time_ms.unwrap_or(0));
    println!("   Proof hash: {:?}", result.proof_hash.map(|h| hex::encode(h)));
}

#[tokio::test]
async fn test_different_job_types_generate_proofs() {
    let executor = JobExecutor::new("test-worker-2".to_string(), false);

    let job_types = vec!["AIInference", "DataPipeline", "ConfidentialVM", "Generic"];

    for job_type in job_types {
        let request = JobExecutionRequest {
            job_id: Some(format!("test-{}-job", job_type)),
            job_type: Some(job_type.to_string()),
            payload: vec![42; 16], // Test payload
            requirements: JobRequirements {
                min_vram_mb: 100,
                min_gpu_count: 1,
                required_job_type: job_type.to_string(),
                timeout_seconds: 60,
                requires_tee: job_type == "ConfidentialVM",
            },
            priority: 1,
            customer_pubkey: None,
        };

        let result = executor.execute(request).await;

        if job_type == "ConfidentialVM" {
            // Skip ConfidentialVM for non-TEE workers
            continue;
        }

        assert!(result.is_ok(), "{} job execution failed: {:?}", job_type, result.err());

        let result = result.unwrap();

        assert!(
            result.proof_hash.is_some(),
            "{} job should generate proof hash",
            job_type
        );

        println!("✅ {} job generated proof successfully", job_type);
    }
}

#[tokio::test]
async fn test_proof_generation_can_be_disabled() {
    // Create executor with proofs disabled
    let executor = JobExecutor::with_proof_config(
        "test-worker-3".to_string(),
        false,
        false, // disable_proofs = false
        true,
    );

    let request = JobExecutionRequest {
        job_id: Some("test-no-proof-job".to_string()),
        job_type: Some("Generic".to_string()),
        payload: vec![1, 2, 3],
        requirements: JobRequirements {
            min_vram_mb: 100,
            min_gpu_count: 1,
            required_job_type: "Generic".to_string(),
            timeout_seconds: 60,
            requires_tee: false,
        },
        priority: 1,
        customer_pubkey: None,
    };

    let result = executor.execute(request).await;

    assert!(result.is_ok());

    let result = result.unwrap();

    // Proof should not be generated when disabled
    assert!(result.proof_hash.is_none(), "Proof should not be generated when disabled");

    println!("✅ Proof generation correctly skipped when disabled");
}
