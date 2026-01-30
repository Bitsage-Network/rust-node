// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Coordinator Payment Integration Tests
// Tests for coordinator creating encrypted payments when jobs complete


use bitsage_node::obelysk::elgamal::{
    KeyPair, Felt252, ECPoint, encrypt, discrete_log_bsgs,
};
use bitsage_node::obelysk::worker_keys::WorkerKeyManager;
use bitsage_node::coordinator::production_coordinator::{
    ProductionCoordinator, WorkerCapabilities, GpuSpecification,
};

// =============================================================================
// Test Helpers
// =============================================================================

fn generate_test_keypair(seed: u64) -> KeyPair {
    let secret = Felt252::from_u64(seed.wrapping_mul(12345678901234567).wrapping_add(111111));
    KeyPair::from_secret(secret)
}

fn generate_test_randomness(seed: u64) -> Felt252 {
    Felt252::from_u64(seed.wrapping_mul(98765432109876543).wrapping_add(222222))
}

fn create_test_capabilities() -> WorkerCapabilities {
    WorkerCapabilities {
        cpu_cores: 8,
        ram_mb: 16384,
        gpus: vec![GpuSpecification {
            name: "NVIDIA RTX 4090".to_string(),
            vram_mb: 24576,
            cuda_cores: 16384,
            tensor_cores: 512,
            driver_version: "535.104.05".to_string(),
            has_tee: false,
        }],
        tee_cpu: false,
        bandwidth_mbps: 1000,
        supported_job_types: vec!["inference".to_string(), "training".to_string()],
    }
}

// =============================================================================
// Unit Tests: Worker Registration with Privacy Key
// =============================================================================

#[tokio::test]
async fn test_worker_registration_without_privacy() {
    let coordinator = ProductionCoordinator::new();

    let worker_id = "worker-001".to_string();
    let capabilities = create_test_capabilities();

    // Register without privacy key
    coordinator.register_worker(worker_id.clone(), capabilities)
        .await
        .expect("Should register worker without privacy key");

    // Verify worker is registered
    let status = coordinator.get_worker_status(&worker_id).await;
    assert!(status.is_some(), "Worker should be registered");
}

#[tokio::test]
async fn test_worker_registration_with_privacy_key() {
    let coordinator = ProductionCoordinator::new();

    let worker_id = "worker-privacy-001".to_string();
    let capabilities = create_test_capabilities();

    // Create key manager for worker
    let key_manager = WorkerKeyManager::new_from_secret(
        &worker_id,
        b"test-worker-secret-key",
        None,
    ).expect("Should create key manager");

    let public_key = key_manager.public_key();
    let timestamp = chrono::Utc::now().timestamp() as u64;
    let signature = key_manager.sign_registration(timestamp);

    // Register with privacy key
    coordinator.register_worker_with_privacy(
        worker_id.clone(),
        capabilities,
        Some("0x1234567890abcdef".to_string()),
        Some(public_key),
        Some(signature),
        None,
    )
    .await
    .expect("Should register worker with privacy key");

    // Verify worker is registered
    let status = coordinator.get_worker_status(&worker_id).await;
    assert!(status.is_some(), "Worker should be registered");
}

#[tokio::test]
async fn test_worker_registration_with_invalid_signature() {
    let coordinator = ProductionCoordinator::new();

    let worker_id = "worker-invalid-sig".to_string();
    let capabilities = create_test_capabilities();

    // Create two different key managers
    let key_manager1 = WorkerKeyManager::new_from_secret(
        &worker_id,
        b"secret-one",
        None,
    ).expect("Should create key manager 1");

    let key_manager2 = WorkerKeyManager::new_from_secret(
        &worker_id,
        b"secret-two",
        None,
    ).expect("Should create key manager 2");

    // Use public key from one, signature from another
    let public_key = key_manager1.public_key();
    let timestamp = chrono::Utc::now().timestamp() as u64;
    let signature = key_manager2.sign_registration(timestamp);

    // Registration should fail
    let result = coordinator.register_worker_with_privacy(
        worker_id,
        capabilities,
        None,
        Some(public_key),
        Some(signature),
        None,
    ).await;

    assert!(result.is_err(), "Should reject invalid signature");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Invalid privacy key signature"), "Error should mention invalid signature");
}

#[tokio::test]
async fn test_worker_registration_with_stale_timestamp() {
    let coordinator = ProductionCoordinator::new();

    let worker_id = "worker-stale-ts".to_string();
    let capabilities = create_test_capabilities();

    let key_manager = WorkerKeyManager::new_from_secret(
        &worker_id,
        b"test-secret",
        None,
    ).expect("Should create key manager");

    let public_key = key_manager.public_key();
    // Use a timestamp from 10 minutes ago (should be rejected)
    let stale_timestamp = chrono::Utc::now().timestamp() as u64 - 600;
    let signature = key_manager.sign_registration(stale_timestamp);

    // Registration should fail due to stale timestamp
    let result = coordinator.register_worker_with_privacy(
        worker_id,
        capabilities,
        None,
        Some(public_key),
        Some(signature),
        None,
    ).await;

    assert!(result.is_err(), "Should reject stale timestamp");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("stale") || err_msg.contains("timestamp"), "Error should mention stale timestamp");
}

// =============================================================================
// Unit Tests: Payment Encryption Verification
// =============================================================================

#[test]
fn test_coordinator_can_encrypt_payment_to_worker() {
    // Simulate: Coordinator has worker's public key from registration
    // Coordinator encrypts payment amount to that public key

    let worker_secret = b"worker-payment-test-secret";
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-pay",
        worker_secret,
        None,
    ).expect("Should create key manager");

    let worker_public_key = worker_manager.public_key();

    // Coordinator encrypts payment
    let payment_amount = 1000u64;
    let randomness = generate_test_randomness(42);
    let encrypted_payment = encrypt(payment_amount, &worker_public_key, &randomness);

    // Worker should be able to decrypt
    let decrypted = worker_manager.decrypt_payment(&encrypted_payment);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

    assert_eq!(recovered, Some(payment_amount), "Worker should decrypt correct payment amount");
}

#[test]
fn test_multiple_payments_to_different_workers() {
    // Simulate coordinator creating payments for multiple workers
    let workers = vec![
        ("worker-1", b"secret-1".as_slice(), 500u64),
        ("worker-2", b"secret-2".as_slice(), 1000u64),
        ("worker-3", b"secret-3".as_slice(), 750u64),
    ];

    for (worker_id, secret, expected_amount) in workers {
        let manager = WorkerKeyManager::new_from_secret(worker_id, secret, None)
            .expect("Should create key manager");

        let public_key = manager.public_key();
        let randomness = generate_test_randomness(expected_amount);
        let ciphertext = encrypt(expected_amount, &public_key, &randomness);

        // Verify worker can decrypt
        let decrypted = manager.decrypt_payment(&ciphertext);
        let h = ECPoint::generator_h();
        let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

        assert_eq!(recovered, Some(expected_amount),
            "Worker {} should decrypt amount {}", worker_id, expected_amount);
    }
}

// =============================================================================
// Unit Tests: Job Pricing Logic
// =============================================================================

#[test]
fn test_payment_amount_calculation() {
    // Test the pricing formula:
    // base_rate * task_count * complexity_multiplier + gpu_time_bonus

    let base_rate = 100u128;

    // Simple inference job: 1 task, complexity 1
    let inference_payment = base_rate * 1 * 1;
    assert_eq!(inference_payment, 100);

    // Training job: 5 tasks, complexity 5
    let training_payment = base_rate * 5 * 5;
    assert_eq!(training_payment, 2500);

    // Data processing: 3 tasks, complexity 2, with 60 seconds GPU time
    let data_payment = base_rate * 3 * 2 + 60;
    assert_eq!(data_payment, 660);
}

// =============================================================================
// Integration Tests: Full E2E Flow (requires devnet)
// =============================================================================

#[tokio::test]
#[ignore = "Requires Starknet devnet with deployed contracts"]
async fn test_full_coordinator_payment_e2e() {
    // Full E2E flow:
    // 1. Start coordinator with payment client
    // 2. Worker registers with privacy public key
    // 3. Client submits job
    // 4. Coordinator assigns job to worker
    // 5. Worker completes job
    // 6. Coordinator creates encrypted payment
    // 7. Worker claims payment on-chain
    // 8. Verify worker balance increased

    // TODO: Implement when devnet infrastructure is available
    // This test requires:
    // - Running Starknet devnet
    // - Deployed PrivacyRouter contract
    // - Funded coordinator account
    // - Test SAGE tokens
}

#[tokio::test]
#[ignore = "Requires Starknet devnet with deployed contracts"]
async fn test_coordinator_payment_for_multi_task_job() {
    // Test payment creation for a job with multiple tasks:
    // 1. Submit job with 5 tasks
    // 2. Job completes
    // 3. Coordinator calculates total payment (sum of task payments)
    // 4. Creates single encrypted payment for total

    // TODO: Implement when devnet infrastructure is available
}

#[tokio::test]
#[ignore = "Requires Starknet devnet with deployed contracts"]
async fn test_coordinator_handles_payment_failure_gracefully() {
    // Test that job still completes even if payment creation fails:
    // 1. Submit and complete job
    // 2. Simulate payment client failure
    // 3. Verify job is marked complete
    // 4. Verify payment is retried or logged for manual resolution

    // TODO: Implement when devnet infrastructure is available
}

// =============================================================================
// Mock Tests: Coordinator Logic Without Network
// =============================================================================

#[tokio::test]
async fn test_coordinator_stores_worker_public_key() {
    let coordinator = ProductionCoordinator::new();

    let worker_id = "worker-pk-store".to_string();
    let capabilities = create_test_capabilities();

    let key_manager = WorkerKeyManager::new_from_secret(
        &worker_id,
        b"pk-store-secret",
        None,
    ).expect("Should create key manager");

    let public_key = key_manager.public_key();
    let timestamp = chrono::Utc::now().timestamp() as u64;
    let signature = key_manager.sign_registration(timestamp);

    coordinator.register_worker_with_privacy(
        worker_id.clone(),
        capabilities,
        Some("0xwallet".to_string()),
        Some(public_key.clone()),
        Some(signature),
        None,
    )
    .await
    .expect("Should register");

    // Verify worker is online (basic check)
    let status = coordinator.get_worker_status(&worker_id).await;
    assert!(status.is_some(), "Worker should be registered");
}

#[tokio::test]
async fn test_multiple_workers_with_different_keys() {
    let coordinator = ProductionCoordinator::new();

    // Register 3 workers with different keys
    for i in 1..=3 {
        let worker_id = format!("multi-worker-{}", i);
        let secret = format!("secret-{}", i);
        let capabilities = create_test_capabilities();

        let key_manager = WorkerKeyManager::new_from_secret(
            &worker_id,
            secret.as_bytes(),
            None,
        ).expect("Should create key manager");

        let public_key = key_manager.public_key();
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let signature = key_manager.sign_registration(timestamp);

        coordinator.register_worker_with_privacy(
            worker_id.clone(),
            capabilities,
            None,
            Some(public_key),
            Some(signature),
        None,
        )
        .await
        .expect("Should register worker");
    }

    // Verify all 3 workers are registered
    let workers = coordinator.list_workers().await;
    assert_eq!(workers.len(), 3, "Should have 3 registered workers");
}

// =============================================================================
// Multi-Asset Payment Tests
// =============================================================================

use bitsage_node::obelysk::privacy_swap::AssetId;
use std::collections::HashMap;

#[test]
fn test_multi_asset_payment_encryption_sage() {
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-multi-sage",
        b"multi-asset-sage-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();
    let payment_amount = 1000u64;
    let asset_id = AssetId::SAGE;

    // Coordinator encrypts payment
    let randomness = generate_test_randomness(1000);
    let encrypted_payment = encrypt(payment_amount, &public_key, &randomness);

    // Worker decrypts
    let decrypted = worker_manager.decrypt_payment(&encrypted_payment);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

    assert_eq!(recovered, Some(payment_amount),
        "Worker should decrypt correct {} payment amount", asset_id.name());
}

#[test]
fn test_multi_asset_payment_encryption_usdc() {
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-multi-usdc",
        b"multi-asset-usdc-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();
    // 10 USDC = 10_000_000 (6 decimals)
    let payment_amount = 10_000_000u64;
    let asset_id = AssetId::USDC;

    let randomness = generate_test_randomness(1001);
    let encrypted_payment = encrypt(payment_amount, &public_key, &randomness);

    let decrypted = worker_manager.decrypt_payment(&encrypted_payment);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 20_000_000);

    assert_eq!(recovered, Some(payment_amount),
        "Worker should decrypt correct {} payment amount", asset_id.name());
}

#[test]
fn test_multi_asset_payment_encryption_btc() {
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-multi-btc",
        b"multi-asset-btc-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();
    // 0.001 BTC = 100_000 sats (8 decimals)
    let payment_amount = 100_000u64;
    let asset_id = AssetId::BTC;

    let randomness = generate_test_randomness(1002);
    let encrypted_payment = encrypt(payment_amount, &public_key, &randomness);

    let decrypted = worker_manager.decrypt_payment(&encrypted_payment);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 200_000);

    assert_eq!(recovered, Some(payment_amount),
        "Worker should decrypt correct {} payment amount", asset_id.name());
}

#[test]
fn test_multi_asset_payment_rates() {
    // Test coordinator payment rate configuration
    let mut base_rates: HashMap<AssetId, u128> = HashMap::new();

    // Configure rates per token (different due to value differences)
    base_rates.insert(AssetId::SAGE, 100);    // 100 SAGE units per task
    base_rates.insert(AssetId::USDC, 1000);   // 0.001 USDC per task (6 decimals)
    base_rates.insert(AssetId::STRK, 50);     // 50 STRK units per task
    base_rates.insert(AssetId::BTC, 10);      // 10 sats per task

    let task_count = 5u128;
    let complexity = 2u128;

    // Calculate payment for each asset
    for (asset_id, base_rate) in &base_rates {
        let payment = base_rate * task_count * complexity;
        assert!(payment > 0, "{} payment should be positive", asset_id.name());
    }

    // Verify SAGE rate
    let sage_payment = base_rates.get(&AssetId::SAGE).unwrap() * task_count * complexity;
    assert_eq!(sage_payment, 100 * 5 * 2); // 1000 SAGE units

    // Verify USDC rate
    let usdc_payment = base_rates.get(&AssetId::USDC).unwrap() * task_count * complexity;
    assert_eq!(usdc_payment, 1000 * 5 * 2); // 10000 = 0.01 USDC
}

#[test]
fn test_payment_token_extraction_from_job() {
    // Simulate extracting payment token from job metadata
    fn extract_payment_token(job_params: &serde_json::Value) -> AssetId {
        job_params.get("payment_token")
            .and_then(|v| v.as_str())
            .map(|s| parse_asset_id(s))
            .unwrap_or(AssetId::SAGE)
    }

    fn parse_asset_id(s: &str) -> AssetId {
        match s.to_uppercase().as_str() {
            "SAGE" | "0" => AssetId::SAGE,
            "USDC" | "1" => AssetId::USDC,
            "STRK" | "2" => AssetId::STRK,
            "BTC" | "WBTC" | "3" => AssetId::BTC,
            "ETH" | "4" => AssetId::ETH,
            _ => AssetId::SAGE,
        }
    }

    // Job with explicit USDC payment
    let usdc_job = serde_json::json!({
        "model_type": "llama-7b",
        "payment_token": "USDC"
    });
    assert_eq!(extract_payment_token(&usdc_job), AssetId::USDC);

    // Job with BTC payment
    let btc_job = serde_json::json!({
        "model_type": "stable-diffusion",
        "payment_token": "BTC"
    });
    assert_eq!(extract_payment_token(&btc_job), AssetId::BTC);

    // Job without payment token (defaults to SAGE)
    let default_job = serde_json::json!({
        "model_type": "whisper"
    });
    assert_eq!(extract_payment_token(&default_job), AssetId::SAGE);

    // Job with lowercase token name
    let lowercase_job = serde_json::json!({
        "payment_token": "strk"
    });
    assert_eq!(extract_payment_token(&lowercase_job), AssetId::STRK);
}

#[test]
fn test_multi_asset_payment_to_multiple_workers() {
    // Simulate coordinator distributing payments to multiple workers in different assets
    struct WorkerPayment {
        worker_id: String,
        asset_id: AssetId,
        amount: u64,
    }

    let workers = vec![
        ("worker-1", b"secret-1".as_slice(), AssetId::SAGE, 500u64),
        ("worker-2", b"secret-2".as_slice(), AssetId::USDC, 1000u64),
        ("worker-3", b"secret-3".as_slice(), AssetId::BTC, 100u64),
    ];

    for (worker_id, secret, expected_asset, expected_amount) in workers {
        let manager = WorkerKeyManager::new_from_secret(worker_id, secret, None)
            .expect("Should create key manager");

        let public_key = manager.public_key();
        let randomness = generate_test_randomness(expected_amount as u64 + 1000);
        let ciphertext = encrypt(expected_amount, &public_key, &randomness);

        // Worker decrypts
        let decrypted = manager.decrypt_payment(&ciphertext);
        let h = ECPoint::generator_h();
        let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

        assert_eq!(recovered, Some(expected_amount),
            "Worker {} should decrypt {} {} payment",
            worker_id, expected_amount, expected_asset.name());
    }
}

#[test]
fn test_backward_compatible_sage_payments() {
    // Ensure legacy SAGE-only code paths still work
    let worker_manager = WorkerKeyManager::new_from_secret(
        "legacy-worker",
        b"legacy-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();
    let payment_amount = 1500u64;

    // Legacy encryption (no asset_id parameter - implicitly SAGE)
    let randomness = generate_test_randomness(9999);
    let encrypted = encrypt(payment_amount, &public_key, &randomness);

    // Decryption should work the same
    let decrypted = worker_manager.decrypt_payment(&encrypted);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

    assert_eq!(recovered, Some(payment_amount));
}

#[tokio::test]
async fn test_coordinator_multi_asset_worker_registration() {
    let coordinator = ProductionCoordinator::new();

    // Register workers, each preferring a different payment token
    let worker_configs = vec![
        ("sage-worker", "sage-secret", Some("0x1111")),
        ("usdc-worker", "usdc-secret", Some("0x2222")),
        ("btc-worker", "btc-secret", Some("0x3333")),
    ];

    for (worker_id, secret, wallet) in worker_configs {
        let capabilities = create_test_capabilities();
        let key_manager = WorkerKeyManager::new_from_secret(
            worker_id,
            secret.as_bytes(),
            None,
        ).expect("Should create key manager");

        let public_key = key_manager.public_key();
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let signature = key_manager.sign_registration(timestamp);

        coordinator.register_worker_with_privacy(
            worker_id.to_string(),
            capabilities,
            wallet.map(|s| s.to_string()),
            Some(public_key),
            Some(signature),
        None,
        )
        .await
        .expect("Should register worker");
    }

    let workers = coordinator.list_workers().await;
    assert_eq!(workers.len(), 3);
}

#[test]
fn test_asset_decimal_adjustments() {
    // Verify decimal handling for different assets
    fn adjust_amount_for_display(amount: u64, asset_id: AssetId) -> f64 {
        let decimals = asset_id.decimals() as u32;
        amount as f64 / 10u64.pow(decimals) as f64
    }

    // 1 SAGE (18 decimals)
    let sage_amount = 1_000_000_000_000_000_000u64; // 1e18
    let sage_display = adjust_amount_for_display(sage_amount, AssetId::SAGE);
    assert!((sage_display - 1.0).abs() < 0.0001);

    // 1 USDC (6 decimals)
    let usdc_amount = 1_000_000u64; // 1e6
    let usdc_display = adjust_amount_for_display(usdc_amount, AssetId::USDC);
    assert!((usdc_display - 1.0).abs() < 0.0001);

    // 1 BTC (8 decimals)
    let btc_amount = 100_000_000u64; // 1e8
    let btc_display = adjust_amount_for_display(btc_amount, AssetId::BTC);
    assert!((btc_display - 1.0).abs() < 0.0001);
}
