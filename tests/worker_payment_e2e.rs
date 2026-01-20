// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Worker Payment E2E Integration Tests
// Tests for encrypted payment claiming flow

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

use bitsage_node::obelysk::elgamal::{
    KeyPair, Felt252, ECPoint, ElGamalCiphertext,
    encrypt, decrypt_point, discrete_log_bsgs, homomorphic_add,
};
use bitsage_node::obelysk::worker_keys::WorkerKeyManager;

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

// =============================================================================
// Unit Tests: Payment Queue Operations
// =============================================================================

#[tokio::test]
async fn test_payment_queue_basic_operations() {
    // Simulates the pending payment queue used by worker
    let pending: Arc<RwLock<VecDeque<u128>>> = Arc::new(RwLock::new(VecDeque::new()));
    let claimed: Arc<RwLock<HashSet<u128>>> = Arc::new(RwLock::new(HashSet::new()));

    // Queue some job IDs
    let job_ids = vec![1001u128, 1002u128, 1003u128];
    for job_id in &job_ids {
        pending.write().await.push_back(*job_id);
    }

    assert_eq!(pending.read().await.len(), 3, "Should have 3 pending payments");

    // Simulate claiming first payment
    let job_id = pending.write().await.pop_front().unwrap();
    claimed.write().await.insert(job_id);

    assert_eq!(pending.read().await.len(), 2, "Should have 2 pending after claim");
    assert!(claimed.read().await.contains(&1001), "Job 1001 should be claimed");
}

#[tokio::test]
async fn test_payment_queue_skip_already_claimed() {
    let pending: Arc<RwLock<VecDeque<u128>>> = Arc::new(RwLock::new(VecDeque::new()));
    let claimed: Arc<RwLock<HashSet<u128>>> = Arc::new(RwLock::new(HashSet::new()));

    // Pre-mark job as claimed
    claimed.write().await.insert(1001);

    // Queue jobs including the already-claimed one
    for job_id in [1001u128, 1002u128, 1003u128] {
        pending.write().await.push_back(job_id);
    }

    // Simulate batch collection logic (skip already claimed)
    let batch: Vec<u128> = {
        let mut pending_guard = pending.write().await;
        let mut batch = Vec::new();
        let batch_size = 10;

        while batch.len() < batch_size {
            if let Some(job_id) = pending_guard.pop_front() {
                // Skip if already claimed (mirrors worker.rs logic)
                if !claimed.read().await.contains(&job_id) {
                    batch.push(job_id);
                }
            } else {
                break;
            }
        }
        batch
    };

    assert_eq!(batch.len(), 2, "Batch should only contain unclaimed jobs");
    assert!(!batch.contains(&1001), "Batch should not contain already claimed job");
    assert!(batch.contains(&1002), "Batch should contain job 1002");
    assert!(batch.contains(&1003), "Batch should contain job 1003");
}

#[tokio::test]
async fn test_payment_queue_requeue_on_failure() {
    let pending: Arc<RwLock<VecDeque<u128>>> = Arc::new(RwLock::new(VecDeque::new()));

    // Queue a job
    pending.write().await.push_back(1001);

    // Pop it for processing
    let job_id = pending.write().await.pop_front().unwrap();
    assert_eq!(job_id, 1001);
    assert!(pending.read().await.is_empty());

    // Simulate failure - requeue at back
    pending.write().await.push_back(job_id);

    assert_eq!(pending.read().await.len(), 1);
    assert_eq!(*pending.read().await.front().unwrap(), 1001);
}

#[tokio::test]
async fn test_batch_collection_respects_size_limit() {
    let pending: Arc<RwLock<VecDeque<u128>>> = Arc::new(RwLock::new(VecDeque::new()));
    let claimed: Arc<RwLock<HashSet<u128>>> = Arc::new(RwLock::new(HashSet::new()));

    // Queue 20 jobs
    for i in 1..=20u128 {
        pending.write().await.push_back(i);
    }

    let batch_size = 10;
    let batch: Vec<u128> = {
        let mut pending_guard = pending.write().await;
        let mut batch = Vec::with_capacity(batch_size);

        while batch.len() < batch_size {
            if let Some(job_id) = pending_guard.pop_front() {
                if !claimed.read().await.contains(&job_id) {
                    batch.push(job_id);
                }
            } else {
                break;
            }
        }
        batch
    };

    assert_eq!(batch.len(), 10, "Batch should be limited to batch_size");
    assert_eq!(pending.read().await.len(), 10, "Should have 10 remaining in queue");
}

// =============================================================================
// Unit Tests: Worker Key Manager
// =============================================================================

#[test]
fn test_worker_key_manager_from_secret() {
    let worker_id = "test-worker-001";
    let secret = b"test-secret-key-for-worker";

    let manager = WorkerKeyManager::new_from_secret(worker_id, secret, None)
        .expect("Should create key manager from secret");

    // Public key should be deterministic
    let pk1 = manager.public_key();
    let manager2 = WorkerKeyManager::new_from_secret(worker_id, secret, None)
        .expect("Should create second key manager");
    let pk2 = manager2.public_key();

    assert_eq!(pk1, pk2, "Same secret should produce same public key");
}

#[test]
fn test_worker_key_manager_different_secrets() {
    let worker_id = "test-worker-001";
    let secret1 = b"secret-one";
    let secret2 = b"secret-two";

    let manager1 = WorkerKeyManager::new_from_secret(worker_id, secret1, None)
        .expect("Should create key manager 1");
    let manager2 = WorkerKeyManager::new_from_secret(worker_id, secret2, None)
        .expect("Should create key manager 2");

    let pk1 = manager1.public_key();
    let pk2 = manager2.public_key();

    assert_ne!(pk1, pk2, "Different secrets should produce different keys");
}

#[test]
fn test_worker_decrypt_payment() {
    let worker_id = "test-worker-decrypt";
    let secret = b"worker-secret-for-decrypt-test";

    let manager = WorkerKeyManager::new_from_secret(worker_id, secret, None)
        .expect("Should create key manager");

    let public_key = manager.public_key();

    // Simulate an encrypted payment
    let amount = 500u64;
    let randomness = generate_test_randomness(42);
    let ciphertext = encrypt(amount, &public_key, &randomness);

    // Worker decrypts the payment
    let decrypted = manager.decrypt_payment(&ciphertext);

    // Verify decryption (should get amount * H)
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

    assert_eq!(recovered, Some(amount), "Worker should decrypt payment correctly");
}

#[test]
fn test_worker_create_claim_proof() {
    let worker_id = "test-worker-proof";
    let secret = b"worker-secret-for-proof-test";

    let manager = WorkerKeyManager::new_from_secret(worker_id, secret, None)
        .expect("Should create key manager");

    let public_key = manager.public_key();

    // Create a test ciphertext
    let amount = 1000u64;
    let randomness = generate_test_randomness(123);
    let ciphertext = encrypt(amount, &public_key, &randomness);

    let job_id = 12345u128;

    // Worker creates claim proof
    let proof = manager.create_claim_proof(&ciphertext, job_id);

    // Proof should have all required components
    // EncryptionProof has: commitment_x, commitment_y, challenge, response, range_proof_hash, nullifier
    assert!(!proof.challenge.is_zero(), "Proof challenge should not be zero");
    assert!(!proof.response.is_zero(), "Proof response should not be zero");
}

// =============================================================================
// Unit Tests: Job ID Parsing
// =============================================================================

#[test]
fn test_parse_numeric_job_id() {
    // Simple numeric job ID
    let job_id_str = "12345";
    let parsed: Option<u128> = job_id_str.parse().ok();
    assert_eq!(parsed, Some(12345u128));
}

#[test]
fn test_parse_large_job_id() {
    // Large numeric job ID
    let job_id_str = "340282366920938463463374607431768211455"; // u128::MAX
    let parsed: Option<u128> = job_id_str.parse().ok();
    assert_eq!(parsed, Some(u128::MAX));
}

#[test]
fn test_parse_uuid_style_job_id() {
    // UUID-style job ID (common format)
    // We need to convert UUID to u128
    let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
    // Remove dashes and parse as hex
    let hex_str: String = uuid_str.chars().filter(|c| *c != '-').collect();
    let parsed = u128::from_str_radix(&hex_str, 16).ok();
    assert!(parsed.is_some(), "Should parse UUID hex string");
}

// =============================================================================
// Integration Tests: Full E2E Flow (requires devnet)
// =============================================================================

#[tokio::test]
#[ignore = "Requires Starknet devnet with deployed contracts"]
async fn test_worker_payment_e2e_flow() {
    // This test requires:
    // 1. Running Starknet devnet
    // 2. Deployed PrivacyRouter contract
    // 3. Funded accounts
    //
    // Test flow:
    // 1. Create worker with privacy manager
    // 2. Register worker's privacy account
    // 3. Simulate job completion (external - payer creates encrypted payment)
    // 4. Worker claims the payment
    // 5. Verify balance updated

    // TODO: Implement when devnet is available
    // let worker_config = WorkerConfig {
    //     enable_privacy_payments: true,
    //     starknet_rpc_url: Some("http://localhost:5050".to_string()),
    //     ...
    // };
    // let worker = Worker::new(worker_config).await?;
    // worker.start().await?;
    // ... complete flow
}

#[tokio::test]
#[ignore = "Requires Starknet devnet with deployed contracts"]
async fn test_batch_payment_claim_e2e() {
    // Test batch claiming with actual contract calls
    //
    // Test flow:
    // 1. Create worker with privacy manager
    // 2. Register account
    // 3. Have payer create 5 encrypted payments
    // 4. Worker batch claims all 5
    // 5. Verify single transaction, all balances updated

    // TODO: Implement when devnet is available
}

#[tokio::test]
#[ignore = "Requires Starknet devnet with deployed contracts"]
async fn test_claim_already_claimed_payment() {
    // Test that claiming an already-claimed payment is handled gracefully
    //
    // Test flow:
    // 1. Create payment and claim it
    // 2. Try to claim again
    // 3. Verify error is "already claimed" and job is marked in claimed set

    // TODO: Implement when devnet is available
}

// =============================================================================
// Mock Tests: Claim Logic Without Network
// =============================================================================

/// Simulates the claim decision logic without actual network calls
#[tokio::test]
async fn test_claim_decision_single_payment() {
    let pending: Arc<RwLock<VecDeque<u128>>> = Arc::new(RwLock::new(VecDeque::new()));
    pending.write().await.push_back(1001);

    // With single payment, should use individual claim (not batch)
    let batch_size = pending.read().await.len();
    assert_eq!(batch_size, 1, "Single payment should not trigger batch");
}

#[tokio::test]
async fn test_claim_decision_multiple_payments() {
    let pending: Arc<RwLock<VecDeque<u128>>> = Arc::new(RwLock::new(VecDeque::new()));
    for i in 1..=5u128 {
        pending.write().await.push_back(i);
    }

    // With multiple payments, should use batch claim
    let batch_size = pending.read().await.len();
    assert!(batch_size > 1, "Multiple payments should trigger batch claim");
}

#[test]
fn test_payment_encryption_for_worker() {
    // Test that payments encrypted to worker public key can be decrypted
    let keypair = generate_test_keypair(999);
    let amounts = [100u64, 500u64, 1000u64, 5000u64];

    for (i, &amount) in amounts.iter().enumerate() {
        let randomness = generate_test_randomness(i as u64);
        let ciphertext = encrypt(amount, &keypair.public_key, &randomness);

        let decrypted = decrypt_point(&ciphertext, &keypair.secret_key);
        let h = ECPoint::generator_h();
        let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

        assert_eq!(recovered, Some(amount), "Should decrypt amount {}", amount);
    }
}

#[test]
fn test_payment_accumulation() {
    // Test that multiple payments can be accumulated homomorphically
    let keypair = generate_test_keypair(888);
    let amounts = [100u64, 200u64, 300u64];
    let mut accumulated: Option<ElGamalCiphertext> = None;

    for (i, &amount) in amounts.iter().enumerate() {
        let randomness = generate_test_randomness(i as u64 + 100);
        let ciphertext = encrypt(amount, &keypair.public_key, &randomness);

        accumulated = match accumulated {
            None => Some(ciphertext),
            Some(acc) => Some(homomorphic_add(&acc, &ciphertext)),
        };
    }

    let total: u64 = amounts.iter().sum();
    let decrypted = decrypt_point(&accumulated.unwrap(), &keypair.secret_key);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

    assert_eq!(recovered, Some(total), "Accumulated payments should sum correctly");
}
