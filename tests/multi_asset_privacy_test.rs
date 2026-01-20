// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Multi-Asset Privacy Payment Tests
// Comprehensive tests for multi-asset privacy payment functionality

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

use bitsage_node::obelysk::elgamal::{
    KeyPair, Felt252, ECPoint, encrypt, decrypt_point, discrete_log_bsgs,
    ElGamalCiphertext,
};
use bitsage_node::obelysk::privacy_swap::AssetId;
use bitsage_node::obelysk::worker_keys::WorkerKeyManager;
use bitsage_node::obelysk::privacy_client::PrivateWorkerPayment;

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

fn create_test_ciphertext(amount: u64, public_key: &ECPoint, seed: u64) -> ElGamalCiphertext {
    let randomness = generate_test_randomness(seed);
    encrypt(amount, public_key, &randomness)
}

// =============================================================================
// Unit Tests: AssetId
// =============================================================================

#[test]
fn test_asset_id_constants() {
    assert_eq!(AssetId::SAGE.0, 0);
    assert_eq!(AssetId::USDC.0, 1);
    assert_eq!(AssetId::STRK.0, 2);
    assert_eq!(AssetId::BTC.0, 3);
    assert_eq!(AssetId::ETH.0, 4);
}

#[test]
fn test_asset_id_wbtc_alias() {
    // WBTC is an alias for BTC (both map to asset_id 3)
    assert_eq!(AssetId::WBTC.0, AssetId::BTC.0);
}

#[test]
fn test_asset_id_default() {
    let default = AssetId::default_sage();
    assert_eq!(default, AssetId::SAGE);
}

#[test]
fn test_asset_id_names() {
    assert_eq!(AssetId::SAGE.name(), "SAGE");
    assert_eq!(AssetId::USDC.name(), "USDC");
    assert_eq!(AssetId::STRK.name(), "STRK");
    assert_eq!(AssetId::BTC.name(), "BTC");
    assert_eq!(AssetId::ETH.name(), "ETH");
}

#[test]
fn test_asset_id_decimals() {
    assert_eq!(AssetId::SAGE.decimals(), 18);
    assert_eq!(AssetId::USDC.decimals(), 6);
    assert_eq!(AssetId::STRK.decimals(), 18);
    assert_eq!(AssetId::BTC.decimals(), 8);
    assert_eq!(AssetId::ETH.decimals(), 18);
}

#[test]
fn test_asset_id_unknown_decimals() {
    let unknown = AssetId(99);
    assert_eq!(unknown.decimals(), 18); // Default to 18
}

#[test]
fn test_asset_id_unknown_name() {
    let unknown = AssetId(99);
    assert_eq!(unknown.name(), "UNKNOWN");
}

#[test]
fn test_asset_id_equality() {
    assert_eq!(AssetId::SAGE, AssetId(0));
    assert_eq!(AssetId::USDC, AssetId(1));
    assert_ne!(AssetId::SAGE, AssetId::USDC);
}

#[test]
fn test_asset_id_hash() {
    let mut set = HashSet::new();
    set.insert(AssetId::SAGE);
    set.insert(AssetId::USDC);
    set.insert(AssetId::SAGE); // Duplicate

    assert_eq!(set.len(), 2);
    assert!(set.contains(&AssetId::SAGE));
    assert!(set.contains(&AssetId::USDC));
}

#[test]
fn test_asset_id_as_hashmap_key() {
    let mut rates: HashMap<AssetId, u128> = HashMap::new();
    rates.insert(AssetId::SAGE, 100);
    rates.insert(AssetId::USDC, 50);
    rates.insert(AssetId::BTC, 1);

    assert_eq!(rates.get(&AssetId::SAGE), Some(&100));
    assert_eq!(rates.get(&AssetId::USDC), Some(&50));
    assert_eq!(rates.get(&AssetId::BTC), Some(&1));
    assert_eq!(rates.get(&AssetId::ETH), None);
}

// =============================================================================
// Unit Tests: PrivateWorkerPayment with AssetId
// =============================================================================

#[test]
fn test_private_worker_payment_default_asset() {
    let keypair = generate_test_keypair(1);
    let ciphertext = create_test_ciphertext(1000, &keypair.public_key, 42);

    let payment = PrivateWorkerPayment {
        job_id: 12345,
        worker: starknet::core::types::FieldElement::from(0x1234u64),
        encrypted_amount: ciphertext,
        timestamp: 1700000000,
        is_claimed: false,
        asset_id: AssetId::default_sage(),
    };

    assert_eq!(payment.asset_id, AssetId::SAGE);
}

#[test]
fn test_private_worker_payment_with_usdc() {
    let keypair = generate_test_keypair(2);
    let ciphertext = create_test_ciphertext(500, &keypair.public_key, 43);

    let payment = PrivateWorkerPayment {
        job_id: 67890,
        worker: starknet::core::types::FieldElement::from(0x5678u64),
        encrypted_amount: ciphertext,
        timestamp: 1700000001,
        is_claimed: false,
        asset_id: AssetId::USDC,
    };

    assert_eq!(payment.asset_id, AssetId::USDC);
    assert_eq!(payment.asset_id.decimals(), 6);
}

#[test]
fn test_private_worker_payment_with_btc() {
    let keypair = generate_test_keypair(3);
    let ciphertext = create_test_ciphertext(100, &keypair.public_key, 44);

    let payment = PrivateWorkerPayment {
        job_id: 11111,
        worker: starknet::core::types::FieldElement::from(0x9ABCu64),
        encrypted_amount: ciphertext,
        timestamp: 1700000002,
        is_claimed: false,
        asset_id: AssetId::BTC,
    };

    assert_eq!(payment.asset_id, AssetId::BTC);
    assert_eq!(payment.asset_id.decimals(), 8);
}

// =============================================================================
// Unit Tests: Multi-Asset Payment Encryption/Decryption
// =============================================================================

#[test]
fn test_encrypt_decrypt_sage_payment() {
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-sage",
        b"sage-test-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();
    let payment_amount = 1000u64;
    let randomness = generate_test_randomness(100);

    let encrypted = encrypt(payment_amount, &public_key, &randomness);
    let decrypted = worker_manager.decrypt_payment(&encrypted);

    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

    assert_eq!(recovered, Some(payment_amount));
}

#[test]
fn test_encrypt_decrypt_usdc_payment() {
    // USDC has 6 decimals, so 1 USDC = 1_000_000 smallest units
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-usdc",
        b"usdc-test-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();
    let payment_amount = 1_000_000u64; // 1 USDC
    let randomness = generate_test_randomness(101);

    let encrypted = encrypt(payment_amount, &public_key, &randomness);
    let decrypted = worker_manager.decrypt_payment(&encrypted);

    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 2_000_000);

    assert_eq!(recovered, Some(payment_amount));
}

#[test]
fn test_encrypt_decrypt_btc_payment() {
    // BTC has 8 decimals, so 1 satoshi = 1 smallest unit
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-btc",
        b"btc-test-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();
    let payment_amount = 100_000u64; // 0.001 BTC (100k sats)
    let randomness = generate_test_randomness(102);

    let encrypted = encrypt(payment_amount, &public_key, &randomness);
    let decrypted = worker_manager.decrypt_payment(&encrypted);

    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted, &h, 200_000);

    assert_eq!(recovered, Some(payment_amount));
}

#[test]
fn test_multiple_assets_same_worker() {
    // Worker can receive payments in different assets
    let worker_manager = WorkerKeyManager::new_from_secret(
        "worker-multi",
        b"multi-asset-secret",
        None,
    ).expect("Should create key manager");

    let public_key = worker_manager.public_key();

    // SAGE payment
    let sage_amount = 500u64;
    let sage_rand = generate_test_randomness(200);
    let sage_encrypted = encrypt(sage_amount, &public_key, &sage_rand);

    // USDC payment
    let usdc_amount = 250u64;
    let usdc_rand = generate_test_randomness(201);
    let usdc_encrypted = encrypt(usdc_amount, &public_key, &usdc_rand);

    // BTC payment
    let btc_amount = 100u64;
    let btc_rand = generate_test_randomness(202);
    let btc_encrypted = encrypt(btc_amount, &public_key, &btc_rand);

    // Decrypt all
    let h = ECPoint::generator_h();

    let sage_decrypted = worker_manager.decrypt_payment(&sage_encrypted);
    let sage_recovered = discrete_log_bsgs(&sage_decrypted, &h, 1000);
    assert_eq!(sage_recovered, Some(sage_amount));

    let usdc_decrypted = worker_manager.decrypt_payment(&usdc_encrypted);
    let usdc_recovered = discrete_log_bsgs(&usdc_decrypted, &h, 1000);
    assert_eq!(usdc_recovered, Some(usdc_amount));

    let btc_decrypted = worker_manager.decrypt_payment(&btc_encrypted);
    let btc_recovered = discrete_log_bsgs(&btc_decrypted, &h, 1000);
    assert_eq!(btc_recovered, Some(btc_amount));
}

// =============================================================================
// Unit Tests: Payment Tracking Data Structures
// =============================================================================

#[test]
fn test_pending_payment_queue_with_assets() {
    let mut queue: VecDeque<(u128, AssetId)> = VecDeque::new();

    // Queue payments in different assets
    queue.push_back((1001, AssetId::SAGE));
    queue.push_back((1002, AssetId::USDC));
    queue.push_back((1003, AssetId::BTC));
    queue.push_back((1004, AssetId::SAGE)); // Same asset, different job

    assert_eq!(queue.len(), 4);

    // Process in order
    let (job_id, asset_id) = queue.pop_front().unwrap();
    assert_eq!(job_id, 1001);
    assert_eq!(asset_id, AssetId::SAGE);

    let (job_id, asset_id) = queue.pop_front().unwrap();
    assert_eq!(job_id, 1002);
    assert_eq!(asset_id, AssetId::USDC);
}

#[test]
fn test_claimed_payments_tracking() {
    let mut claimed: HashMap<u128, HashSet<AssetId>> = HashMap::new();

    // Job 1001: claimed SAGE
    claimed.entry(1001).or_insert_with(HashSet::new).insert(AssetId::SAGE);

    // Job 1002: claimed SAGE and USDC (multi-asset job)
    claimed.entry(1002).or_insert_with(HashSet::new).insert(AssetId::SAGE);
    claimed.entry(1002).or_insert_with(HashSet::new).insert(AssetId::USDC);

    // Check claimed status
    assert!(claimed.get(&1001).map(|s| s.contains(&AssetId::SAGE)).unwrap_or(false));
    assert!(!claimed.get(&1001).map(|s| s.contains(&AssetId::USDC)).unwrap_or(false));

    assert!(claimed.get(&1002).map(|s| s.contains(&AssetId::SAGE)).unwrap_or(false));
    assert!(claimed.get(&1002).map(|s| s.contains(&AssetId::USDC)).unwrap_or(false));
    assert!(!claimed.get(&1002).map(|s| s.contains(&AssetId::BTC)).unwrap_or(false));

    // Job 1003: not claimed at all
    assert!(claimed.get(&1003).is_none());
}

#[test]
fn test_total_claimed_count() {
    let mut claimed: HashMap<u128, HashSet<AssetId>> = HashMap::new();

    claimed.entry(1001).or_insert_with(HashSet::new).insert(AssetId::SAGE);
    claimed.entry(1002).or_insert_with(HashSet::new).insert(AssetId::SAGE);
    claimed.entry(1002).or_insert_with(HashSet::new).insert(AssetId::USDC);
    claimed.entry(1003).or_insert_with(HashSet::new).insert(AssetId::BTC);

    // Total claimed payments (across all jobs and assets)
    let total: usize = claimed.values().map(|assets| assets.len()).sum();
    assert_eq!(total, 4);

    // Total unique jobs with claims
    assert_eq!(claimed.len(), 3);
}

// =============================================================================
// Unit Tests: Asset-Specific Payment Rates
// =============================================================================

#[test]
fn test_payment_rate_calculation_sage() {
    let base_rates: HashMap<AssetId, u128> = [
        (AssetId::SAGE, 100),
        (AssetId::USDC, 50),
        (AssetId::BTC, 1),
    ].into_iter().collect();

    let task_count = 5u128;
    let duration_minutes = 3u128;
    let gpu_multiplier = 2u128;

    let sage_rate = base_rates.get(&AssetId::SAGE).unwrap();
    let payment = sage_rate * task_count * duration_minutes * gpu_multiplier;

    assert_eq!(payment, 100 * 5 * 3 * 2); // 3000 SAGE units
}

#[test]
fn test_payment_rate_calculation_usdc() {
    let base_rates: HashMap<AssetId, u128> = [
        (AssetId::SAGE, 100),
        (AssetId::USDC, 50), // Lower base rate for USDC (higher value per unit)
        (AssetId::BTC, 1),
    ].into_iter().collect();

    let task_count = 5u128;
    let duration_minutes = 3u128;
    let gpu_multiplier = 2u128;

    let usdc_rate = base_rates.get(&AssetId::USDC).unwrap();
    let payment = usdc_rate * task_count * duration_minutes * gpu_multiplier;

    assert_eq!(payment, 50 * 5 * 3 * 2); // 1500 USDC units (0.0015 USDC at 6 decimals)
}

#[test]
fn test_payment_rate_fallback_to_default() {
    let base_rates: HashMap<AssetId, u128> = [
        (AssetId::SAGE, 100),
    ].into_iter().collect();

    let default_rate = 100u128;

    // ETH not configured, should fall back to default
    let eth_rate = base_rates.get(&AssetId::ETH).copied().unwrap_or(default_rate);
    assert_eq!(eth_rate, default_rate);
}

// =============================================================================
// Unit Tests: Asset ID Parsing
// =============================================================================

fn parse_asset_id_from_string(s: &str) -> AssetId {
    match s.to_uppercase().as_str() {
        "SAGE" | "0" => AssetId::SAGE,
        "USDC" | "1" => AssetId::USDC,
        "STRK" | "2" => AssetId::STRK,
        "BTC" | "WBTC" | "3" => AssetId::BTC,
        "ETH" | "4" => AssetId::ETH,
        _ => AssetId::SAGE, // Default
    }
}

#[test]
fn test_parse_asset_id_by_name() {
    assert_eq!(parse_asset_id_from_string("SAGE"), AssetId::SAGE);
    assert_eq!(parse_asset_id_from_string("USDC"), AssetId::USDC);
    assert_eq!(parse_asset_id_from_string("STRK"), AssetId::STRK);
    assert_eq!(parse_asset_id_from_string("BTC"), AssetId::BTC);
    assert_eq!(parse_asset_id_from_string("ETH"), AssetId::ETH);
}

#[test]
fn test_parse_asset_id_case_insensitive() {
    assert_eq!(parse_asset_id_from_string("sage"), AssetId::SAGE);
    assert_eq!(parse_asset_id_from_string("Usdc"), AssetId::USDC);
    assert_eq!(parse_asset_id_from_string("btc"), AssetId::BTC);
}

#[test]
fn test_parse_asset_id_by_number() {
    assert_eq!(parse_asset_id_from_string("0"), AssetId::SAGE);
    assert_eq!(parse_asset_id_from_string("1"), AssetId::USDC);
    assert_eq!(parse_asset_id_from_string("2"), AssetId::STRK);
    assert_eq!(parse_asset_id_from_string("3"), AssetId::BTC);
    assert_eq!(parse_asset_id_from_string("4"), AssetId::ETH);
}

#[test]
fn test_parse_asset_id_wbtc_alias() {
    assert_eq!(parse_asset_id_from_string("WBTC"), AssetId::BTC);
    assert_eq!(parse_asset_id_from_string("wbtc"), AssetId::BTC);
}

#[test]
fn test_parse_asset_id_unknown_defaults_to_sage() {
    assert_eq!(parse_asset_id_from_string("UNKNOWN"), AssetId::SAGE);
    assert_eq!(parse_asset_id_from_string("FOO"), AssetId::SAGE);
    assert_eq!(parse_asset_id_from_string(""), AssetId::SAGE);
}

// =============================================================================
// Unit Tests: Backward Compatibility
// =============================================================================

#[test]
fn test_legacy_payment_defaults_to_sage() {
    // Simulate a legacy payment without explicit asset_id
    let keypair = generate_test_keypair(10);
    let ciphertext = create_test_ciphertext(500, &keypair.public_key, 50);

    // Legacy payment structure (before multi-asset)
    let legacy_job_id: u128 = 99999;
    let legacy_worker = starknet::core::types::FieldElement::from(0xABCDu64);
    let legacy_timestamp: u64 = 1700000000;
    let legacy_is_claimed = false;

    // When converting to new format, default to SAGE
    let payment = PrivateWorkerPayment {
        job_id: legacy_job_id,
        worker: legacy_worker,
        encrypted_amount: ciphertext,
        timestamp: legacy_timestamp,
        is_claimed: legacy_is_claimed,
        asset_id: AssetId::default_sage(), // Backward compat default
    };

    assert_eq!(payment.asset_id, AssetId::SAGE);
}

#[test]
fn test_batch_claim_mixed_assets() {
    // Simulate batch claiming payments in different assets
    let claims: Vec<(u128, AssetId)> = vec![
        (1001, AssetId::SAGE),
        (1002, AssetId::USDC),
        (1003, AssetId::SAGE),
        (1004, AssetId::BTC),
    ];

    // Group by asset for efficient processing
    let mut by_asset: HashMap<AssetId, Vec<u128>> = HashMap::new();
    for (job_id, asset_id) in claims {
        by_asset.entry(asset_id).or_insert_with(Vec::new).push(job_id);
    }

    assert_eq!(by_asset.get(&AssetId::SAGE).map(|v| v.len()), Some(2));
    assert_eq!(by_asset.get(&AssetId::USDC).map(|v| v.len()), Some(1));
    assert_eq!(by_asset.get(&AssetId::BTC).map(|v| v.len()), Some(1));
}

// =============================================================================
// Async Tests: Concurrent Payment Tracking
// =============================================================================

#[tokio::test]
async fn test_concurrent_payment_queue_access() {
    let pending: Arc<RwLock<VecDeque<(u128, AssetId)>>> = Arc::new(RwLock::new(VecDeque::new()));

    // Simulate multiple workers queueing payments
    let pending_clone1 = pending.clone();
    let pending_clone2 = pending.clone();

    let handle1 = tokio::spawn(async move {
        for i in 0..10 {
            pending_clone1.write().await.push_back((1000 + i, AssetId::SAGE));
        }
    });

    let handle2 = tokio::spawn(async move {
        for i in 0..10 {
            pending_clone2.write().await.push_back((2000 + i, AssetId::USDC));
        }
    });

    handle1.await.unwrap();
    handle2.await.unwrap();

    let queue = pending.read().await;
    assert_eq!(queue.len(), 20);

    // Count by asset
    let sage_count = queue.iter().filter(|(_, a)| *a == AssetId::SAGE).count();
    let usdc_count = queue.iter().filter(|(_, a)| *a == AssetId::USDC).count();

    assert_eq!(sage_count, 10);
    assert_eq!(usdc_count, 10);
}

#[tokio::test]
async fn test_concurrent_claimed_tracking() {
    let claimed: Arc<RwLock<HashMap<u128, HashSet<AssetId>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Simulate concurrent claim tracking
    let claimed_clone = claimed.clone();

    // Mark some payments as claimed
    {
        let mut guard = claimed_clone.write().await;
        guard.entry(1001).or_insert_with(HashSet::new).insert(AssetId::SAGE);
        guard.entry(1002).or_insert_with(HashSet::new).insert(AssetId::USDC);
    }

    // Check from another reference
    {
        let guard = claimed.read().await;

        let is_1001_sage_claimed = guard
            .get(&1001)
            .map(|s| s.contains(&AssetId::SAGE))
            .unwrap_or(false);
        assert!(is_1001_sage_claimed);

        let is_1001_usdc_claimed = guard
            .get(&1001)
            .map(|s| s.contains(&AssetId::USDC))
            .unwrap_or(false);
        assert!(!is_1001_usdc_claimed);
    }
}

// =============================================================================
// Integration Tests: Full Payment Flow (Mock)
// =============================================================================

#[tokio::test]
async fn test_full_multi_asset_payment_flow() {
    // 1. Create worker key manager
    let worker_manager = WorkerKeyManager::new_from_secret(
        "test-worker",
        b"integration-test-secret",
        None,
    ).expect("Should create key manager");

    let worker_pk = worker_manager.public_key();

    // 2. Coordinator creates payments in different assets
    let payments: Vec<(u128, AssetId, u64)> = vec![
        (1001, AssetId::SAGE, 1000),
        (1002, AssetId::USDC, 500),
        (1003, AssetId::BTC, 100),
    ];

    // 3. Encrypt each payment
    let mut encrypted_payments: Vec<(u128, AssetId, ElGamalCiphertext)> = Vec::new();
    for (job_id, asset_id, amount) in &payments {
        let randomness = generate_test_randomness(*job_id as u64);
        let ciphertext = encrypt(*amount, &worker_pk, &randomness);
        encrypted_payments.push((*job_id, *asset_id, ciphertext));
    }

    // 4. Worker decrypts and verifies each payment
    let h = ECPoint::generator_h();
    for ((job_id, asset_id, expected_amount), (_, _, ciphertext)) in
        payments.iter().zip(encrypted_payments.iter())
    {
        let decrypted = worker_manager.decrypt_payment(ciphertext);
        let recovered = discrete_log_bsgs(&decrypted, &h, 10000);

        assert_eq!(
            recovered, Some(*expected_amount),
            "Job {} ({}) should decrypt to {}",
            job_id, asset_id.name(), expected_amount
        );
    }
}

#[tokio::test]
async fn test_payment_claim_deduplication() {
    let claimed: Arc<RwLock<HashMap<u128, HashSet<AssetId>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let pending: Arc<RwLock<VecDeque<(u128, AssetId)>>> =
        Arc::new(RwLock::new(VecDeque::new()));

    // Queue same payment twice (should be deduplicated)
    {
        let mut guard = pending.write().await;
        guard.push_back((1001, AssetId::SAGE));
        guard.push_back((1001, AssetId::SAGE)); // Duplicate
        guard.push_back((1001, AssetId::USDC)); // Different asset, same job - valid
    }

    // Process queue with deduplication
    let mut processed = Vec::new();
    while let Some((job_id, asset_id)) = pending.write().await.pop_front() {
        let already_claimed = claimed.read().await
            .get(&job_id)
            .map(|s| s.contains(&asset_id))
            .unwrap_or(false);

        if !already_claimed {
            // "Claim" the payment
            claimed.write().await
                .entry(job_id)
                .or_insert_with(HashSet::new)
                .insert(asset_id);
            processed.push((job_id, asset_id));
        }
    }

    // Should have processed 2 unique payments (SAGE once, USDC once)
    assert_eq!(processed.len(), 2);
    assert!(processed.contains(&(1001, AssetId::SAGE)));
    assert!(processed.contains(&(1001, AssetId::USDC)));
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_zero_amount_payment() {
    let keypair = generate_test_keypair(20);
    let randomness = generate_test_randomness(200);

    // Zero amount should still encrypt/decrypt correctly
    let encrypted = encrypt(0, &keypair.public_key, &randomness);

    let h = ECPoint::generator_h();
    let decrypted_point = decrypt_point(&encrypted, &keypair.secret_key);
    let recovered = discrete_log_bsgs(&decrypted_point, &h, 100);

    assert_eq!(recovered, Some(0));
}

#[test]
fn test_large_payment_amount() {
    let keypair = generate_test_keypair(21);
    let randomness = generate_test_randomness(201);

    // Large but reasonable payment (within BSGS range)
    let large_amount = 50000u64;
    let encrypted = encrypt(large_amount, &keypair.public_key, &randomness);

    let h = ECPoint::generator_h();
    let decrypted_point = decrypt_point(&encrypted, &keypair.secret_key);
    let recovered = discrete_log_bsgs(&decrypted_point, &h, 100000);

    assert_eq!(recovered, Some(large_amount));
}

#[test]
fn test_all_supported_assets() {
    let supported = [
        AssetId::SAGE,
        AssetId::USDC,
        AssetId::STRK,
        AssetId::BTC,
        AssetId::ETH,
    ];

    for asset in supported {
        // Each should have valid name and decimals
        assert!(!asset.name().is_empty());
        assert!(asset.decimals() > 0);

        // Should be usable as HashMap key
        let mut map: HashMap<AssetId, bool> = HashMap::new();
        map.insert(asset, true);
        assert_eq!(map.get(&asset), Some(&true));
    }
}

#[test]
fn test_asset_id_serialization() {
    // AssetId should serialize to its inner u64 value
    let sage = AssetId::SAGE;
    let serialized = serde_json::to_string(&sage).unwrap();
    assert_eq!(serialized, "0");

    let usdc = AssetId::USDC;
    let serialized = serde_json::to_string(&usdc).unwrap();
    assert_eq!(serialized, "1");
}

#[test]
fn test_asset_id_deserialization() {
    let sage: AssetId = serde_json::from_str("0").unwrap();
    assert_eq!(sage, AssetId::SAGE);

    let btc: AssetId = serde_json::from_str("3").unwrap();
    assert_eq!(btc, AssetId::BTC);
}
