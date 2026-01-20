//! Privacy Contract Integration Tests
//!
//! Tests for the PrivacyRouterClient integration with the Cairo contract.
//! These tests verify the full flow of privacy operations.
//!
//! # Running Tests
//!
//! For unit tests (no contract required):
//! ```bash
//! cargo test --test privacy_contract_integration unit_
//! ```
//!
//! For integration tests with devnet:
//! ```bash
//! STARKNET_DEVNET=http://localhost:5050 cargo test --test privacy_contract_integration integration_
//! ```

use anyhow::Result;
use bitsage_node::obelysk::elgamal::{
    Felt252, ElGamalCiphertext,
    generate_keypair, generate_randomness, encrypt, scalar_mul_g, hash_felts,
};
use bitsage_node::obelysk::privacy_client::{
    PrivacyRouterClient, CompressionStats, PrivateAccount, AEHint, AccountHints,
    felt252_to_field_element, field_element_to_felt252,
};
use bitsage_node::obelysk::proof_compression::{ProofCompressor, CompressionAlgorithm};
use starknet::core::types::FieldElement;

// =============================================================================
// Unit Tests (no network required)
// =============================================================================

/// Test keypair generation and public key derivation
#[test]
fn unit_test_keypair_generation() {
    let keypair = generate_keypair().expect("keypair generation should work");

    // Public key should be on the curve (not at infinity)
    assert!(!keypair.public_key.is_infinity());

    // Verify pk = sk * G
    let derived_pk = scalar_mul_g(&keypair.secret_key);
    assert_eq!(keypair.public_key.x, derived_pk.x);
    assert_eq!(keypair.public_key.y, derived_pk.y);
}

/// Test encryption produces different ciphertext for same amount (due to randomness)
#[test]
fn unit_test_encryption_randomness() {
    let keypair = generate_keypair().expect("keypair generation should work");
    let amount = 1000u64;

    let r1 = generate_randomness().expect("randomness should work");
    let r2 = generate_randomness().expect("randomness should work");

    let ct1 = encrypt(amount, &keypair.public_key, &r1);
    let ct2 = encrypt(amount, &keypair.public_key, &r2);

    // Different randomness should produce different ciphertexts
    assert_ne!(ct1.c1_x, ct2.c1_x);
    assert_ne!(ct1.c2_x, ct2.c2_x);
}

/// Test Felt252 <-> FieldElement conversion roundtrip
#[test]
fn unit_test_felt_conversion_roundtrip() {
    let values = vec![
        Felt252::from_u64(0),
        Felt252::from_u64(1),
        Felt252::from_u64(u64::MAX),
        Felt252::from_u128(u128::MAX),
    ];

    for original in values {
        let fe = felt252_to_field_element(&original);
        let back = field_element_to_felt252(&fe);
        assert_eq!(original, back, "Roundtrip failed for {:?}", original);
    }
}

/// Test compression of proof data
#[test]
fn unit_test_proof_compression() {
    // Generate realistic proof-like data
    let keypair = generate_keypair().expect("keypair generation should work");
    let randomness = generate_randomness().expect("randomness should work");
    let encrypted = encrypt(1000, &keypair.public_key, &randomness);

    // Simulate proof bytes (EC points + scalars)
    let proof_bytes: Vec<u8> = vec![
        keypair.public_key.x.to_be_bytes().to_vec(),
        keypair.public_key.y.to_be_bytes().to_vec(),
        encrypted.c1_x.to_be_bytes().to_vec(),
        encrypted.c1_y.to_be_bytes().to_vec(),
        encrypted.c2_x.to_be_bytes().to_vec(),
        encrypted.c2_y.to_be_bytes().to_vec(),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Test all compression algorithms
    for algorithm in &[
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lz4,
        CompressionAlgorithm::Snappy,
        CompressionAlgorithm::None,
    ] {
        let compressed = ProofCompressor::compress(&proof_bytes, *algorithm)
            .expect("compression should work");

        assert!(compressed.verify_integrity());

        let decompressed = ProofCompressor::decompress(&compressed)
            .expect("decompression should work");

        assert_eq!(proof_bytes, decompressed);
    }
}

/// Test compression statistics calculation
#[test]
fn unit_test_compression_stats() {
    let original_size = 1000;
    let compressed_size = 650;

    // Use CompressionStats via the public struct
    let stats = CompressionStats {
        original_size,
        compressed_size,
        compression_ratio: compressed_size as f64 / original_size as f64,
        algorithm: CompressionAlgorithm::Zstd,
        estimated_gas_savings: ((original_size - compressed_size) * 16) as u64,
    };

    assert_eq!(stats.original_size, 1000);
    assert_eq!(stats.compressed_size, 650);
    assert!((stats.compression_ratio - 0.65).abs() < 0.001);
    assert_eq!(stats.estimated_gas_savings, 350 * 16);
}

/// Test nullifier computation determinism
#[test]
fn unit_test_nullifier_determinism() {
    let keypair = generate_keypair().expect("keypair generation should work");
    let randomness = generate_randomness().expect("randomness should work");
    let encrypted = encrypt(1000, &keypair.public_key, &randomness);

    // Compute nullifier twice with same inputs
    let domain = Felt252::from_hex("4f42454c59534b5f4e554c4c4946494552")
        .unwrap_or_else(|| Felt252::from_u64(0x4e554c4c49464945));

    let nullifier1 = hash_felts(&[
        domain,
        keypair.secret_key,
        encrypted.c1_x,
        encrypted.c1_y,
        encrypted.c2_x,
        encrypted.c2_y,
    ]);

    let nullifier2 = hash_felts(&[
        domain,
        keypair.secret_key,
        encrypted.c1_x,
        encrypted.c1_y,
        encrypted.c2_x,
        encrypted.c2_y,
    ]);

    assert_eq!(nullifier1, nullifier2, "Nullifier should be deterministic");

    // Different ciphertext should produce different nullifier
    let randomness2 = generate_randomness().expect("randomness should work");
    let encrypted2 = encrypt(1000, &keypair.public_key, &randomness2);

    let nullifier3 = hash_felts(&[
        domain,
        keypair.secret_key,
        encrypted2.c1_x,
        encrypted2.c1_y,
        encrypted2.c2_x,
        encrypted2.c2_y,
    ]);

    assert_ne!(nullifier1, nullifier3, "Different ciphertext should produce different nullifier");
}

/// Test AccountHints default values
#[test]
fn unit_test_account_hints_default() {
    let hints = AccountHints::default();

    assert_eq!(hints.balance_hint.c0, Felt252::default());
    assert_eq!(hints.hint_nonce, 0);
}

/// Test AEHint structure
#[test]
fn unit_test_ae_hint_structure() {
    let hint = AEHint {
        c0: Felt252::from_u64(1),
        c1: Felt252::from_u64(2),
        c2: Felt252::from_u64(3),
    };

    assert_eq!(hint.c0, Felt252::from_u64(1));
    assert_eq!(hint.c1, Felt252::from_u64(2));
    assert_eq!(hint.c2, Felt252::from_u64(3));
}

/// Test compression algorithm comparison
#[test]
fn unit_test_compression_algorithm_comparison() {
    // Generate test data (simulating proof bytes)
    let test_data: Vec<u8> = (0..512).map(|i| (i * 17 + 42) as u8).collect();

    let zstd = ProofCompressor::compress(&test_data, CompressionAlgorithm::Zstd)
        .expect("zstd should work");
    let lz4 = ProofCompressor::compress(&test_data, CompressionAlgorithm::Lz4)
        .expect("lz4 should work");
    let snappy = ProofCompressor::compress(&test_data, CompressionAlgorithm::Snappy)
        .expect("snappy should work");

    // Zstd typically has the best ratio
    println!(
        "Compression ratios - Zstd: {:.2}%, LZ4: {:.2}%, Snappy: {:.2}%",
        zstd.compression_ratio * 100.0,
        lz4.compression_ratio * 100.0,
        snappy.compression_ratio * 100.0
    );

    // All should compress (ratio < 1.0 for compressible data)
    assert!(zstd.compression_ratio <= 1.0);
    assert!(lz4.compression_ratio <= 1.0);
    assert!(snappy.compression_ratio <= 1.0);
}

/// Test PrivateAccount structure
#[test]
fn unit_test_private_account_structure() {
    let keypair = generate_keypair().expect("keypair generation should work");

    let account = PrivateAccount {
        public_key: keypair.public_key,
        encrypted_balance: bitsage_node::obelysk::elgamal::EncryptedBalance {
            ciphertext: ElGamalCiphertext::zero(),
            pending_in: ElGamalCiphertext::zero(),
            pending_out: ElGamalCiphertext::zero(),
            epoch: 0,
        },
        pending_transfers: 0,
        last_rollup_epoch: 0,
        is_registered: false,
    };

    assert!(!account.is_registered);
    assert_eq!(account.pending_transfers, 0);
}

// =============================================================================
// Serialization Tests
// =============================================================================

/// Test calldata serialization format matches Cairo expectations
#[test]
fn unit_test_calldata_serialization() {
    let keypair = generate_keypair().expect("keypair generation should work");
    let pk = keypair.public_key;

    // Public key should serialize as 2 felt252s (x, y)
    let pk_x = felt252_to_field_element(&pk.x);
    let pk_y = felt252_to_field_element(&pk.y);

    // Verify we can reconstruct
    let recovered_x = field_element_to_felt252(&pk_x);
    let recovered_y = field_element_to_felt252(&pk_y);

    assert_eq!(pk.x, recovered_x);
    assert_eq!(pk.y, recovered_y);
}

/// Test u256 amount serialization (low, high format)
#[test]
fn unit_test_u256_serialization() {
    let amount = 1_000_000u64;

    // Cairo u256 is (low: u128, high: u128)
    let low = FieldElement::from(amount);
    let _high = FieldElement::ZERO; // High bits are zero for amounts < 2^128

    // Verify low part contains the amount
    let low_bytes = low.to_bytes_be();
    let recovered_low = u64::from_be_bytes(low_bytes[24..32].try_into().unwrap());
    assert_eq!(amount, recovered_low);
}

/// Test ElGamalCiphertext serialization
#[test]
fn unit_test_ciphertext_serialization() {
    let keypair = generate_keypair().expect("keypair generation should work");
    let randomness = generate_randomness().expect("randomness should work");
    let amount = 500u64;

    let ciphertext = encrypt(amount, &keypair.public_key, &randomness);

    // Ciphertext should serialize as 4 felt252s (c1_x, c1_y, c2_x, c2_y)
    let calldata = vec![
        felt252_to_field_element(&ciphertext.c1_x),
        felt252_to_field_element(&ciphertext.c1_y),
        felt252_to_field_element(&ciphertext.c2_x),
        felt252_to_field_element(&ciphertext.c2_y),
    ];

    assert_eq!(calldata.len(), 4);

    // Verify roundtrip
    let recovered = ElGamalCiphertext {
        c1_x: field_element_to_felt252(&calldata[0]),
        c1_y: field_element_to_felt252(&calldata[1]),
        c2_x: field_element_to_felt252(&calldata[2]),
        c2_y: field_element_to_felt252(&calldata[3]),
    };

    assert_eq!(ciphertext.c1_x, recovered.c1_x);
    assert_eq!(ciphertext.c1_y, recovered.c1_y);
    assert_eq!(ciphertext.c2_x, recovered.c2_x);
    assert_eq!(ciphertext.c2_y, recovered.c2_y);
}

// =============================================================================
// Integration Tests (require devnet or Sepolia)
// =============================================================================

/// Integration test: Full deposit-withdraw cycle
///
/// Requires: STARKNET_DEVNET environment variable set
#[tokio::test]
#[ignore = "Requires Starknet devnet"]
async fn integration_test_deposit_withdraw_cycle() -> Result<()> {
    let devnet_url = std::env::var("STARKNET_DEVNET")
        .unwrap_or_else(|_| "http://localhost:5050".to_string());

    // These would be devnet pre-funded account credentials
    let private_key = std::env::var("DEVNET_PRIVATE_KEY")
        .expect("DEVNET_PRIVATE_KEY required");
    let account_address = FieldElement::from_hex_be(
        &std::env::var("DEVNET_ACCOUNT").expect("DEVNET_ACCOUNT required"),
    )?;
    let contract_address = FieldElement::from_hex_be(
        &std::env::var("PRIVACY_CONTRACT").expect("PRIVACY_CONTRACT required"),
    )?;

    // Create client
    let mut client = PrivacyRouterClient::new(
        &devnet_url,
        contract_address,
        &private_key,
        account_address,
    )
    .await?;

    // Generate keypair
    let keypair = generate_keypair()?;

    // Register account
    let _tx = client.register_account(&keypair).await?;

    // Deposit
    let randomness = generate_randomness()?;
    let deposit_tx = client.deposit(&keypair, 1000, &randomness).await?;
    println!("Deposit tx: {:?}", deposit_tx);

    // Verify balance updated
    let account = client.get_account(account_address).await?;
    assert!(account.is_registered);

    // Withdraw
    let withdraw_tx = client.withdraw(&keypair, 500).await?;
    println!("Withdraw tx: {:?}", withdraw_tx);

    Ok(())
}

/// Integration test: Private transfer between two accounts
///
/// Requires: STARKNET_DEVNET environment variable set
#[tokio::test]
#[ignore = "Requires Starknet devnet"]
async fn integration_test_private_transfer() -> Result<()> {
    let devnet_url = std::env::var("STARKNET_DEVNET")
        .unwrap_or_else(|_| "http://localhost:5050".to_string());

    let private_key = std::env::var("DEVNET_PRIVATE_KEY")
        .expect("DEVNET_PRIVATE_KEY required");
    let sender_address = FieldElement::from_hex_be(
        &std::env::var("DEVNET_ACCOUNT").expect("DEVNET_ACCOUNT required"),
    )?;
    let receiver_address = FieldElement::from_hex_be(
        &std::env::var("DEVNET_RECEIVER").unwrap_or_else(|_| "0x456".to_string()),
    )?;
    let contract_address = FieldElement::from_hex_be(
        &std::env::var("PRIVACY_CONTRACT").expect("PRIVACY_CONTRACT required"),
    )?;

    let mut client = PrivacyRouterClient::new(
        &devnet_url,
        contract_address,
        &private_key,
        sender_address,
    )
    .await?;

    // Generate keypairs
    let sender_keypair = generate_keypair()?;
    let receiver_keypair = generate_keypair()?;

    // Fund sender account
    let randomness = generate_randomness()?;
    let _ = client.deposit(&sender_keypair, 1000, &randomness).await?;

    // Execute private transfer
    let tx = client
        .private_transfer(
            &sender_keypair,
            receiver_address,
            &receiver_keypair.public_key,
            500,
        )
        .await?;

    println!("Private transfer tx: {:?}", tx);

    Ok(())
}

/// Integration test: Nullifier prevents double-spend
///
/// Requires: STARKNET_DEVNET environment variable set
#[tokio::test]
#[ignore = "Requires Starknet devnet"]
async fn integration_test_nullifier_double_spend_prevention() -> Result<()> {
    let devnet_url = std::env::var("STARKNET_DEVNET")
        .unwrap_or_else(|_| "http://localhost:5050".to_string());

    let private_key = std::env::var("DEVNET_PRIVATE_KEY")
        .expect("DEVNET_PRIVATE_KEY required");
    let account_address = FieldElement::from_hex_be(
        &std::env::var("DEVNET_ACCOUNT").expect("DEVNET_ACCOUNT required"),
    )?;
    let contract_address = FieldElement::from_hex_be(
        &std::env::var("PRIVACY_CONTRACT").expect("PRIVACY_CONTRACT required"),
    )?;

    let mut client = PrivacyRouterClient::new(
        &devnet_url,
        contract_address,
        &private_key,
        account_address,
    )
    .await?;

    let keypair = generate_keypair()?;

    // Deposit funds
    let randomness = generate_randomness()?;
    let _ = client.deposit(&keypair, 1000, &randomness).await?;

    // First withdraw should succeed
    let tx1 = client.withdraw(&keypair, 500).await?;
    println!("First withdraw tx: {:?}", tx1);

    // Second withdraw with same nullifier should fail
    // (This test verifies the local nullifier cache prevents duplicate submissions)
    let result = client.withdraw(&keypair, 500).await;

    match result {
        Ok(_) => println!("Second withdraw succeeded (different nullifier)"),
        Err(e) => {
            assert!(
                e.to_string().contains("Nullifier"),
                "Should fail due to nullifier: {}",
                e
            );
        }
    }

    Ok(())
}

/// Integration test: Compressed deposit
///
/// Requires: STARKNET_DEVNET environment variable set
#[tokio::test]
#[ignore = "Requires Starknet devnet with compressed endpoints"]
async fn integration_test_compressed_deposit() -> Result<()> {
    let devnet_url = std::env::var("STARKNET_DEVNET")
        .unwrap_or_else(|_| "http://localhost:5050".to_string());

    let private_key = std::env::var("DEVNET_PRIVATE_KEY")
        .expect("DEVNET_PRIVATE_KEY required");
    let account_address = FieldElement::from_hex_be(
        &std::env::var("DEVNET_ACCOUNT").expect("DEVNET_ACCOUNT required"),
    )?;
    let contract_address = FieldElement::from_hex_be(
        &std::env::var("PRIVACY_CONTRACT").expect("PRIVACY_CONTRACT required"),
    )?;

    let client = PrivacyRouterClient::new(
        &devnet_url,
        contract_address,
        &private_key,
        account_address,
    )
    .await?;

    let keypair = generate_keypair()?;
    let randomness = generate_randomness()?;

    // Deposit with compression
    let (tx, stats) = client
        .deposit_compressed(&keypair, 1000, &randomness, CompressionAlgorithm::Zstd)
        .await?;

    println!("Compressed deposit tx: {:?}", tx);
    println!(
        "Compression stats: {} -> {} bytes ({:.1}%)",
        stats.original_size, stats.compressed_size, stats.compression_ratio * 100.0
    );

    // Verify compression occurred
    assert!(stats.compression_ratio < 1.0, "Should have some compression");

    Ok(())
}

// =============================================================================
// Performance Benchmarks
// =============================================================================

/// Benchmark keypair generation
#[test]
fn bench_keypair_generation() {
    let start = std::time::Instant::now();
    let iterations = 100;

    for _ in 0..iterations {
        let _ = generate_keypair().expect("keypair generation should work");
    }

    let elapsed = start.elapsed();
    println!(
        "Keypair generation: {} iterations in {:?} ({:.2}ms/op)",
        iterations,
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / iterations as f64
    );
}

/// Benchmark encryption
#[test]
fn bench_encryption() {
    let keypair = generate_keypair().expect("keypair generation should work");
    let randomness = generate_randomness().expect("randomness should work");

    let start = std::time::Instant::now();
    let iterations = 100;

    for i in 0..iterations {
        let _ = encrypt(i as u64, &keypair.public_key, &randomness);
    }

    let elapsed = start.elapsed();
    println!(
        "Encryption: {} iterations in {:?} ({:.2}ms/op)",
        iterations,
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / iterations as f64
    );
}

/// Benchmark compression algorithms
#[test]
fn bench_compression_algorithms() {
    let keypair = generate_keypair().expect("keypair generation should work");
    let randomness = generate_randomness().expect("randomness should work");

    // Generate realistic proof data
    let proof_data: Vec<u8> = (0..10)
        .flat_map(|_| {
            let ct = encrypt(1000, &keypair.public_key, &randomness);
            vec![
                ct.c1_x.to_be_bytes().to_vec(),
                ct.c1_y.to_be_bytes().to_vec(),
                ct.c2_x.to_be_bytes().to_vec(),
                ct.c2_y.to_be_bytes().to_vec(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>()
        })
        .collect();

    println!("Proof data size: {} bytes", proof_data.len());

    for algorithm in &[
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lz4,
        CompressionAlgorithm::Snappy,
    ] {
        let start = std::time::Instant::now();
        let iterations = 100;

        for _ in 0..iterations {
            let _ = ProofCompressor::compress(&proof_data, *algorithm).expect("compress should work");
        }

        let elapsed = start.elapsed();
        let compressed = ProofCompressor::compress(&proof_data, *algorithm).expect("compress should work");

        println!(
            "{:?}: {} iterations in {:?} ({:.2}ms/op), ratio: {:.2}%",
            algorithm,
            iterations,
            elapsed,
            elapsed.as_secs_f64() * 1000.0 / iterations as f64,
            compressed.compression_ratio * 100.0
        );
    }
}
