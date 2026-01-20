// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Privacy System Integration Tests
// End-to-end tests for privacy features

use bitsage_node::obelysk::elgamal::{
    // Core types
    ECPoint, Felt252, KeyPair, EncryptedBalance,
    // Encryption functions
    encrypt, decrypt_point, discrete_log_bsgs,
    // Homomorphic operations
    homomorphic_add, homomorphic_sub,
    // Proofs
    create_schnorr_proof, verify_schnorr_proof,
    // AE Hints
    create_ae_hint, decrypt_ae_hint,
    encrypt_with_hint, decrypt_with_hint,
    // Ragequit
    create_ragequit_proof, verify_ragequit_proof, execute_ragequit,
    // Steganographic
    StegOperationType, create_steg_transaction, verify_steg_transaction,
    create_stealth_address, scan_steg_transactions,
    // Ring Signatures
    RingMember, compute_key_image, create_ring_signature, verify_ring_signature,
    create_confidential_ring_signature, verify_confidential_ring_signature,
    // View Keys
    derive_view_keypair, create_view_key_derivation_proof, verify_view_key_derivation_proof,
    create_threshold_disclosure, verify_threshold_disclosure,
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

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn create_ring_member(keypair: &KeyPair) -> RingMember {
    RingMember {
        public_key: keypair.public_key.clone(),
        stealth_address: None,
        amount_commitment: ECPoint::generator(),
        output_index: 0,
        block_height: 1000,
    }
}

// =============================================================================
// Feature 1: ElGamal Encryption Tests
// =============================================================================

#[test]
fn test_elgamal_encrypt_decrypt_roundtrip() {
    let keypair = generate_test_keypair(1);
    let amount = 1000u64;
    let randomness = generate_test_randomness(1);

    // Encrypt
    let ciphertext = encrypt(amount, &keypair.public_key, &randomness);

    // Decrypt to get M = amount * H
    let decrypted_point = decrypt_point(&ciphertext, &keypair.secret_key);

    // Use BSGS to recover amount
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted_point, &h, 10000);

    assert_eq!(recovered, Some(amount), "Decryption should recover original amount");
}

#[test]
fn test_elgamal_homomorphic_addition() {
    let keypair = generate_test_keypair(2);
    let amount1 = 500u64;
    let amount2 = 300u64;

    let ct1 = encrypt(amount1, &keypair.public_key, &generate_test_randomness(1));
    let ct2 = encrypt(amount2, &keypair.public_key, &generate_test_randomness(2));

    // Homomorphic add
    let ct_sum = homomorphic_add(&ct1, &ct2);

    // Decrypt sum
    let decrypted_point = decrypt_point(&ct_sum, &keypair.secret_key);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted_point, &h, 10000);

    assert_eq!(recovered, Some(amount1 + amount2), "Homomorphic addition failed");
}

#[test]
fn test_elgamal_homomorphic_subtraction() {
    let keypair = generate_test_keypair(3);
    let amount1 = 800u64;
    let amount2 = 300u64;

    let ct1 = encrypt(amount1, &keypair.public_key, &generate_test_randomness(3));
    let ct2 = encrypt(amount2, &keypair.public_key, &generate_test_randomness(4));

    let ct_diff = homomorphic_sub(&ct1, &ct2);

    let decrypted_point = decrypt_point(&ct_diff, &keypair.secret_key);
    let h = ECPoint::generator_h();
    let recovered = discrete_log_bsgs(&decrypted_point, &h, 10000);

    assert_eq!(recovered, Some(amount1 - amount2), "Homomorphic subtraction failed");
}

#[test]
fn test_schnorr_proof_valid() {
    let keypair = generate_test_keypair(4);
    let nonce = generate_test_randomness(5);
    let context = vec![Felt252::from_u64(123456)];

    let proof = create_schnorr_proof(
        &keypair.secret_key,
        &keypair.public_key,
        &nonce,
        &context,
    );

    assert!(
        verify_schnorr_proof(&keypair.public_key, &proof, &context),
        "Valid Schnorr proof should verify"
    );
}

#[test]
fn test_schnorr_proof_wrong_context_fails() {
    let keypair = generate_test_keypair(5);
    let nonce = generate_test_randomness(6);
    let context1 = vec![Felt252::from_u64(111111)];
    let context2 = vec![Felt252::from_u64(222222)];

    let proof = create_schnorr_proof(
        &keypair.secret_key,
        &keypair.public_key,
        &nonce,
        &context1,
    );

    assert!(
        !verify_schnorr_proof(&keypair.public_key, &proof, &context2),
        "Schnorr proof with wrong context should fail"
    );
}

// =============================================================================
// Feature 2: AE Hints Tests
// =============================================================================

#[test]
fn test_ae_hint_creation_and_decryption() {
    let keypair = generate_test_keypair(6);
    let amount = 1234u64;
    let nonce = 12345u64;

    // Create hint
    let hint = create_ae_hint(amount, &keypair.secret_key, nonce).unwrap();

    // Decrypt hint
    let decrypted = decrypt_ae_hint(&hint, &keypair.secret_key, nonce).unwrap();

    assert_eq!(decrypted, amount, "AE hint decryption failed");
}

#[test]
fn test_encrypt_with_hint_roundtrip() {
    let keypair = generate_test_keypair(7);
    let amount = 5678u64;
    let randomness = generate_test_randomness(7);
    let nonce = 67890u64;

    // Encrypt with hint
    let ct_with_hint = encrypt_with_hint(
        amount,
        &keypair.public_key,
        &keypair.secret_key,
        &randomness,
        nonce
    ).unwrap();

    // Decrypt with hint
    let decrypted = decrypt_with_hint(&ct_with_hint, &keypair.secret_key, nonce).unwrap();

    assert_eq!(decrypted, amount, "Encrypt/decrypt with hint roundtrip failed");
}

// =============================================================================
// Feature 3: Ragequit Tests
// =============================================================================

#[test]
fn test_ragequit_proof_creation() {
    let keypair = generate_test_keypair(10);
    let balance = 10000u64;
    let randomness = generate_test_randomness(10);
    let timestamp = current_timestamp();

    // Create encrypted balance
    let ciphertext = encrypt(balance, &keypair.public_key, &randomness);
    let encrypted_balance = EncryptedBalance::new(ciphertext, 0);

    let proof = create_ragequit_proof(
        &keypair,
        &encrypted_balance,
        balance,
        timestamp
    ).unwrap();

    assert!(
        verify_ragequit_proof(
            &proof,
            &keypair.public_key,
            &encrypted_balance,
            timestamp,
            3600 // 1 hour max age
        ),
        "Valid ragequit proof should verify"
    );
}

#[test]
fn test_ragequit_execution() {
    let keypair = generate_test_keypair(11);
    let balance = 5000u64;
    let randomness = generate_test_randomness(11);
    let timestamp = current_timestamp();

    // Create encrypted balance
    let ciphertext = encrypt(balance, &keypair.public_key, &randomness);
    let encrypted_balance = EncryptedBalance::new(ciphertext, 0);

    let proof = create_ragequit_proof(
        &keypair,
        &encrypted_balance,
        balance,
        timestamp
    ).unwrap();

    // Execute ragequit
    let result = execute_ragequit(&proof, &keypair, &encrypted_balance, timestamp);

    assert!(result.success, "Ragequit execution should succeed");
    assert_eq!(result.amount, balance, "Ragequit should return full balance");
}

// =============================================================================
// Feature 4: Steganographic Transactions Tests
// =============================================================================

#[test]
fn test_stealth_address_creation() {
    let recipient = generate_test_keypair(14);

    let result = create_stealth_address(&recipient.public_key);
    assert!(result.is_ok(), "Stealth address creation should succeed");

    let (stealth_addr, _ephemeral_secret) = result.unwrap();

    // Stealth address should be valid
    assert!(!stealth_addr.stealth_pubkey.is_infinity(), "Stealth pubkey should not be zero");
    assert!(!stealth_addr.ephemeral_pubkey.is_infinity(), "Ephemeral pubkey should not be zero");

    // Stealth address should be recognizable by recipient
    assert!(stealth_addr.belongs_to(&recipient), "Stealth address should belong to recipient");
}

#[test]
fn test_steg_transaction_creation() {
    let sender = generate_test_keypair(15);
    let recipient = generate_test_keypair(16);
    let amount = 2500u64;
    let randomness = generate_test_randomness(15);
    let timestamp = current_timestamp();

    // Create sender balance
    let sender_balance_amount = 10000u64;
    let sender_ciphertext = encrypt(sender_balance_amount, &sender.public_key, &randomness);
    let sender_balance = EncryptedBalance::new(sender_ciphertext, 0);

    let steg_tx = create_steg_transaction(
        StegOperationType::Transfer,
        &sender,
        &recipient.public_key,
        amount,
        &sender_balance,
        timestamp,
    ).unwrap();

    assert!(
        verify_steg_transaction(&steg_tx),
        "Valid steg transaction should verify"
    );
}

#[test]
fn test_steg_transaction_scanning() {
    let sender = generate_test_keypair(17);
    let recipient = generate_test_keypair(18);
    let other = generate_test_keypair(19);
    let amount = 3000u64;
    let randomness = generate_test_randomness(17);
    let timestamp = current_timestamp();

    // Create sender balance
    let sender_ciphertext = encrypt(10000u64, &sender.public_key, &randomness);
    let sender_balance = EncryptedBalance::new(sender_ciphertext, 0);

    let steg_tx = create_steg_transaction(
        StegOperationType::Transfer,
        &sender,
        &recipient.public_key,
        amount,
        &sender_balance,
        timestamp,
    ).unwrap();

    // First verify the receiver_stealth belongs to recipient
    assert!(
        steg_tx.receiver_stealth.belongs_to(&recipient),
        "Receiver stealth address should belong to recipient"
    );

    // Recipient should be able to scan and find their transaction
    let found = scan_steg_transactions(&[steg_tx.clone()], &recipient);
    assert!(!found.is_empty(), "Recipient should find their transaction");

    // Other party should not find it
    let not_found = scan_steg_transactions(&[steg_tx], &other);
    assert!(not_found.is_empty(), "Other party should not find the transaction");
}

// =============================================================================
// Feature 5: Ring Signatures Tests
// =============================================================================

#[test]
fn test_key_image_determinism() {
    let keypair = generate_test_keypair(20);

    let key_image1 = compute_key_image(&keypair.secret_key, &keypair.public_key);
    let key_image2 = compute_key_image(&keypair.secret_key, &keypair.public_key);

    // Same signer should produce same key image
    assert_eq!(key_image1.x, key_image2.x, "Key images should be deterministic (x)");
    assert_eq!(key_image1.y, key_image2.y, "Key images should be deterministic (y)");

    // Different signer should produce different key image
    let other = generate_test_keypair(21);
    let other_image = compute_key_image(&other.secret_key, &other.public_key);

    assert!(
        key_image1.x != other_image.x || key_image1.y != other_image.y,
        "Different signers should have different key images"
    );
}

#[test]
fn test_ring_signature_creation_and_verification() {
    // Create a ring of 4 members
    let signer = generate_test_keypair(22);
    let decoy1 = generate_test_keypair(23);
    let decoy2 = generate_test_keypair(24);
    let decoy3 = generate_test_keypair(25);

    let ring: Vec<RingMember> = vec![
        create_ring_member(&decoy1),
        create_ring_member(&signer),
        create_ring_member(&decoy2),
        create_ring_member(&decoy3),
    ];

    let message = Felt252::from_u64(12345678);
    let signer_index = 1; // Signer is at index 1

    // Extract public keys for ring signature (basic ring sig uses ECPoints)
    let public_keys: Vec<ECPoint> = ring.iter().map(|m| m.public_key).collect();

    let signature = create_ring_signature(
        &message,
        &public_keys,
        &signer.secret_key,
        signer_index,
    ).unwrap();

    assert!(
        verify_ring_signature(&message, &public_keys, &signature),
        "Valid ring signature should verify"
    );
}

#[test]
fn test_ring_signature_wrong_message_fails() {
    let signer = generate_test_keypair(26);
    let decoy = generate_test_keypair(27);

    let ring: Vec<RingMember> = vec![
        create_ring_member(&signer),
        create_ring_member(&decoy),
    ];

    let message = Felt252::from_u64(0xAAAA);
    let wrong_message = Felt252::from_u64(0xBBBB);

    // Extract public keys
    let public_keys: Vec<ECPoint> = ring.iter().map(|m| m.public_key).collect();

    let signature = create_ring_signature(&message, &public_keys, &signer.secret_key, 0).unwrap();

    assert!(
        !verify_ring_signature(&wrong_message, &public_keys, &signature),
        "Ring signature with wrong message should fail"
    );
}

#[test]
fn test_confidential_ring_signature() {
    let signer = generate_test_keypair(28);
    let decoy1 = generate_test_keypair(29);
    let decoy2 = generate_test_keypair(30);

    let ring: Vec<RingMember> = vec![
        create_ring_member(&signer),
        create_ring_member(&decoy1),
        create_ring_member(&decoy2),
    ];

    let amount = 1000u64;
    let randomness = generate_test_randomness(28);
    let message = Felt252::from_u64(0xC0FFEE);

    let signature = create_confidential_ring_signature(
        &message,
        &ring,
        &signer.secret_key,
        0,
        amount,
        &randomness,
    ).unwrap();

    assert!(
        verify_confidential_ring_signature(&message, &ring, &signature),
        "Valid confidential ring signature should verify"
    );
}

// =============================================================================
// Feature 8: View Keys Tests
// =============================================================================

#[test]
fn test_view_key_derivation() {
    let master_keypair = generate_test_keypair(59);
    let view_keypair = derive_view_keypair(&master_keypair);

    // View key should be different from master key
    assert_ne!(
        view_keypair.view_secret_key, master_keypair.secret_key,
        "View key should differ from master key"
    );

    // View public key should match master public key reference
    assert_eq!(
        view_keypair.master_public_key, master_keypair.public_key,
        "Master public key should be preserved"
    );
}

#[test]
fn test_view_key_derivation_proof() {
    let master_keypair = generate_test_keypair(60);
    let view_keypair = derive_view_keypair(&master_keypair);

    let proof = create_view_key_derivation_proof(&master_keypair, &view_keypair).unwrap();

    assert!(
        verify_view_key_derivation_proof(
            &master_keypair.public_key,
            &view_keypair.view_public_key,
            &proof
        ),
        "Valid view key derivation proof should verify"
    );
}

#[test]
fn test_threshold_disclosure() {
    let master_keypair = generate_test_keypair(63);
    let view_keypair = derive_view_keypair(&master_keypair);
    let amount = 10000u64;
    let threshold = 5000u64;
    let randomness = generate_test_randomness(63);

    // Encrypt to view public key so view_decrypt can decrypt it
    let ciphertext = encrypt(amount, &view_keypair.view_public_key, &randomness);

    // Create disclosure proving amount > threshold
    let disclosure = create_threshold_disclosure(
        &ciphertext,
        &view_keypair,
        threshold,
    ).unwrap();

    assert!(
        verify_threshold_disclosure(&view_keypair.view_public_key, &disclosure),
        "Valid threshold disclosure should verify"
    );
    assert!(disclosure.is_above, "Amount {} should be above threshold {}", amount, threshold);
}

#[test]
fn test_view_key_cannot_create_valid_schnorr() {
    let master_keypair = generate_test_keypair(65);
    let view_keypair = derive_view_keypair(&master_keypair);

    let nonce = generate_test_randomness(65);
    let context = vec![Felt252::from_u64(999999)];

    // Create Schnorr proof with view secret key
    let proof = create_schnorr_proof(
        &view_keypair.view_secret_key,
        &master_keypair.public_key, // Using master pubkey!
        &nonce,
        &context,
    );

    // This should NOT verify because view_secret * G != master_public_key
    assert!(
        !verify_schnorr_proof(&master_keypair.public_key, &proof, &context),
        "Schnorr proof with view key should not verify against master pubkey"
    );
}

// =============================================================================
// End-to-End Integration Tests
// =============================================================================

#[test]
fn test_full_privacy_flow() {
    let timestamp = current_timestamp();

    // 1. Setup: Create accounts
    let alice = generate_test_keypair(100);
    let bob = generate_test_keypair(101);

    // 2. Alice deposits and gets encrypted balance with AE hint
    let deposit_amount = 10000u64;
    let deposit_randomness = generate_test_randomness(100);
    let alice_ciphertext = encrypt(deposit_amount, &alice.public_key, &deposit_randomness);
    let alice_hint = create_ae_hint(deposit_amount, &alice.secret_key, 100).unwrap();

    // 3. Alice can decrypt her balance via hint
    let alice_balance = decrypt_ae_hint(&alice_hint, &alice.secret_key, 100).unwrap();
    assert_eq!(alice_balance, deposit_amount);

    // 4. Alice creates a private transfer to Bob using ring signature
    let decoy1 = generate_test_keypair(103);
    let decoy2 = generate_test_keypair(104);

    let ring: Vec<RingMember> = vec![
        create_ring_member(&alice),
        create_ring_member(&decoy1),
        create_ring_member(&decoy2),
    ];

    let transfer_message = Felt252::from_u64(0xDEADBEEF);
    let public_keys: Vec<ECPoint> = ring.iter().map(|m| m.public_key).collect();
    let ring_sig = create_ring_signature(&transfer_message, &public_keys, &alice.secret_key, 0).unwrap();
    assert!(verify_ring_signature(&transfer_message, &public_keys, &ring_sig));

    // 5. Bob receives funds with steg transaction for extra privacy
    let transfer_amount = 3000u64;
    let encrypted_balance = EncryptedBalance::new(alice_ciphertext.clone(), 0);

    let steg_tx = create_steg_transaction(
        StegOperationType::Transfer,
        &alice,
        &bob.public_key,
        transfer_amount,
        &encrypted_balance,
        timestamp,
    ).unwrap();
    assert!(verify_steg_transaction(&steg_tx));

    // 6. Create view key for auditing
    let alice_view_key = derive_view_keypair(&alice);

    // For threshold disclosure, we need a ciphertext encrypted to the view public key
    // (view_decrypt uses view_secret_key, so it needs matching encryption)
    let view_randomness = generate_test_randomness(106);
    let view_ciphertext = encrypt(deposit_amount, &alice_view_key.view_public_key, &view_randomness);

    // Verify Alice's balance is above compliance threshold
    let threshold_proof = create_threshold_disclosure(
        &view_ciphertext,
        &alice_view_key,
        1000u64, // Minimum required balance
    ).unwrap();

    assert!(verify_threshold_disclosure(&alice_view_key.view_public_key, &threshold_proof));

    // 7. If Alice needs emergency exit, she can ragequit
    let ragequit_proof = create_ragequit_proof(
        &alice,
        &encrypted_balance,
        deposit_amount,
        timestamp
    ).unwrap();
    assert!(verify_ragequit_proof(
        &ragequit_proof,
        &alice.public_key,
        &encrypted_balance,
        timestamp,
        3600
    ));
}
