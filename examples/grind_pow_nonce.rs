//! Grind for a valid PoW nonce for STWO proof submission
//!
//! Run with: cargo run --example grind_pow_nonce --release

use starknet::core::types::FieldElement;
use starknet_crypto::{poseidon_hash, poseidon_hash_many};
use std::time::Instant;

type Felt = FieldElement;

/// Check if nonce satisfies PoW requirement
/// Contract computes:
/// 1. proof_hash = poseidon_hash_many([...proof_elements, nonce])
/// 2. pow_hash = poseidon_hash_many([proof_hash, nonce])  // Using span, not 2-to-1
/// 3. Checks pow_hash < threshold
fn check_pow(proof_elements: &[Felt], nonce: u64, difficulty_bits: u32) -> bool {
    let nonce_felt = Felt::from(nonce);

    // Build full proof with nonce at end
    let mut full_proof = proof_elements.to_vec();
    full_proof.push(nonce_felt);

    // Compute proof_hash = poseidon_hash_many(proof_with_nonce)
    let proof_hash = poseidon_hash_many(&full_proof);

    // Compute pow_hash = poseidon_hash_many([proof_hash, nonce])
    // NOTE: Cairo uses poseidon_hash_span which is equivalent to poseidon_hash_many
    let pow_hash = poseidon_hash_many(&[proof_hash, nonce_felt]);

    // Convert to big integer for comparison
    let hash_bytes = pow_hash.to_bytes_be();

    // Check leading zeros
    let leading_zero_bytes = difficulty_bits / 8;
    let remaining_bits = difficulty_bits % 8;

    for i in 0..leading_zero_bytes as usize {
        if hash_bytes[i] != 0 {
            return false;
        }
    }

    if remaining_bits > 0 {
        let mask = 0xFF << (8 - remaining_bits);
        if hash_bytes[leading_zero_bytes as usize] & mask != 0 {
            return false;
        }
    }

    true
}

fn main() {
    println!("=== STWO PoW Nonce Grinder (Correct Algorithm) ===\n");

    // M31-compliant proof elements (without nonce)
    let proof_elements: Vec<Felt> = vec![
        Felt::from(0x09cd58c2_u64), // trace commitment (M31 reduced)
        Felt::from(0x09cd58c2_u64), // composition commitment
        Felt::from(0x09cd58c2_u64), // FRI layer 0 commitment
        Felt::from(0x499602d2_u64), // alpha
        Felt::from(0x0d5454a2_u64),
        Felt::from(0x27bb29d4_u64),
        Felt::from(0x32523b20_u64),
        Felt::from(0x08688110_u64),
        Felt::from(0x137b78d0_u64),
        Felt::from(0x038736c9_u64),
        Felt::from(0x09cd58c2_u64),
        Felt::from(0x4996330b_u64),
        Felt::from(0x4aaa462f_u64),
        Felt::from(0x4a9681bf_u64),
        Felt::from(0x12493770_u64),
        Felt::from(0x40f86902_u64),
        Felt::from(0x2fe0c5f4_u64),
        Felt::from(0x036d3e5c_u64),
        Felt::from(0x09cd58c2_u64),
        Felt::from(0x49966344_u64),
        Felt::from(0x104931b6_u64),
        Felt::from(0x66d6e482_u64),
        Felt::from(0x09cd58c2_u64),
        Felt::from(0x4996937d_u64),
        Felt::from(0x2be1493f_u64),
        Felt::from(0x3d88092d_u64),
        Felt::from(0x574a5e80_u64),
        Felt::from(0x7fa7cca6_u64),
        Felt::from(0x09cd58c2_u64),
        Felt::from(0x4996c3b6_u64),
        Felt::from(0x430bacd8_u64),
        Felt::from(0x555b0378_u64),
        Felt::from(0x00000000_u64),
        Felt::from(0x00000000_u64),
        Felt::from(0x41f04a37_u64),
        Felt::from(0x41f04a37_u64),
        Felt::from(0x00000001_u64),
        Felt::from(0x00000000_u64),
        Felt::from(0x41f04a37_u64),
        Felt::from(0x41f04a37_u64),
        Felt::from(0x00000002_u64),
        Felt::from(0x00000000_u64),
        Felt::from(0x41f04a37_u64),
        Felt::from(0x41f04a37_u64),
        Felt::from(0x0000000b_u64),
        Felt::from(0x09ed19a7_u64),
        Felt::from(0x01cf8c09_u64),
        // Nonce NOT included here - will be appended during check
    ];

    println!("Proof elements (without nonce): {}", proof_elements.len());

    let difficulty_bits = 16u32;
    println!("Difficulty: {} bits ({} leading zeros)", difficulty_bits, difficulty_bits);
    println!("Expected iterations: ~{}", 1u64 << difficulty_bits);
    println!("\nGrinding (correct: nonce in proof_hash AND pow_hash)...\n");

    let start = Instant::now();
    let mut found_nonce: Option<u64> = None;

    for nonce in 1u64..10_000_000 {
        if check_pow(&proof_elements, nonce, difficulty_bits) {
            found_nonce = Some(nonce);
            break;
        }

        if nonce % 100_000 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let rate = nonce as f64 / elapsed;
            println!("  {:>8} iterations... ({:.0} hash/s)", nonce, rate);
        }
    }

    let elapsed = start.elapsed();

    if let Some(nonce) = found_nonce {
        println!("\n{}", "=".repeat(60));
        println!("FOUND VALID NONCE!");
        println!("{}\n", "=".repeat(60));

        let nonce_felt = Felt::from(nonce);

        // Build full proof with nonce
        let mut full_proof = proof_elements.clone();
        full_proof.push(nonce_felt);

        // Compute like the contract does
        let proof_hash = poseidon_hash_many(&full_proof);
        let pow_hash = poseidon_hash_many(&[proof_hash, nonce_felt]);

        println!("Nonce (decimal): {}", nonce);
        println!("Nonce (hex):     {:#066x}", nonce_felt);
        println!("Proof hash:      {:#066x}", proof_hash);
        println!("PoW hash:        {:#066x}", pow_hash);
        println!("Time elapsed:    {:.2}s", elapsed.as_secs_f64());
        println!("Hash rate:       {:.0} h/s", nonce as f64 / elapsed.as_secs_f64());

        // Output the complete proof array
        println!("\n{}", "=".repeat(60));
        println!("COMPLETE STARKLI COMMAND");
        println!("{}\n", "=".repeat(60));

        let total_elements = proof_elements.len() + 1;

        println!("starkli invoke \\");
        println!("    0x017ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b \\");
        println!("    verify_proof \\");
        println!("    4 0 \\"); // job_id = 4
        println!("    {} \\", total_elements);

        for elem in &proof_elements {
            println!("    {:#066x} \\", elem);
        }
        println!("    {:#066x} \\", nonce_felt);
        println!("    --account /tmp/account.json \\");
        println!("    --private-key 0x02c22c55e9c3aae8293e99a8b5d4ee1862595936f5f15f7d1f6ddcf8b216c44d \\");
        println!("    --rpc https://rpc.starknet-testnet.lava.build");
    } else {
        println!("\nNo valid nonce found after 10M iterations!");
    }
}
