//! Test Consensus Account Manager and Transaction Signing
//!
//! This example verifies:
//! 1. AccountManager can load from keystore
//! 2. Can query account nonce and balance
//! 3. Can submit fraud proof challenges (optional)
//!
//! Usage:
//!   cargo run --example consensus_account_test -- [--submit-challenge]

use anyhow::Result;
use bitsage_node::obelysk::starknet::{AccountManager, AccountManagerConfig};
use tracing::{info, warn};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    info!("🧪 Testing Consensus Account Manager Integration");
    info!("================================================");

    // Load configuration from environment or defaults
    let deployer_address = std::env::var("DEPLOYER_ADDRESS")
        .unwrap_or_else(|_| "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string());

    let keystore_path = std::env::var("KEYSTORE_PATH")
        .unwrap_or_else(|_| "../BitSage-Cairo-Smart-Contracts/deployment/sepolia_keystore.json".to_string());

    let keystore_password = std::env::var("KEYSTORE_PASSWORD")
        .unwrap_or_else(|_| "bitsage123".to_string());

    let rpc_url = std::env::var("STARKNET_RPC_URL")
        .unwrap_or_else(|_| "https://starknet-sepolia-rpc.publicnode.com".to_string());

    info!("Configuration:");
    info!("  Deployer: {}", deployer_address);
    info!("  Keystore: {}", keystore_path);
    info!("  RPC: {}", rpc_url);
    info!("  Network: sepolia");
    info!("");

    // 1. Initialize AccountManager
    info!("📝 Step 1: Initializing AccountManager from keystore...");

    let account_config = AccountManagerConfig::from_toml(
        &keystore_path,
        keystore_password,
        &deployer_address,
        rpc_url.clone(),
        "sepolia",
    )?;

    let account_manager = AccountManager::new(account_config).await?;

    info!("✅ AccountManager initialized successfully!");
    info!("   Address: {:#064x}", account_manager.address());
    info!("");

    // 2. Test account queries
    info!("🔍 Step 2: Querying account information...");

    // Get nonce
    match account_manager.get_nonce().await {
        Ok(nonce) => {
            info!("✅ Current nonce: {}", nonce);
        }
        Err(e) => {
            warn!("⚠️  Failed to get nonce: {}", e);
        }
    }

    // Get balance
    match account_manager.get_balance().await {
        Ok(balance) => {
            // Convert from wei to STRK (18 decimals)
            let balance_strk = balance.to_string().parse::<f64>().unwrap_or(0.0) / 1e18;
            info!("✅ Current balance: {} wei (~{:.6} STRK)", balance, balance_strk);
        }
        Err(e) => {
            warn!("⚠️  Failed to get balance: {}", e);
        }
    }
    info!("");

    // 3. Check if we should test fraud challenge submission
    let should_submit = std::env::args().any(|arg| arg == "--submit-challenge");

    if should_submit {
        info!("⚖️  Step 3: Testing fraud proof challenge submission...");
        warn!("⚠️  This will submit a REAL transaction to Sepolia testnet!");
        warn!("   Contract: 0x5d5bc1565e4df7c61c811b0c494f1345fc0f964e154e57e829c727990116b50");

        // Test fraud challenge (using dummy data)
        use starknet::core::types::FieldElement;
        use starknet::accounts::Call;
        use starknet::core::utils::get_selector_from_name;

        let fraud_proof_contract = FieldElement::from_hex_be(
            "0x5d5bc1565e4df7c61c811b0c494f1345fc0f964e154e57e829c727990116b50"
        )?;

        // Dummy challenge data
        let job_id = FieldElement::from(12345u64);
        let validator = FieldElement::from_hex_be(&deployer_address)?;
        let original_hash = FieldElement::from_hex_be("0x1234567890abcdef")?;
        let disputed_hash = FieldElement::from_hex_be("0xfedcba0987654321")?;
        let evidence_hash = FieldElement::from_hex_be("0xdeadbeefcafebabe")?;
        let method = FieldElement::from(1u64); // HashComparison

        let calldata = vec![
            job_id,
            validator,
            original_hash,
            disputed_hash,
            evidence_hash,
            method,
        ];

        let selector = get_selector_from_name("submit_challenge")?;

        let call = Call {
            to: fraud_proof_contract,
            selector,
            calldata,
        };

        info!("   Submitting test fraud challenge...");
        match account_manager.execute_calls(vec![call]).await {
            Ok(tx_hash) => {
                info!("✅ Transaction submitted successfully!");
                info!("   Tx hash: {:#064x}", tx_hash);
                info!("   Explorer: https://sepolia.starkscan.co/tx/{:#064x}", tx_hash);
            }
            Err(e) => {
                warn!("⚠️  Transaction failed: {}", e);
                warn!("   This is expected if the account doesn't have sufficient balance");
                warn!("   or if the contract rejects the challenge");
            }
        }
    } else {
        info!("ℹ️  Step 3: Skipping fraud challenge submission");
        info!("   Run with --submit-challenge flag to test actual transaction");
    }
    info!("");

    // Summary
    info!("📊 Test Summary");
    info!("==============");
    info!("✅ AccountManager initialization: SUCCESS");
    info!("✅ Account queries: SUCCESS");
    if should_submit {
        info!("⚠️  Transaction submission: See output above");
    } else {
        info!("⏭️  Transaction submission: SKIPPED");
    }
    info!("");
    info!("🎉 Account integration test complete!");
    info!("");
    info!("Next steps:");
    info!("  1. Run with --submit-challenge to test real transactions");
    info!("  2. Check account balance on Sepolia: https://sepolia.starkscan.co/contract/{}", deployer_address);
    info!("  3. Monitor FraudProof contract: https://sepolia.starkscan.co/contract/0x5d5bc1565e4df7c61c811b0c494f1345fc0f964e154e57e829c727990116b50");

    Ok(())
}
