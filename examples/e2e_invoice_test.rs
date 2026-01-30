//! # End-to-End Invoice Test
//!
//! Tests the complete proof-as-invoice pipeline:
//! 1. Create a job
//! 2. Execute with proof generation
//! 3. Generate compute invoice
//! 4. Verify locally
//! 5. Settle on-chain (if LIVE_MODE=true)
//!
//! Run with: cargo run --release --example e2e_invoice_test

use anyhow::Result;
use std::env;

use bitsage_node::compute::job_executor::{JobExecutor, JobExecutionRequest, JobRequirements};
use bitsage_node::coordinator::settlement::SettlementService;
use bitsage_node::obelysk::compute_invoice::verify_invoice_locally;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bitsage_node=info".parse()?)
        )
        .init();

    println!();
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  🧪 BitSage E2E Invoice Test - Production Pipeline");
    println!("═══════════════════════════════════════════════════════════════════");
    println!();

    // Get configuration from environment
    let wallet_address = env::var("WALLET_ADDRESS")
        .unwrap_or_else(|_| "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string());
    let live_mode = env::var("LIVE_MODE")
        .map(|v| v == "true")
        .unwrap_or(false);

    println!("📋 Configuration:");
    println!("   Wallet: {}...", &wallet_address[..20.min(wallet_address.len())]);
    println!("   Live Mode: {} {}", live_mode, if live_mode { "⚠️  REAL TRANSACTIONS" } else { "(dry run)" });
    println!();

    // =========================================================================
    // Step 1: Create Job Executor
    // =========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Step 1: Initialize Job Executor");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let executor = JobExecutor::with_config(
        "e2e-test-worker".to_string(),
        wallet_address.clone(),
        false, // has_tee
        true,  // enable_proofs
        true,  // use_gpu
        "NVIDIA H100".to_string(),
        "Enterprise".to_string(),
        200,   // $2.00/hour for H100
    );

    println!("   ✅ Executor initialized with proof generation enabled");
    println!();

    // =========================================================================
    // Step 2: Execute Ping Job with Proof
    // =========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Step 2: Execute Job with Proof Generation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let job_request = JobExecutionRequest {
        job_id: Some("e2e-test-001".to_string()),
        job_type: Some("Ping".to_string()),
        payload: b"E2E Test Payload".to_vec(),
        requirements: JobRequirements {
            min_vram_mb: 1024,
            min_gpu_count: 1,
            required_job_type: "Ping".to_string(),
            timeout_seconds: 60,
            requires_tee: false,
        },
        priority: 1,
        customer_pubkey: None,
    };

    println!("   📤 Submitting job: Ping");
    let result = executor.execute(job_request).await?;

    println!("   ✅ Job completed: {}", result.job_id);
    println!("   ⏱️  Execution time: {}ms", result.execution_time_ms);
    println!("   📊 Output hash: {}...", &result.output_hash[..16]);

    if let Some(ref proof_hash) = result.proof_hash {
        println!("   🔐 Proof hash: 0x{}...", hex::encode(&proof_hash[..8]));
    }
    if let Some(ref proof_size) = result.proof_size_bytes {
        println!("   📦 Proof size: {} bytes", proof_size);
    }
    if let Some(ref proof_time) = result.proof_time_ms {
        println!("   ⚡ Proof time: {}ms", proof_time);
    }
    println!();

    // =========================================================================
    // Step 3: Verify Invoice
    // =========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Step 3: Verify Compute Invoice");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if let Some(ref invoice) = result.invoice {
        println!("   📜 Invoice ID: {}", invoice.invoice_id);
        println!("   🏷️  Circuit Type: {:?}", invoice.circuit_type);
        println!("   💰 Total Cost: ${:.4}", invoice.total_cost_cents as f64 / 100.0);
        println!("   👷 Worker Payment: ${:.4} (80%)", invoice.worker_payment_cents as f64 / 100.0);
        println!("   🏛️  Protocol Fee: ${:.4} (20%)", invoice.protocol_fee_cents as f64 / 100.0);
        println!();
        println!("   SAGE Distribution:");
        let decimals = 1_000_000_000_000_000_000u128;
        println!("      Worker: {} SAGE", invoice.total_sage_payout / decimals);
        println!("      Burn:   {} SAGE (70% of fee)", invoice.sage_to_burn / decimals);
        println!("      Treasury: {} SAGE (20% of fee)", invoice.sage_to_treasury / decimals);
        println!("      Stakers: {} SAGE (10% of fee)", invoice.sage_to_stakers / decimals);
        println!();

        // Local verification
        match verify_invoice_locally(invoice) {
            Ok(_) => println!("   ✅ Invoice passed local verification"),
            Err(e) => println!("   ❌ Invoice failed verification: {}", e),
        }
    } else {
        println!("   ⚠️  No invoice generated (proof may have failed)");
    }
    println!();

    // =========================================================================
    // Step 4: Settlement
    // =========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Step 4: On-Chain Settlement");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if let Some(mut invoice) = result.invoice {
        if live_mode {
            println!("   ⛓️  LIVE MODE: Settling on Starknet Sepolia...");

            // Get private key from env
            let private_key = env::var("STARKNET_PRIVATE_KEY")
                .expect("STARKNET_PRIVATE_KEY required for live mode");
            let account_address = starknet::core::types::FieldElement::from_hex_be(&wallet_address)?;

            let settlement = SettlementService::for_sepolia(&private_key, account_address, true).await?;
            let record = settlement.settle_invoice(&mut invoice).await?;

            println!("   ✅ Settlement complete!");
            println!("   📝 Status: {:?}", record.status);
            if let Some(tx) = record.worker_transfer_tx {
                println!("   🔗 Worker TX: {}", tx);
            }
            if let Some(tx) = record.burn_tx {
                println!("   🔗 Burn TX: {}", tx);
            }
        } else {
            println!("   🔄 DRY RUN: Simulating settlement...");

            let settlement = SettlementService::read_only()?;
            let record = settlement.settle_invoice(&mut invoice).await?;

            println!("   ✅ Dry run complete!");
            println!("   📝 Status: {:?}", record.status);
            println!();
            println!("   To enable real settlement, set LIVE_MODE=true in .env");
        }
    }

    println!();
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  ✅ E2E Test Complete!");
    println!("═══════════════════════════════════════════════════════════════════");
    println!();

    Ok(())
}
