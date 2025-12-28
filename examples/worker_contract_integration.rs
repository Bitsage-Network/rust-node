// Worker-Contract Integration Example
// Demonstrates end-to-end flow: Execute job → Submit to contract

use bitsage_node::obelysk::{ObelyskVM, OpCode, Instruction, M31, Matrix, MockTEEGenerator, TEEType};
use bitsage_node::blockchain::{WorkerBridge, hash_matrix_result};
use bitsage_node::types::JobId;
use starknet::core::types::FieldElement;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║     Worker-Contract Integration Demo                         ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // ═════════════════════════════════════════════════════════════════
    // STEP 1: Execute ML Inference Job
    // ═════════════════════════════════════════════════════════════════
    println!("📊 Step 1: Executing ML inference job locally...\n");

    let mut vm = ObelyskVM::new();

    // Weight matrix W (2x3)
    let weights = Matrix::from_data(2, 3, vec![
        M31::new(1), M31::new(2), M31::new(3),
        M31::new(4), M31::new(5), M31::new(6),
    ])?;

    // Input vector x (3x1)
    let input = Matrix::from_data(3, 1, vec![
        M31::new(1), M31::new(2), M31::new(3)
    ])?;

    vm.write_matrix(100, &weights);
    vm.write_matrix(200, &input);

    let program = vec![
        Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(100)), address: None },
        Instruction { opcode: OpCode::LoadImm, dst: 1, src1: 0, src2: 0, immediate: Some(M31::new(200)), address: None },
        Instruction { opcode: OpCode::LoadImm, dst: 2, src1: 0, src2: 0, immediate: Some(M31::new(300)), address: None },
        Instruction { opcode: OpCode::MatMul, dst: 2, src1: 0, src2: 1, immediate: None, address: None },
        Instruction { opcode: OpCode::Halt, dst: 0, src1: 0, src2: 0, immediate: None, address: None },
    ];

    vm.load_program(program);
    let _trace = vm.execute()?;

    let result = vm.read_matrix(300)?;
    println!("  Result: [{}, {}]", result.get(0, 0).unwrap().value(), result.get(1, 0).unwrap().value());
    println!("  ✅ Execution complete\n");

    // ═════════════════════════════════════════════════════════════════
    // STEP 2: Generate TEE Quote
    // ═════════════════════════════════════════════════════════════════
    println!("🔒 Step 2: Generating TEE attestation quote...\n");

    let tee_generator = MockTEEGenerator::new(TEEType::IntelTDX);
    let result_hash_bytes = hash_matrix_result(&result);
    let tee_quote = tee_generator.generate_quote(&result_hash_bytes.to_bytes_be());

    println!("  Quote generated:");
    println!("    MRENCLAVE: {}...", hex::encode(&tee_quote.mrenclave[..8]));
    println!("    Signature: {} bytes", tee_quote.signature.len());
    println!("  ✅ TEE attestation ready\n");

    // ═════════════════════════════════════════════════════════════════
    // STEP 3: Submit to OptimisticTEE Contract
    // ═════════════════════════════════════════════════════════════════
    println!("⛓️  Step 3: Submitting result to Starknet contract...\n");

    // NOTE: For this demo, we'll show the structure without actual deployment
    // In production, you'd provide real RPC URL, private key, etc.
    
    let demo_mode = true;
    
    if demo_mode {
        println!("  [DEMO MODE - No actual transaction]");
        println!("  Would submit:");
        println!("    Job ID: {}", Uuid::new_v4());
        println!("    Result Hash: 0x{}", hex::encode(result_hash_bytes.to_bytes_be()));
        println!("    Worker ID: 0x123...");
        println!("    TEE Quote: {} bytes", tee_quote.signature.len());
        println!("\n  To enable real submission:");
        println!("    1. Deploy contracts to Sepolia");
        println!("    2. Create worker Starknet account");
        println!("    3. Set environment variables:");
        println!("       - STARKNET_RPC_URL");
        println!("       - WORKER_PRIVATE_KEY");
        println!("       - OPTIMISTIC_TEE_ADDRESS");
        println!("    4. Run with --features=live-contracts");
    } else {
        // Real submission code (requires deployed contracts)
        let rpc_url = std::env::var("STARKNET_RPC_URL")
            .unwrap_or_else(|_| "https://rpc.starknet-testnet.lava.build".to_string());
        
        let private_key = std::env::var("WORKER_PRIVATE_KEY")
            .expect("WORKER_PRIVATE_KEY not set");
        
        let account_address = FieldElement::from_hex_be(
            &std::env::var("WORKER_ADDRESS").expect("WORKER_ADDRESS not set")
        )?;
        
        let optimistic_tee_address = FieldElement::from_hex_be(
            &std::env::var("OPTIMISTIC_TEE_ADDRESS").expect("OPTIMISTIC_TEE_ADDRESS not set")
        )?;

        let worker_id = FieldElement::from_hex_be("0x123")?;
        let chain_id = FieldElement::from_hex_be("0x534e5f5345504f4c4941")?; // SN_SEPOLIA

        let bridge = WorkerBridge::new(
            &rpc_url,
            &private_key,
            account_address,
            chain_id,
            optimistic_tee_address,
            worker_id,
        )?;

        let job_id = JobId(Uuid::new_v4());
        let tx_hash = bridge.submit_result(&job_id, result_hash_bytes, &tee_quote).await?;
        
        println!("  ✅ Transaction submitted: {:#x}", tx_hash);
        println!("     View on Voyager: https://sepolia.voyager.online/tx/{:#x}", tx_hash);
    }

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║     Demo Complete                                             ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    println!("What happened:");
    println!("  1. ✅ Executed ML inference (W * x = [14, 32])");
    println!("  2. ✅ Generated TEE attestation quote");
    println!("  3. ⚠️  [Demo] Showed contract submission structure");
    println!("\nNext steps:");
    println!("  → Deploy contracts to Sepolia");
    println!("  → Fund worker account with ETH");
    println!("  → Run with real contract addresses");

    Ok(())
}


