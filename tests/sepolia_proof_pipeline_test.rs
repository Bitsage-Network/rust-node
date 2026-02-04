/// Sepolia integration test for the end-to-end proof pipeline
///
/// Tests the wired pipeline on Starknet Sepolia:
/// 1. Connect to Sepolia and verify contract accessibility
/// 2. Pack a proof and verify packing works
/// 3. Build multicall from proof and verify call structure
/// 4. Submit multicall on-chain (register_job_payment + submit_and_verify)
/// 5. Poll for PaymentReleased events

#[cfg(test)]
mod sepolia_pipeline_tests {
    use std::sync::Arc;
    #[allow(unused_imports)]
    use starknet::core::types::FieldElement;
    use starknet::core::utils::get_selector_from_name;

    use bitsage_node::blockchain::client::StarknetClient;
    use bitsage_node::obelysk::multicall_builder::{
        build_proof_multicall, generate_gpu_attestation, PipelineContracts,
    };
    use bitsage_node::obelysk::proof_packer::pack_proof;
    use bitsage_node::obelysk::prover::{StarkProof, FRILayer, Opening, ProofMetadata};
    use bitsage_node::obelysk::M31;

    /// Load env from .env file in the crate root, then read key
    fn load_env(key: &str) -> String {
        // Manually parse .env if present
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            if let Ok(contents) = std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"),
            ) {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((k, v)) = line.split_once('=') {
                        if std::env::var(k.trim()).is_err() {
                            std::env::set_var(k.trim(), v.trim());
                        }
                    }
                }
            }
        });
        std::env::var(key).unwrap_or_else(|_| panic!("{} not set — add to .env or environment", key))
    }

    fn rpc_url() -> String {
        load_env("STARKNET_RPC_URL")
    }

    fn load_contracts() -> PipelineContracts {
        // Ensure .env is loaded first
        load_env("STARKNET_RPC_URL");
        PipelineContracts {
            stwo_verifier: FieldElement::from_hex_be(
                &std::env::var("STWO_VERIFIER_ADDRESS")
                    .unwrap_or_else(|_| load_env("PROOF_VERIFIER_ADDRESS")),
            )
            .unwrap(),
            proof_gated_payment: FieldElement::from_hex_be(
                &std::env::var("PROOF_GATED_PAYMENT_ADDRESS")
                    .unwrap_or_else(|_| load_env("PAYMENT_ROUTER_ADDRESS")),
            )
            .unwrap(),
            payment_router: FieldElement::from_hex_be(&load_env("PAYMENT_ROUTER_ADDRESS")).unwrap(),
            optimistic_tee: FieldElement::from_hex_be(
                &std::env::var("OPTIMISTIC_TEE_ADDRESS").unwrap_or_else(|_| "0x0".to_string()),
            )
            .unwrap(),
            prover_staking: FieldElement::from_hex_be(&load_env("WORKER_STAKING_ADDRESS")).unwrap(),
        }
    }

    /// Create a synthetic but structurally valid StarkProof for testing
    /// Uses timestamp-based randomness so each run produces a unique proof hash
    fn create_test_proof() -> StarkProof {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u8;
        StarkProof {
            trace_commitment: vec![nonce; 32],
            fri_layers: vec![
                FRILayer {
                    commitment: vec![0xCD; 32],
                    evaluations: vec![M31::new(42), M31::new(43)],
                },
                FRILayer {
                    commitment: vec![0xEF; 32],
                    evaluations: vec![M31::new(44)],
                },
            ],
            openings: vec![Opening {
                position: 0,
                values: vec![M31::new(100), M31::new(200)],
                merkle_path: vec![vec![0x11; 32]],
            }],
            public_inputs: vec![M31::new(1), M31::new(2)],
            public_outputs: vec![M31::new(3)],
            metadata: ProofMetadata {
                trace_length: 1024,
                trace_width: 8,
                generation_time_ms: 500,
                proof_size_bytes: 2048,
                prover_version: "test-sepolia-v1".to_string(),
            },
            io_commitment: Some([0xBE; 32]),
        }
    }

    /// Step 1: Verify connectivity and contract accessibility
    #[tokio::test]
    async fn test_step1_sepolia_connectivity() {
        let client = StarknetClient::new(rpc_url()).unwrap();
        client.connect().await.unwrap();
        let block = client.get_block_number().await.unwrap();
        assert!(block > 0, "Should be connected to a live chain");
        println!("Connected to Sepolia at block {}", block);

        let contracts = load_contracts();
        let val = client
            .get_storage_at(contracts.stwo_verifier, FieldElement::ZERO)
            .await;
        println!(
            "StwoVerifier storage[0] = {:?}",
            val.as_ref().map(|v| format!("{:#x}", v))
        );
        assert!(val.is_ok(), "StwoVerifier contract should be accessible");

        // Also check payment router
        let val2 = client
            .get_storage_at(contracts.payment_router, FieldElement::ZERO)
            .await;
        println!(
            "PaymentRouter storage[0] = {:?}",
            val2.as_ref().map(|v| format!("{:#x}", v))
        );

        // Check prover staking
        let val3 = client
            .get_storage_at(contracts.prover_staking, FieldElement::ZERO)
            .await;
        println!(
            "ProverStaking storage[0] = {:?}",
            val3.as_ref().map(|v| format!("{:#x}", v))
        );
    }

    /// Step 2: Pack a proof into felt252 array
    #[tokio::test]
    async fn test_step2_proof_packing() {
        let proof = create_test_proof();
        let packed = pack_proof(&proof).unwrap();

        assert!(!packed.proof_data.is_empty(), "Packed proof should have felts");
        assert!(packed.calldata_size > 0);

        println!(
            "Proof packed: {} felts, calldata_size={}",
            packed.proof_data.len(),
            packed.calldata_size,
        );

        // Verify we can hash the packed data (same as contract does)
        use starknet_crypto::poseidon_hash_many as poseidon_hash_many_fe;
        let proof_hash = poseidon_hash_many_fe(&packed.proof_data);
        assert_ne!(proof_hash, FieldElement::ZERO);
        println!("Proof hash: {:#066x}", proof_hash);
    }

    /// Step 3: Build multicall from proof and verify call structure
    #[tokio::test]
    async fn test_step3_multicall_construction() {
        let proof = create_test_proof();
        let contracts = load_contracts();
        let worker_address =
            FieldElement::from_hex_be(&load_env("SIGNER_ACCOUNT_ADDRESS")).unwrap();
        let attestation = generate_gpu_attestation(50);

        let multicall = build_proof_multicall(
            &proof,
            1u128,
            worker_address,
            &attestation,
            &contracts,
            false,
        )
        .unwrap();

        assert!(
            multicall.calls.len() >= 2,
            "Should have at least 2 calls (register + verify), got {}",
            multicall.calls.len()
        );

        // Verify first call targets proof_gated_payment
        assert_eq!(
            multicall.calls[0].to, contracts.proof_gated_payment,
            "Call 1 should target ProofGatedPayment"
        );

        // Verify second call targets stwo_verifier
        assert_eq!(
            multicall.calls[1].to, contracts.stwo_verifier,
            "Call 2 should target StwoVerifier"
        );

        println!(
            "Multicall built: {} calls, proof_hash={:#066x}, expected_events={}",
            multicall.calls.len(),
            multicall.proof_hash,
            multicall.expected_events
        );

        // Print call details
        for (i, call) in multicall.calls.iter().enumerate() {
            println!(
                "  Call {}: to={:#066x}, selector={:#066x}, calldata_len={}",
                i,
                call.to,
                call.selector,
                call.calldata.len()
            );
        }
    }

    /// Step 4: Submit multicall on-chain via INVOKE V3 (requires funded account)
    #[tokio::test]
    #[ignore = "requires funded Sepolia account — run with --ignored"]
    async fn test_step4_submit_on_chain() {
        use bitsage_node::obelysk::multicall_builder::execute_v3_multicall;

        let client = Arc::new(StarknetClient::new(rpc_url()).unwrap());
        client.connect().await.unwrap();

        let private_key =
            FieldElement::from_hex_be(&load_env("DEPLOYER_PRIVATE_KEY")).unwrap();
        let account_address =
            FieldElement::from_hex_be(&load_env("SIGNER_ACCOUNT_ADDRESS")).unwrap();

        let proof = create_test_proof();
        let contracts = load_contracts();
        let attestation = generate_gpu_attestation(50);

        // Use timestamp-based job_id to avoid "Job already registered" collisions
        let job_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u128;
        println!("Using job_id={}", job_id);

        let multicall = build_proof_multicall(
            &proof,
            job_id,
            account_address,
            &attestation,
            &contracts,
            false,
        )
        .unwrap();

        println!(
            "Submitting {} calls via INVOKE V3 to Sepolia...",
            multicall.calls.len()
        );

        // Submit all calls together as a single multicall
        println!("--- Submitting all {} calls together ---", multicall.calls.len());
        let tx_result = execute_v3_multicall(
            &multicall.calls,
            private_key,
            account_address,
        )
        .await;
        match tx_result {
            Ok(tx_hash) => {
                println!("TX hash: {:#066x}", tx_hash);
                println!("Waiting 15s for confirmation...");
                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

                // Poll for PaymentReleased event
                let payment_released_key =
                    get_selector_from_name("PaymentReleased").unwrap();
                let block = client.get_block_number().await.unwrap();
                let events = client
                    .get_events_by_key(
                        contracts.proof_gated_payment,
                        payment_released_key,
                        block.saturating_sub(10),
                        Some(block),
                    )
                    .await
                    .unwrap();

                println!("PaymentReleased events found: {}", events.len());
                for event in &events {
                    println!(
                        "  tx={:#066x}, keys={}, data={}",
                        event.transaction_hash,
                        event.keys.len(),
                        event.data.len()
                    );
                }
            }
            Err(e) => {
                panic!("TX submission failed: {}", e);
            }
        }
    }

    /// Step 5: Poll PaymentReleased events from Sepolia
    #[tokio::test]
    async fn test_step5_poll_payment_events() {
        let client = StarknetClient::new(rpc_url()).unwrap();
        client.connect().await.unwrap();

        let contracts = load_contracts();
        let block = client.get_block_number().await.unwrap();
        let payment_released_key = get_selector_from_name("PaymentReleased").unwrap();

        let from_block = block.saturating_sub(1000);
        let events = client
            .get_events_by_key(
                contracts.proof_gated_payment,
                payment_released_key,
                from_block,
                Some(block),
            )
            .await
            .unwrap();

        println!(
            "Scanned blocks {}..{} for PaymentReleased: {} events found",
            from_block, block, events.len()
        );
        for event in &events {
            println!(
                "  tx={:#066x}, keys={}, data={}",
                event.transaction_hash,
                event.keys.len(),
                event.data.len()
            );
        }
        // No assertion — zero events expected until step4 runs
    }
}
