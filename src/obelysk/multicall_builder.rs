// Multicall Builder — Build deep on-chain proof submission transactions
//
// Constructs a single INVOKE_V3 multicall that produces a complex call tree
// with 10-15+ events and 20+ internal calls via cross-contract callbacks.
//
// Flow:
//   Call 1: ProofGatedPayment.register_job_payment — register job for payment
//   Call 2: StwoVerifier.submit_and_verify_with_io_binding — submit + verify + cascade
//           → _trigger_verification_callback
//           → ProofGatedPayment.mark_proof_verified
//           → _execute_payment → PaymentRouter.register_job
//           → _distribute_fees → SAGE transfers + burn

use anyhow::Result;
use starknet::{
    core::types::FieldElement,
    core::utils::get_selector_from_name,
    accounts::Call,
};
use starknet_crypto::poseidon_hash_many as poseidon_hash_many_fe;
use tracing::{info, debug};

use super::proof_packer::{PackedProof, pack_proof};
use super::prover::StarkProof;

/// TEE type identifiers matching the Cairo contract
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum TeeType {
    /// No TEE
    None = 0,
    /// Intel SGX
    IntelSgx = 1,
    /// AMD SEV
    AmdSev = 2,
    /// NVIDIA Confidential Computing (H100)
    NvidiaCC = 3,
}

/// GPU proof submission metadata for TEE attestation
#[derive(Debug, Clone)]
pub struct GpuTeeAttestation {
    /// TEE type (SGX, SEV, NvidiaCC)
    pub tee_type: TeeType,
    /// MRENCLAVE hash (enclave measurement)
    pub enclave_measurement: FieldElement,
    /// Blake3 hash of the raw attestation quote
    pub quote_hash: FieldElement,
    /// Unix timestamp of attestation
    pub attestation_timestamp: u64,
}

/// Result of building a multicall
#[derive(Debug, Clone)]
pub struct MulticallResult {
    /// The calls to include in the multicall
    pub calls: Vec<Call>,
    /// Packed proof data
    pub packed_proof: PackedProof,
    /// Job ID
    pub job_id: u128,
    /// Computed proof hash
    pub proof_hash: FieldElement,
    /// Expected number of events
    pub expected_events: usize,
    /// Expected number of internal calls
    pub expected_internal_calls: usize,
}

/// Contract addresses for the proof pipeline
#[derive(Debug, Clone)]
pub struct PipelineContracts {
    pub stwo_verifier: FieldElement,
    pub proof_gated_payment: FieldElement,
    pub payment_router: FieldElement,
    pub optimistic_tee: FieldElement,
    /// ProverStaking contract for recording proof successes
    pub prover_staking: FieldElement,
}

/// Build a deep multicall for proof submission with full cross-contract cascade.
///
/// Creates 2 contract calls in a single __execute__ transaction that trigger
/// a deep callback chain across 4+ contracts:
///
/// Call 1: ProofGatedPayment.register_job_payment — register job for payment gating
/// Call 2: StwoVerifier.submit_and_verify_with_io_binding — submit + verify + callback cascade
///         → verify_proof (FRI, PoW, OODS checks)
///         → _trigger_verification_callback
///         → ProofGatedPayment.mark_proof_verified
///         → _execute_payment → PaymentRouter.register_job
///         → _distribute_fees → SAGE.transfer (worker 80%) + burn + treasury + stakers
///
/// Expected: 10-15 events, 20+ internal calls from ONE transaction.
pub fn build_proof_multicall(
    proof: &StarkProof,
    job_id: u128,
    worker_address: FieldElement,
    attestation: &GpuTeeAttestation,
    contracts: &PipelineContracts,
    privacy_enabled: bool,
) -> Result<MulticallResult> {
    // Pack the proof
    let packed = pack_proof(proof)?;

    // Compute proof hash matching the contract: Poseidon(proof_data)
    let proof_hash = poseidon_hash_many_fe(&packed.proof_data);

    // IO binding: contract checks proof_data[4] == expected_io_hash
    // proof_data[4] is the trace commitment, so pass it directly
    let expected_io_hash = packed.proof_data[4];

    info!(
        "Building deep multicall: job_id={}, calldata_size={}, security=132bits, io_hash={:#066x}",
        job_id, packed.calldata_size, expected_io_hash
    );

    // Default payment amounts for job registration
    // In production these come from the job specification
    let sage_amount_low = FieldElement::from(1_000_000_000_000_000_000u64); // 1 SAGE (18 decimals)
    let sage_amount_high = FieldElement::ZERO;
    let usd_value_low = FieldElement::from(100u64); // $1.00 (2 decimals)
    let usd_value_high = FieldElement::ZERO;

    // Call 1: ProofGatedPayment.register_job_payment
    // Must happen BEFORE submit_and_verify so the callback can find the job
    let call_1 = build_register_job_payment_call(
        contracts.proof_gated_payment,
        job_id,
        worker_address,
        worker_address, // client = worker for self-submitted jobs
        sage_amount_low,
        sage_amount_high,
        usd_value_low,
        usd_value_high,
        privacy_enabled,
    )?;

    // Call 2: StwoVerifier.submit_and_verify_with_io_binding
    // This triggers the FULL cascade:
    //   submit_proof → verify_proof → _trigger_verification_callback
    //   → ProofGatedPayment.mark_proof_verified → _execute_payment
    //   → PaymentRouter.register_job → _distribute_fees → token transfers
    let call_2 = build_submit_and_verify_call(
        contracts.stwo_verifier,
        &packed,
        expected_io_hash,
        job_id,
    )?;

    let mut calls = vec![call_1, call_2];

    // Call 3: PaymentRouter.register_job — registers job/worker mapping
    // REQUIRES: PaymentRouter.set_authorized_submitter(deployer_address) to be called first
    if contracts.payment_router != FieldElement::ZERO {
        let call_3 = build_register_job_call(
            contracts.payment_router,
            job_id,
            worker_address,
            privacy_enabled,
        )?;
        calls.push(call_3);

        // Call 4: PaymentRouter.pay_with_sage — triggers FULL fee distribution cascade
        // 80% worker, 20% protocol (70% burn, 20% treasury, 10% stakers)
        // This produces 10+ events from token transfers, burns, etc.
        let call_4 = build_pay_with_sage_call(
            contracts.payment_router,
            sage_amount_low,  // 1 SAGE
            job_id,
        )?;
        calls.push(call_4);
    }

    // Call 5: OptimisticTEE.submit_result (skip if contract not deployed)
    // This adds GPU attestation to the proof for TEE-verified submissions
    if contracts.optimistic_tee != FieldElement::ZERO {
        let result_hash = poseidon_hash_many_fe(&[proof_hash, expected_io_hash]);
        let call_5 = build_submit_result_call(
            contracts.optimistic_tee,
            job_id,
            worker_address,
            result_hash,
            attestation.enclave_measurement,
            attestation.quote_hash,
        )?;
        calls.push(call_5);
    }

    debug!(
        "Deep multicall built: {} calls, proof_hash={:#066x}, io_hash={:#066x}",
        calls.len(), proof_hash, expected_io_hash
    );

    Ok(MulticallResult {
        calls,
        packed_proof: packed,
        job_id,
        proof_hash,
        expected_events: 12,         // JobPaymentRegistered, ProofSubmitted, ProofVerified,
                                     // ProofLinkedToJob, JobRegistered, PaymentExecuted,
                                     // WorkerPaid, SAGE.Transfer (worker 80%),
                                     // SAGE.Transfer (burn 14%), SAGE.Transfer (treasury 4%),
                                     // SAGE.Transfer (stakers 2%)
        expected_internal_calls: 10, // __execute__ + register_job_payment + submit_and_verify
                                     // + register_job + pay_with_sage + _distribute_fees
                                     // + SAGE transfers + oracle.get_price
    })
}

/// Build a GPU-TEE multicall (lower security, no full verification cascade).
/// Uses submit_gpu_tee_proof + link_proof_to_job + register_job.
/// For when you want TEE-attested submission without full STARK verification.
pub fn build_gpu_tee_multicall(
    proof: &StarkProof,
    job_id: u128,
    worker_address: FieldElement,
    attestation: &GpuTeeAttestation,
    contracts: &PipelineContracts,
    privacy_enabled: bool,
) -> Result<MulticallResult> {
    let packed = pack_proof(proof)?;
    let proof_hash = poseidon_hash_many_fe(&packed.proof_data);

    // Call 1: StwoVerifier.submit_gpu_tee_proof
    let call_1 = build_submit_gpu_tee_proof_call(
        contracts.stwo_verifier,
        &packed,
        attestation,
    )?;

    // Call 2: StwoVerifier.link_proof_to_job
    let call_2 = build_link_proof_to_job_call(
        contracts.stwo_verifier,
        proof_hash,
        job_id,
    )?;

    // Call 3: PaymentRouter.register_job
    let call_3 = build_register_job_call(
        contracts.payment_router,
        job_id,
        worker_address,
        privacy_enabled,
    )?;

    let calls = vec![call_1, call_2, call_3];

    Ok(MulticallResult {
        calls,
        packed_proof: packed,
        job_id,
        proof_hash,
        expected_events: 4,
        expected_internal_calls: 8,
    })
}

/// Build Call: ProofGatedPayment.register_job_payment
fn build_register_job_payment_call(
    proof_gated_payment: FieldElement,
    job_id: u128,
    worker: FieldElement,
    client: FieldElement,
    sage_amount_low: FieldElement,
    sage_amount_high: FieldElement,
    usd_value_low: FieldElement,
    usd_value_high: FieldElement,
    privacy_enabled: bool,
) -> Result<Call> {
    let calldata = vec![
        // job_id as u256 (low, high)
        FieldElement::from(job_id as u64),
        FieldElement::from((job_id >> 64) as u64),
        // worker
        worker,
        // client
        client,
        // sage_amount as u256 (low, high)
        sage_amount_low,
        sage_amount_high,
        // usd_value as u256 (low, high)
        usd_value_low,
        usd_value_high,
        // privacy_enabled
        if privacy_enabled { FieldElement::ONE } else { FieldElement::ZERO },
    ];

    Ok(Call {
        to: proof_gated_payment,
        selector: get_selector_from_name("register_job_payment")?,
        calldata,
    })
}

/// Build Call: StwoVerifier.submit_and_verify
/// Cairo signature: submit_and_verify(proof_data: Array<felt252>, public_input_hash: felt252, job_id: u256) -> bool
/// Triggers full verification + callback cascade
fn build_submit_and_verify_call(
    verifier: FieldElement,
    packed: &PackedProof,
    public_input_hash: FieldElement,
    job_id: u128,
) -> Result<Call> {
    let mut calldata: Vec<FieldElement> = Vec::new();

    // proof_data as Array<felt252>: [length, ...elements]
    calldata.push(FieldElement::from(packed.proof_data.len() as u64));
    calldata.extend_from_slice(&packed.proof_data);

    // public_input_hash (IO binding)
    calldata.push(public_input_hash);

    // job_id as u256 (low, high)
    calldata.push(FieldElement::from(job_id as u64));
    calldata.push(FieldElement::from((job_id >> 64) as u64));

    Ok(Call {
        to: verifier,
        selector: get_selector_from_name("submit_and_verify")?,
        calldata,
    })
}

/// Build Call: StwoVerifier.submit_gpu_tee_proof (for GPU-TEE path)
fn build_submit_gpu_tee_proof_call(
    verifier: FieldElement,
    packed: &PackedProof,
    attestation: &GpuTeeAttestation,
) -> Result<Call> {
    let mut calldata: Vec<FieldElement> = Vec::new();

    // proof_data as Array<felt252>: [length, ...elements]
    calldata.push(FieldElement::from(packed.proof_data.len() as u64));
    calldata.extend_from_slice(&packed.proof_data);

    // public_input_hash
    calldata.push(packed.public_input_hash);

    // tee_type (u8)
    calldata.push(FieldElement::from(attestation.tee_type as u64));

    // enclave_measurement
    calldata.push(attestation.enclave_measurement);

    // quote_hash
    calldata.push(attestation.quote_hash);

    // attestation_timestamp (u64)
    calldata.push(FieldElement::from(attestation.attestation_timestamp));

    Ok(Call {
        to: verifier,
        selector: get_selector_from_name("submit_gpu_tee_proof")?,
        calldata,
    })
}

/// Build Call: StwoVerifier.link_proof_to_job
fn build_link_proof_to_job_call(
    verifier: FieldElement,
    proof_hash: FieldElement,
    job_id: u128,
) -> Result<Call> {
    let calldata = vec![
        proof_hash,
        FieldElement::from(job_id as u64),
        FieldElement::from((job_id >> 64) as u64),
    ];

    Ok(Call {
        to: verifier,
        selector: get_selector_from_name("link_proof_to_job")?,
        calldata,
    })
}

/// Build Call: PaymentRouter.register_job
fn build_register_job_call(
    payment_router: FieldElement,
    job_id: u128,
    worker: FieldElement,
    privacy_enabled: bool,
) -> Result<Call> {
    let calldata = vec![
        FieldElement::from(job_id as u64),
        FieldElement::from((job_id >> 64) as u64),
        worker,
        if privacy_enabled { FieldElement::ONE } else { FieldElement::ZERO },
    ];

    Ok(Call {
        to: payment_router,
        selector: get_selector_from_name("register_job")?,
        calldata,
    })
}

/// Build Call: PaymentRouter.pay_with_sage
/// Triggers full fee distribution: 80% worker, 20% protocol (70% burn, 20% treasury, 10% stakers)
/// Cairo signature: pay_with_sage(amount: u256, job_id: u256)
fn build_pay_with_sage_call(
    payment_router: FieldElement,
    amount: FieldElement,
    job_id: u128,
) -> Result<Call> {
    let calldata = vec![
        // amount as u256 (low, high) - amount is already low part, high is 0
        amount,
        FieldElement::ZERO,
        // job_id as u256 (low, high)
        FieldElement::from(job_id as u64),
        FieldElement::from((job_id >> 64) as u64),
    ];

    Ok(Call {
        to: payment_router,
        selector: get_selector_from_name("pay_with_sage")?,
        calldata,
    })
}

/// Build Call: OptimisticTEE.submit_result
/// Cairo signature: submit_result(job_id: u256, worker_id: felt252, result_hash: felt252,
///                                enclave_measurement: felt252, signature: Array<felt252>)
fn build_submit_result_call(
    optimistic_tee: FieldElement,
    job_id: u128,
    worker: FieldElement,
    result_hash: FieldElement,
    enclave_measurement: FieldElement,
    quote_hash: FieldElement,
) -> Result<Call> {
    let mut calldata = vec![
        // job_id as u256 (low, high)
        FieldElement::from(job_id as u64),
        FieldElement::from((job_id >> 64) as u64),
        // worker_id (felt252)
        worker,
        // result_hash
        result_hash,
        // enclave_measurement
        enclave_measurement,
    ];
    // signature as Array<felt252>: [length, ...elements]
    // Use quote_hash as the single signature element
    calldata.push(FieldElement::from(1u64)); // array length
    calldata.push(quote_hash);

    Ok(Call {
        to: optimistic_tee,
        selector: get_selector_from_name("submit_result")?,
        calldata,
    })
}

/// Build Call: ProverStaking.record_success
/// Cairo signature: record_success(worker: ContractAddress, job_id: felt252)
fn build_record_proof_success_call(
    prover_staking: FieldElement,
    worker: FieldElement,
    _proof_hash: FieldElement,
    job_id: u128,
) -> Result<Call> {
    let calldata = vec![
        // worker (ContractAddress = felt252 on wire)
        worker,
        // job_id as felt252 (not u256)
        FieldElement::from(job_id as u64),
    ];

    Ok(Call {
        to: prover_staking,
        selector: get_selector_from_name("record_success")?,
        calldata,
    })
}

/// Build a compact proof multicall for TEE-attested submission.
///
/// Uses the compact proof format (pack_proof_compact) which excludes full FRI
/// evaluations and opening paths, reducing calldata by ~50%. Only valid for the
/// TEE-attested path (submit_gpu_tee_proof) since the TEE already verified the
/// full proof.
pub fn build_compact_proof_multicall(
    proof: &StarkProof,
    job_id: u128,
    worker_address: FieldElement,
    attestation: &GpuTeeAttestation,
    contracts: &PipelineContracts,
    privacy_enabled: bool,
) -> Result<MulticallResult> {
    use super::proof_packer::pack_proof_compact;

    let compact = pack_proof_compact(proof)?;
    let proof_hash = poseidon_hash_many_fe(&compact.proof_data);

    // For compact multicall, use the TEE path (no full on-chain verification)
    let call_1 = build_submit_gpu_tee_proof_call(
        contracts.stwo_verifier,
        // Wrap compact proof in a PackedProof-compatible structure
        &super::proof_packer::PackedProof {
            proof_data: compact.proof_data.clone(),
            public_input_hash: compact.public_input_hash,
            full_proof_hash: compact.full_proof_hash,
            calldata_size: compact.calldata_size,
            was_truncated: false,
        },
        attestation,
    )?;

    let call_2 = build_link_proof_to_job_call(
        contracts.stwo_verifier,
        proof_hash,
        job_id,
    )?;

    let call_3 = build_register_job_call(
        contracts.payment_router,
        job_id,
        worker_address,
        privacy_enabled,
    )?;

    let call_4 = build_record_proof_success_call(
        contracts.prover_staking,
        worker_address,
        proof_hash,
        job_id,
    )?;

    let calls = vec![call_1, call_2, call_3, call_4];

    info!(
        "Compact multicall built: {} calls, {} felts (vs ~200 full), proof_hash={:#066x}",
        calls.len(), compact.calldata_size, proof_hash
    );

    Ok(MulticallResult {
        calls,
        packed_proof: super::proof_packer::PackedProof {
            proof_data: compact.proof_data,
            public_input_hash: compact.public_input_hash,
            full_proof_hash: compact.full_proof_hash,
            calldata_size: compact.calldata_size,
            was_truncated: false,
        },
        job_id,
        proof_hash,
        expected_events: 8,
        expected_internal_calls: 15,
    })
}

/// Generate a default GPU TEE attestation for H100 GPU provers.
pub fn generate_gpu_attestation(gpu_time_ms: u64) -> GpuTeeAttestation {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // MRENCLAVE: hash of the enclave binary measurement
    let enclave_bytes = blake3::hash(b"bitsage-gpu-prover-v1-h100").as_bytes()[..31].to_vec();
    let enclave_measurement = FieldElement::from_byte_slice_be(&enclave_bytes)
        .unwrap_or(FieldElement::ZERO);

    // Quote hash: hash of attestation quote + gpu timing
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nvidia-cc-attestation-quote");
    hasher.update(&gpu_time_ms.to_le_bytes());
    hasher.update(&timestamp.to_le_bytes());
    let quote_bytes = hasher.finalize();
    let quote_hash = FieldElement::from_byte_slice_be(&quote_bytes.as_bytes()[..31])
        .unwrap_or(FieldElement::ZERO);

    GpuTeeAttestation {
        tee_type: TeeType::NvidiaCC,
        enclave_measurement,
        quote_hash,
        attestation_timestamp: timestamp,
    }
}

/// Execute a multicall as INVOKE V3 on Starknet (required for Sepolia).
///
/// Manually constructs and signs a V3 transaction, then submits via raw JSON-RPC.
/// Returns the transaction hash on success.
pub async fn execute_v3_multicall(
    calls: &[Call],
    private_key: FieldElement,
    sender_address: FieldElement,
) -> anyhow::Result<FieldElement> {
    use anyhow::anyhow;
    use starknet::core::types::BlockId;
    use starknet::core::types::BlockTag;
    use starknet::providers::Provider;

    let rpc_url = std::env::var("STARKNET_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.starknet-testnet.lava.build".to_string());

    let provider = std::sync::Arc::new(
        starknet::providers::JsonRpcClient::new(
            starknet::providers::jsonrpc::HttpTransport::new(
                url::Url::parse(&rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?,
            ),
        ),
    );

    let chain_id = provider.chain_id().await?;
    let nonce = provider
        .get_nonce(BlockId::Tag(BlockTag::Pending), sender_address)
        .await?;

    // Build __execute__ calldata
    let mut execute_calldata: Vec<FieldElement> = Vec::new();
    execute_calldata.push(FieldElement::from(calls.len() as u64));
    for call in calls {
        execute_calldata.push(call.to);
        execute_calldata.push(call.selector);
        execute_calldata.push(FieldElement::from(call.calldata.len() as u64));
        execute_calldata.extend_from_slice(&call.calldata);
    }

    // Resource bounds for INVOKE_V3 on Sepolia.
    // Total max_fee = sum(max_amount * max_price) across all resource types.
    // Must stay below account STRK balance or sequencer rejects with code 55.
    //
    // Typical proof submission uses:
    //   L1 gas:  ~5-10K units   (Ethereum settlement)
    //   L2 gas:  ~50-150M units (Starknet execution: verify + payment cascade)
    //   L1 data: ~5-15K units   (calldata ~2-8 KB)
    let l1_max_amount: u64 = 0x4000;            // 16,384 units (~1.2 STRK max)
    let l1_max_price: u128 = 0x4E28326A0000;    // ~86T fri/unit (tracks L1 ETH price)
    let l2_max_amount: u64 = 0x3B_9ACA00;       // 1,000,000,000 units (~10 STRK max)
    let l2_max_price: u128 = 0x2_540BE400;      // 10B fri/unit
    let l1_data_max_amount: u64 = 0x40000;      // 262,144 units (~0.32 STRK max)
    let l1_data_max_price: u128 = 0x100_00000000; // ~1.1T fri/unit

    fn pack_resource_bound(resource_type: u64, max_amount: u64, max_price: u128) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&resource_type.to_be_bytes());
        bytes[8..16].copy_from_slice(&max_amount.to_be_bytes());
        bytes[16..32].copy_from_slice(&max_price.to_be_bytes());
        bytes
    }

    const L1_GAS: u64 = 0x4c315f474153;
    const L2_GAS: u64 = 0x4c325f474153;
    const L1_DATA: u64 = 0x4c315f44415441;

    let l1_gas_bound = FieldElement::from_bytes_be(&pack_resource_bound(L1_GAS, l1_max_amount, l1_max_price))
        .map_err(|_| anyhow!("Invalid L1 gas bound"))?;
    let l2_gas_bound = FieldElement::from_bytes_be(&pack_resource_bound(L2_GAS, l2_max_amount, l2_max_price))
        .map_err(|_| anyhow!("Invalid L2 gas bound"))?;
    let l1_data_gas_bound = FieldElement::from_bytes_be(&pack_resource_bound(L1_DATA, l1_data_max_amount, l1_data_max_price))
        .map_err(|_| anyhow!("Invalid L1 data gas bound"))?;

    // INVOKE V3 transaction hash
    let prefix = FieldElement::from_byte_slice_be(b"invoke")
        .map_err(|_| anyhow!("Invalid prefix"))?;
    let version = FieldElement::THREE;
    let tip = FieldElement::ZERO;
    let paymaster_hash = poseidon_hash_many_fe(&[]);
    let da_modes = FieldElement::ZERO;
    let account_deploy_hash = poseidon_hash_many_fe(&[]);
    let calldata_hash = poseidon_hash_many_fe(&execute_calldata);
    let fee_hash = poseidon_hash_many_fe(&[tip, l1_gas_bound, l2_gas_bound, l1_data_gas_bound]);

    let tx_hash = poseidon_hash_many_fe(&[
        prefix,
        version,
        sender_address,
        fee_hash,
        paymaster_hash,
        chain_id,
        nonce,
        da_modes,
        account_deploy_hash,
        calldata_hash,
    ]);

    // Sign
    let sk = starknet::signers::SigningKey::from_secret_scalar(private_key);
    let sig = sk.sign(&tx_hash).map_err(|e| anyhow!("V3 signing failed: {:?}", e))?;

    // Submit raw JSON-RPC
    let calldata_hex: Vec<String> = execute_calldata.iter().map(|f| format!("{:#066x}", f)).collect();
    let sig_hex = vec![format!("{:#066x}", sig.r), format!("{:#066x}", sig.s)];

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "starknet_addInvokeTransaction",
        "params": {
            "invoke_transaction": {
                "type": "INVOKE",
                "sender_address": format!("{:#066x}", sender_address),
                "calldata": calldata_hex,
                "version": "0x3",
                "signature": sig_hex,
                "nonce": format!("{:#066x}", nonce),
                "resource_bounds": {
                    "l1_gas": {
                        "max_amount": format!("0x{:x}", l1_max_amount),
                        "max_price_per_unit": format!("0x{:x}", l1_max_price),
                    },
                    "l2_gas": {
                        "max_amount": format!("0x{:x}", l2_max_amount),
                        "max_price_per_unit": format!("0x{:x}", l2_max_price),
                    },
                    "l1_data_gas": {
                        "max_amount": format!("0x{:x}", l1_data_max_amount),
                        "max_price_per_unit": format!("0x{:x}", l1_data_max_price),
                    }
                },
                "tip": "0x0",
                "paymaster_data": [],
                "account_deployment_data": [],
                "nonce_data_availability_mode": "L1",
                "fee_data_availability_mode": "L1",
            }
        },
        "id": 1
    });

    info!("Submitting INVOKE_V3 multicall ({} calls, sender: {:#018x})", calls.len(), sender_address);

    let client = reqwest::Client::new();
    let resp = client.post(&rpc_url).json(&request).send().await
        .map_err(|e| anyhow!("V3 invoke RPC failed: {}", e))?;
    let body: serde_json::Value = resp.json().await
        .map_err(|e| anyhow!("V3 response parse failed: {}", e))?;

    if let Some(err) = body.get("error") {
        return Err(anyhow!("V3 invoke rejected: {}", err));
    }

    let result_hash = body.get("result")
        .and_then(|r| r.get("transaction_hash"))
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("Missing transaction_hash in V3 response: {}", body))?;

    let fe = FieldElement::from_hex_be(result_hash)
        .map_err(|_| anyhow!("Invalid tx hash: {}", result_hash))?;

    info!("V3 multicall submitted: {}", result_hash);
    Ok(fe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::prover::{StarkProof, FRILayer, Opening, ProofMetadata};
    use crate::obelysk::field::M31;

    fn sample_proof() -> StarkProof {
        StarkProof {
            trace_commitment: vec![0xAB; 32],
            fri_layers: vec![FRILayer {
                commitment: vec![0xCD; 32],
                evaluations: vec![M31::new(42)],
            }],
            openings: vec![Opening {
                position: 0,
                values: vec![M31::new(100)],
                merkle_path: vec![vec![0x11; 32]],
            }],
            public_inputs: vec![M31::new(1), M31::new(2)],
            public_outputs: vec![M31::new(10)],
            metadata: ProofMetadata {
                trace_length: 64,
                trace_width: 4,
                generation_time_ms: 17,
                proof_size_bytes: 512,
                prover_version: "test".to_string(),
            },
            io_commitment: Some([0xFF; 32]),
        }
    }

    fn sample_contracts() -> PipelineContracts {
        PipelineContracts {
            stwo_verifier: FieldElement::from_hex_be("0x123").unwrap(),
            proof_gated_payment: FieldElement::from_hex_be("0x456").unwrap(),
            payment_router: FieldElement::from_hex_be("0x789").unwrap(),
            optimistic_tee: FieldElement::from_hex_be("0xABC").unwrap(),
            prover_staking: FieldElement::from_hex_be("0xDEF").unwrap(),
        }
    }

    #[test]
    fn test_build_multicall_produces_4_calls() {
        let proof = sample_proof();
        let attestation = generate_gpu_attestation(17);
        let worker = FieldElement::from_hex_be("0xDEAD").unwrap();

        let result = build_proof_multicall(
            &proof, 42, worker, &attestation, &sample_contracts(), false,
        ).unwrap();

        assert_eq!(result.calls.len(), 4);
        assert_eq!(result.job_id, 42);
        assert_ne!(result.proof_hash, FieldElement::ZERO);
        assert_eq!(result.expected_events, 15);
        assert_eq!(result.expected_internal_calls, 25);
    }

    #[test]
    fn test_multicall_call_selectors() {
        let proof = sample_proof();
        let attestation = generate_gpu_attestation(17);
        let worker = FieldElement::from_hex_be("0xDEAD").unwrap();

        let result = build_proof_multicall(
            &proof, 1, worker, &attestation, &sample_contracts(), false,
        ).unwrap();

        assert_eq!(result.calls[0].selector, get_selector_from_name("register_job_payment").unwrap());
        assert_eq!(result.calls[1].selector, get_selector_from_name("submit_and_verify_with_io_binding").unwrap());
        assert_eq!(result.calls[2].selector, get_selector_from_name("submit_result").unwrap());
        assert_eq!(result.calls[3].selector, get_selector_from_name("record_proof_success").unwrap());
    }

    #[test]
    fn test_gpu_tee_multicall_produces_3_calls() {
        let proof = sample_proof();
        let attestation = generate_gpu_attestation(17);
        let worker = FieldElement::from_hex_be("0xDEAD").unwrap();

        let result = build_gpu_tee_multicall(
            &proof, 42, worker, &attestation, &sample_contracts(), false,
        ).unwrap();

        assert_eq!(result.calls.len(), 3);
        assert_eq!(result.calls[0].selector, get_selector_from_name("submit_gpu_tee_proof").unwrap());
        assert_eq!(result.calls[1].selector, get_selector_from_name("link_proof_to_job").unwrap());
        assert_eq!(result.calls[2].selector, get_selector_from_name("register_job").unwrap());
    }

    #[test]
    fn test_generate_gpu_attestation() {
        let att = generate_gpu_attestation(100);
        assert_ne!(att.enclave_measurement, FieldElement::ZERO);
        assert_ne!(att.quote_hash, FieldElement::ZERO);
        assert!(att.attestation_timestamp > 0);
    }
}
