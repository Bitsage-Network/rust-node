# Bitsage Network: E2E Production Readiness Plan

## Executive Summary

**Current Status:** ~70% Production Ready
**Target:** Mainnet-ready GPU Worker Network with Privacy Payments
**Timeline:** 6-8 weeks (2 developers)

---

## Critical E2E Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         WORKER NODE E2E LIFECYCLE                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. WALLET CREATION          2. STAKE & JOIN          3. JOB EXECUTION      │
│  ┌─────────────────┐        ┌─────────────────┐      ┌─────────────────┐    │
│  │ Generate Keys   │───────▶│ Stake SAGE     │─────▶│ Receive Job     │    │
│  │ Register TEE    │        │ Register Worker │      │ Execute in TEE  │    │
│  │ Get Testnet     │        │ Join P2P Network│      │ Generate Trace  │    │
│  │   Faucet        │        │ Start Heartbeat │      │ Prove with Stwo │    │
│  └─────────────────┘        └─────────────────┘      └─────────────────┘    │
│           │                        │                        │               │
│           ▼                        ▼                        ▼               │
│  4. PROOF SUBMISSION         5. VALIDATION           6. PAYMENT             │
│  ┌─────────────────┐        ┌─────────────────┐      ┌─────────────────┐    │
│  │ GPU Accelerated │───────▶│ Validator Vote │─────▶│ ElGamal Encrypt │    │
│  │ Submit On-Chain │        │ Consensus (BFT)│      │ Privacy Router  │    │
│  │ Compressed Proof│        │ Fraud Detection│      │ Claim Payment   │    │
│  └─────────────────┘        └─────────────────┘      └─────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 5 Critical Blocking Issues

| # | Gap | Status | Impact | Owner |
|---|-----|--------|--------|-------|
| 1 | **Proof Generation Pipeline** | 75% | Jobs execute but proofs not linked | DEV 1 |
| 2 | **Starknet Signature** | Stubbed | Transactions won't sign | DEV 2 |
| 3 | **Staking Verification** | 60% | Workers join without stake check | DEV 2 |
| 4 | **Proof-Gated Payment** | 70% | Payments not linked to proof verification | DEV 1 |
| 5 | **Validator Consensus** | 40% | No BFT voting, only dashboard | DEV 1 |

---

## 2-Developer Work Split

### DEV 1: STWO GPU + Obelysk + Privacy + Consensus
**Focus:** Proof pipeline, payments, validator network

### DEV 2: Smart Contracts + Staking + Infrastructure
**Focus:** Contract integration, staking, wallet, faucet

---

## DEV 1 Tasks (Weeks 1-6)

### Week 1-2: Proof Generation Pipeline

#### Task 1.1: Link Job Execution to Proof Generation
**File:** `src/compute/obelysk_executor.rs`

```rust
// CURRENT (line 89-145): Job executes but proof not generated
pub async fn execute_job(&self, job: Job) -> Result<JobResult> {
    let trace = vm.execute()?;
    // TODO: Generate proof from trace
    Ok(JobResult { trace, proof: None })  // ⚠️ No proof!
}

// FIX: Connect to Stwo prover
pub async fn execute_job(&self, job: Job) -> Result<JobResult> {
    let trace = vm.execute()?;

    // Generate real proof using Stwo GPU
    let prover = ObelyskProver::new();
    let proof = prover.prove_execution(&trace)?;

    // Compress proof for on-chain submission
    let compressed = ProofCompressor::compress(&proof, CompressionAlgorithm::Zstd)?;

    Ok(JobResult {
        trace,
        proof: Some(compressed),
        proof_hash: blake3::hash(&compressed.data),
    })
}
```

**Checklist:**
- [ ] Add proof generation to execute_job()
- [ ] Add proof compression (Zstd)
- [ ] Add proof hash computation
- [ ] Verify proof size < 256KB for on-chain
- [ ] Add GPU fallback to CPU

#### Task 1.2: Implement Secure Randomness for ElGamal
**File:** `src/obelysk/elgamal.rs`

```rust
// ADD: Secure randomness generation
use getrandom::getrandom;

pub fn generate_randomness() -> Result<Felt252, CryptoError> {
    let mut bytes = [0u8; 32];
    getrandom(&mut bytes).map_err(|_| CryptoError::RngFailed)?;

    // Ensure randomness is less than STARK_PRIME
    let felt = Felt252::from_be_bytes(&bytes);
    if felt >= STARK_PRIME {
        return generate_randomness(); // Retry (rare)
    }
    Ok(felt)
}
```

**Checklist:**
- [ ] Implement generate_randomness()
- [ ] Add to Cargo.toml: `getrandom = "0.2"`
- [ ] Update deposit() to use secure randomness
- [ ] Update claim_worker_payment() nonce generation

#### Task 1.3: Montgomery Reduction (25x Speedup)
**File:** `src/obelysk/elgamal.rs`

```rust
// ADD: Montgomery multiplication for 25x faster crypto
impl Felt252 {
    /// Montgomery reduction: compute (a * b * R^-1) mod P
    pub fn mul_mod_montgomery(&self, other: &Self) -> Self {
        // Precomputed: R = 2^256, R2 = R^2 mod P, P_INV = -P^(-1) mod R
        const R2: Felt252 = ...; // Precompute
        const P_INV: Felt252 = ...; // Precompute

        // 1. Compute 512-bit product
        let t = self.mul_wide(other);

        // 2. Montgomery step: m = (t * P_INV) mod R
        let m = t.low_256().mul_wide(&P_INV).low_256();

        // 3. Reduce: (t + m * P) / R
        let mp = m.mul_wide(&STARK_PRIME);
        let sum = t.add_wide(&mp);
        let result = sum.high_256();

        // 4. Final reduction
        if result >= STARK_PRIME {
            result.sub(&STARK_PRIME)
        } else {
            result
        }
    }
}
```

**Checklist:**
- [ ] Precompute R2 and P_INV constants
- [ ] Implement mul_wide() for 512-bit products
- [ ] Implement Montgomery reduction
- [ ] Replace all mul_mod() calls
- [ ] Benchmark: should see 25x improvement

### Week 3-4: Payment Integration & Validator Consensus

#### Task 1.4: Proof-Gated Payment
**File:** `src/obelysk/payment_client.rs`

```rust
// ADD: Link payment to verified proof
pub async fn submit_payment_with_proof(
    &self,
    worker: &str,
    job_id: u128,
    amount: u128,
    proof: &CompressedProof,
) -> Result<TxHash> {
    // 1. Verify proof is valid (local check)
    let is_valid = verify_proof_structure(proof)?;
    if !is_valid {
        return Err(PaymentError::InvalidProof);
    }

    // 2. Encrypt payment amount
    let randomness = generate_randomness()?;
    let encrypted = self.privacy_client.encrypt_payment(amount, worker, &randomness)?;

    // 3. Submit to contract with proof commitment
    let proof_commitment = blake3::hash(&proof.data);
    let calldata = vec![
        worker_address,
        job_id.into(),
        encrypted.c1_x,
        encrypted.c1_y,
        encrypted.c2_x,
        encrypted.c2_y,
        proof_commitment.into(),
    ];

    self.starknet_client.execute(
        "PaymentRouter",
        "submit_payment_with_proof",
        calldata,
    ).await
}
```

**Checklist:**
- [ ] Add proof commitment to payment
- [ ] Verify proof before payment
- [ ] Update PaymentRouter contract to check proof_commitment
- [ ] Add replay protection (job_id + nonce)

#### Task 1.5: Validator Consensus Protocol
**File:** `src/validator/consensus.rs` (NEW)

```rust
pub struct ValidatorConsensus {
    validators: Vec<ValidatorInfo>,
    threshold: usize,  // 67% supermajority
}

impl ValidatorConsensus {
    /// Vote on proof validity
    pub async fn vote_on_proof(
        &self,
        proof: &StarkProof,
        job_id: u128,
    ) -> Result<ConsensusResult> {
        // 1. Verify proof locally
        let local_valid = verify_with_stwo(proof)?;

        // 2. Broadcast vote to other validators
        let vote = Vote {
            validator: self.identity,
            job_id,
            valid: local_valid,
            signature: self.sign_vote(job_id, local_valid)?,
        };
        self.broadcast_vote(&vote).await?;

        // 3. Collect votes (timeout 30s)
        let votes = self.collect_votes(job_id, Duration::from_secs(30)).await?;

        // 4. Check supermajority (67%)
        let valid_count = votes.iter().filter(|v| v.valid).count();
        let threshold = (self.validators.len() * 2) / 3 + 1;

        if valid_count >= threshold {
            Ok(ConsensusResult::Approved { votes })
        } else {
            Ok(ConsensusResult::Rejected { votes })
        }
    }
}
```

**Checklist:**
- [ ] Create validator/mod.rs module
- [ ] Implement P2P vote broadcast (use existing libp2p)
- [ ] Implement vote collection with timeout
- [ ] Implement supermajority check (67%)
- [ ] Add slashing for invalid votes

### Week 5-6: TEE Attestation & Integration

#### Task 1.6: TEE MRENCLAVE Whitelist
**File:** `src/obelysk/tee_types.rs`

```rust
// ADD: Real MRENCLAVE values from deployed worker images
pub const ALLOWED_MRENCLAVES: &[&[u8; 32]] = &[
    // Worker v1.0.0 - Intel TDX
    b"\x12\x34\x56...",  // Fill with actual hash
    // Worker v1.0.0 - Intel SGX
    b"\xab\xcd\xef...",
    // Worker v1.0.0 - AMD SEV-SNP
    b"\x78\x9a\xbc...",
];

impl EnclaveWhitelist {
    pub fn is_allowed(&self, mrenclave: &[u8]) -> bool {
        ALLOWED_MRENCLAVES.iter().any(|allowed| {
            allowed.as_slice() == mrenclave
        })
    }
}
```

**Checklist:**
- [ ] Build worker Docker images
- [ ] Measure MRENCLAVE for each TEE type
- [ ] Update whitelist constants
- [ ] Add version tracking
- [ ] Implement whitelist update mechanism

#### Task 1.7: Integrate with BitSage-Validator
**File:** `src/validator/bitsage_bridge.rs` (NEW)

```rust
pub struct BitSageValidatorBridge {
    validator_endpoint: String,
}

impl BitSageValidatorBridge {
    pub async fn submit_proof_for_validation(
        &self,
        proof: &StarkProof,
        job_id: u128,
    ) -> Result<ValidationResult> {
        // Call BitSage-Validator API
        let response = self.client
            .post(&format!("{}/validate", self.validator_endpoint))
            .json(&ValidateRequest {
                proof: proof.serialize(),
                job_id,
            })
            .send()
            .await?;

        response.json().await
    }
}
```

**Checklist:**
- [ ] Create bridge to BitSage-Validator
- [ ] Implement proof submission API
- [ ] Implement validation response handling
- [ ] Add retry logic
- [ ] Add fallback validators

---

## DEV 2 Tasks (Weeks 1-6)

### Week 1-2: Smart Contract Integration

#### Task 2.1: Fix Starknet Signature Implementation
**File:** `src/obelysk/starknet/starknet_client.rs`

```rust
// CURRENT (stubbed): Signature doesn't work
pub fn sign_transaction(&self, tx: &Transaction) -> Result<Signature> {
    // TODO: Implement real signing
    Ok(Signature::default())  // ⚠️ STUB
}

// FIX: Implement real Starknet signing
use starknet_crypto::{sign, get_public_key, Signature as CryptoSig};

pub fn sign_transaction(&self, tx: &Transaction) -> Result<Signature> {
    let message_hash = tx.compute_hash()?;
    let private_key = self.signer.get_private_key()?;

    let signature = sign(
        &private_key,
        &message_hash,
        &generate_k()?,  // RFC 6979 deterministic k
    )?;

    Ok(Signature {
        r: signature.r,
        s: signature.s,
    })
}
```

**Checklist:**
- [ ] Implement sign_transaction() with starknet_crypto
- [ ] Add RFC 6979 deterministic k generation
- [ ] Add transaction hash computation
- [ ] Test with testnet deployment
- [ ] Add signature verification

#### Task 2.2: Implement Staking Verification
**File:** `src/obelysk/starknet/staking_client.rs`

```rust
// ADD: Verify stake before accepting worker
pub async fn verify_stake(&self, worker: &str) -> Result<StakeStatus> {
    let stake = self.get_worker_stake(worker).await?;
    let required = self.get_minimum_stake(stake.gpu_tier).await?;

    if stake.amount < required {
        return Ok(StakeStatus::Insufficient {
            current: stake.amount,
            required,
        });
    }

    if stake.locked_until < now() {
        return Ok(StakeStatus::Unlocked);
    }

    Ok(StakeStatus::Valid {
        amount: stake.amount,
        tier: stake.gpu_tier,
        until: stake.locked_until,
    })
}
```

**Checklist:**
- [ ] Add verify_stake() to StakingClient
- [ ] Integrate with worker registration flow
- [ ] Add minimum stake constants per GPU tier
- [ ] Add stake expiry checking
- [ ] Add slashing hooks

#### Task 2.3: Deploy and Configure Contracts
**Files:** Smart contract deployment scripts

```bash
# Contract Addresses to Configure:
# 1. StakingManager
# 2. ReputationManager
# 3. JobManager
# 4. PaymentRouter
# 5. PrivacyRouter
# 6. ProofVerifier
```

**Checklist:**
- [ ] Deploy StakingManager to testnet
- [ ] Deploy ReputationManager
- [ ] Deploy JobManager
- [ ] Deploy PaymentRouter
- [ ] Deploy PrivacyRouter
- [ ] Update contract addresses in config
- [ ] Verify all contracts on explorer

### Week 3-4: Wallet & Faucet Integration

#### Task 2.4: Wallet Creation Flow
**File:** `src/wallet/mod.rs` (NEW)

```rust
pub struct WalletManager {
    keystore_path: PathBuf,
}

impl WalletManager {
    /// Create new wallet with mnemonic
    pub fn create_wallet(&self, password: &str) -> Result<WalletInfo> {
        // 1. Generate mnemonic (BIP-39)
        let mnemonic = bip39::Mnemonic::new(MnemonicType::Words24, Language::English);

        // 2. Derive Starknet key (BIP-44 path: m/44'/9004'/0'/0/0)
        let seed = mnemonic.to_seed(password);
        let derived = derive_key(&seed, "m/44'/9004'/0'/0/0")?;

        // 3. Save encrypted keystore
        let keystore = encrypt_keystore(&derived, password)?;
        std::fs::write(&self.keystore_path, keystore)?;

        // 4. Generate address
        let public_key = get_public_key(&derived.private_key);
        let address = compute_address(&public_key)?;

        Ok(WalletInfo {
            address,
            mnemonic: mnemonic.phrase().to_string(),
        })
    }
}
```

**Checklist:**
- [ ] Implement BIP-39 mnemonic generation
- [ ] Implement BIP-44 key derivation for Starknet
- [ ] Implement encrypted keystore
- [ ] Add wallet import from mnemonic
- [ ] Add address computation

#### Task 2.5: Testnet Faucet Integration
**File:** `src/faucet/mod.rs` (NEW)

```rust
pub struct FaucetClient {
    endpoint: String,
}

impl FaucetClient {
    /// Request testnet tokens
    pub async fn request_tokens(&self, address: &str) -> Result<FaucetResult> {
        let response = self.client
            .post(&format!("{}/faucet", self.endpoint))
            .json(&FaucetRequest {
                address: address.to_string(),
                amount: 1000_000_000_000_000_000, // 1 ETH equivalent
            })
            .send()
            .await?;

        let result: FaucetResponse = response.json().await?;

        Ok(FaucetResult {
            tx_hash: result.transaction_hash,
            amount: result.amount,
        })
    }
}
```

**Checklist:**
- [ ] Implement faucet request
- [ ] Add rate limiting check
- [ ] Add balance verification
- [ ] Integrate with wallet creation
- [ ] Add retry logic

### Week 5-6: Worker Registration & P2P

#### Task 2.6: Complete Worker Registration Flow
**File:** `src/worker/registration.rs` (NEW)

```rust
pub struct WorkerRegistration {
    wallet: WalletManager,
    staking: StakingClient,
    reputation: ReputationClient,
    p2p: P2PNetwork,
}

impl WorkerRegistration {
    /// Full E2E worker registration
    pub async fn register(&self, config: WorkerConfig) -> Result<RegisteredWorker> {
        // 1. Create or load wallet
        let wallet = self.wallet.load_or_create(&config.keystore_password)?;
        tracing::info!("Wallet address: {}", wallet.address);

        // 2. Request testnet tokens (if needed)
        let balance = self.staking.get_balance(&wallet.address).await?;
        if balance < config.stake_amount {
            tracing::info!("Requesting faucet tokens...");
            self.faucet.request_tokens(&wallet.address).await?;
        }

        // 3. Stake tokens
        let stake_tx = self.staking.stake(
            config.stake_amount,
            config.gpu_tier,
            config.lock_duration,
        ).await?;
        tracing::info!("Staked {} SAGE: {}", config.stake_amount, stake_tx);

        // 4. Register worker on-chain
        let register_tx = self.staking.register_worker(
            &wallet.address,
            config.gpu_tier,
            &config.tee_quote,
        ).await?;
        tracing::info!("Registered worker: {}", register_tx);

        // 5. Initialize reputation
        self.reputation.initialize_reputation(&wallet.address).await?;

        // 6. Join P2P network
        self.p2p.join_network(&config.bootstrap_peers).await?;
        tracing::info!("Joined P2P network with {} peers", self.p2p.peer_count());

        // 7. Start heartbeat
        let heartbeat = self.start_heartbeat(&wallet.address);

        Ok(RegisteredWorker {
            address: wallet.address,
            stake: config.stake_amount,
            tier: config.gpu_tier,
            heartbeat,
        })
    }
}
```

**Checklist:**
- [ ] Implement full registration flow
- [ ] Add TEE quote generation
- [ ] Add P2P network join
- [ ] Add heartbeat mechanism
- [ ] Add graceful shutdown

#### Task 2.7: Worker CLI Commands
**File:** `src/bin/worker.rs`

```rust
#[derive(Parser)]
enum Command {
    /// Create new wallet
    CreateWallet {
        #[arg(short, long)]
        password: String,
    },

    /// Register worker on network
    Register {
        #[arg(short, long)]
        stake_amount: u128,
        #[arg(short, long)]
        gpu_tier: String,
    },

    /// Start worker node
    Start {
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Check worker status
    Status,

    /// Claim pending payments
    ClaimPayments,
}
```

**Checklist:**
- [ ] Add create-wallet command
- [ ] Add register command
- [ ] Add start command with config
- [ ] Add status command
- [ ] Add claim-payments command

---

## Integration Testing Plan

### Test Scenarios

| # | Scenario | Commands | Expected Result |
|---|----------|----------|-----------------|
| 1 | Wallet Creation | `sage-worker create-wallet` | Wallet created with mnemonic |
| 2 | Faucet Request | `sage-worker request-tokens` | 1 ETH received |
| 3 | Worker Stake | `sage-worker stake --amount 1000` | Stake confirmed on-chain |
| 4 | Worker Register | `sage-worker register` | Worker appears in network |
| 5 | Job Submission | `sage-coordinator submit-job` | Job queued |
| 6 | Proof Generation | Worker executes job | Proof generated with Stwo GPU |
| 7 | Validator Vote | Validators see proof | Consensus reached |
| 8 | Payment | Coordinator pays worker | ElGamal encrypted payment |
| 9 | Claim Payment | `sage-worker claim` | Payment decrypted, received |
| 10 | Slashing | Submit invalid proof | Worker stake slashed |

### E2E Test Script

```bash
#!/bin/bash
# Full E2E test script

# 1. Start coordinator
sage-coordinator start &

# 2. Create worker wallet
sage-worker create-wallet --password test123

# 3. Request testnet tokens
sage-worker request-tokens

# 4. Stake and register
sage-worker stake --amount 1000 --gpu-tier T4
sage-worker register

# 5. Start worker
sage-worker start &

# 6. Submit test job
JOB_ID=$(sage-coordinator submit-job --type matmul --size 1024)

# 7. Wait for completion
sage-coordinator wait-job $JOB_ID

# 8. Check proof
sage-coordinator verify-proof $JOB_ID

# 9. Claim payment
sage-worker claim

# 10. Check balance
sage-worker balance
```

---

## SDK & MCP Server Requirements

### SDK (For External Developers)

```rust
// Proposed SDK API
pub struct BitsageSDK {
    pub fn connect(endpoint: &str) -> Result<Self>;
    pub fn submit_job(job: JobSpec) -> Result<JobId>;
    pub fn get_job_status(job_id: JobId) -> Result<JobStatus>;
    pub fn get_proof(job_id: JobId) -> Result<StarkProof>;
    pub fn verify_proof(proof: &StarkProof) -> Result<bool>;
}
```

**SDK Features Needed:**
- [ ] Job submission API
- [ ] Proof retrieval API
- [ ] Verification API
- [ ] Payment tracking API
- [ ] Worker status API

### MCP Server (For Claude/AI Integration)

```typescript
// MCP Server Tools
const tools = {
  "bitsage_submit_job": {
    description: "Submit a computation job to Bitsage network",
    parameters: { job_type: "string", inputs: "object" },
  },
  "bitsage_get_proof": {
    description: "Get ZK proof for completed job",
    parameters: { job_id: "string" },
  },
  "bitsage_verify": {
    description: "Verify a ZK proof on-chain",
    parameters: { proof: "object" },
  },
};
```

**MCP Server Needs:**
- [ ] Tool definitions
- [ ] REST API bridge
- [ ] Authentication
- [ ] Rate limiting
- [ ] Error handling

---

## Timeline Summary

| Week | DEV 1 Tasks | DEV 2 Tasks |
|------|-------------|-------------|
| 1 | Proof pipeline, Randomness | Starknet signature, Contract deploy |
| 2 | Montgomery reduction | Staking verification |
| 3 | Payment integration | Wallet creation |
| 4 | Validator consensus | Faucet integration |
| 5 | TEE attestation | Worker registration CLI |
| 6 | BitSage-Validator bridge | E2E testing |
| 7-8 | Integration testing | Load testing, Audit prep |

---

## Success Criteria

### Production Ready Checklist

- [ ] Worker can create wallet from CLI
- [ ] Worker can receive testnet tokens from faucet
- [ ] Worker can stake and register on-chain
- [ ] Worker generates real Stwo proofs (GPU accelerated)
- [ ] Proofs verify on-chain
- [ ] Payments are ElGamal encrypted
- [ ] Workers can claim payments privately
- [ ] Validators reach consensus on proofs
- [ ] Invalid proofs trigger slashing
- [ ] TEE attestation is verified
- [ ] All 10 E2E test scenarios pass
- [ ] Load test: 100 concurrent workers
- [ ] Security audit complete

---

## Contact

**DEV 1:** STWO GPU + Obelysk + Privacy
**DEV 2:** Smart Contracts + Infrastructure

---

*Generated: 2025-12-27*
*Version: 1.0.0*
