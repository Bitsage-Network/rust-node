# Ideal Encrypted Privacy State - BitSage/Obelysk

## Executive Summary

This document defines the **Ideal Encrypted Privacy State** (IEPS) for BitSage/Obelysk - a comprehensive end-to-end encryption architecture where **no plaintext data is ever visible** to any party except the data owner, while still enabling verifiable computation and compliance.

---

## Core Privacy Principles

### 1. Zero-Knowledge Data Flow
```
User → Encrypted → Processed (encrypted) → Verified (ZK) → User decrypts
         ↑                                        ↓
    Only user has key              Proof reveals nothing about data
```

### 2. Privacy State Machine

Every piece of data has a **privacy state** that tracks its encryption lifecycle:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRIVACY STATE MACHINE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PLAINTEXT ──────────────────────────────────────────────────►  │
│      │                                                           │
│      │ encrypt(user_key)                                         │
│      ▼                                                           │
│  USER_ENCRYPTED ─────────────────────────────────────────────►  │
│      │                                                           │
│      │ re_encrypt(worker_fhe_key) [inside TEE only]             │
│      ▼                                                           │
│  FHE_ENCRYPTED ──────────────────────────────────────────────►  │
│      │                                                           │
│      │ compute_homomorphic(operation)                            │
│      ▼                                                           │
│  FHE_RESULT ─────────────────────────────────────────────────►  │
│      │                                                           │
│      │ generate_proof(stwo)                                      │
│      ▼                                                           │
│  PROVEN_ENCRYPTED ───────────────────────────────────────────►  │
│      │                                                           │
│      │ re_encrypt(user_key) [inside TEE only]                   │
│      ▼                                                           │
│  USER_RESULT_ENCRYPTED ──────────────────────────────────────►  │
│      │                                                           │
│      │ decrypt(user_key) [client-side only]                     │
│      ▼                                                           │
│  PLAINTEXT_RESULT (only visible to user)                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Architecture Layers

### Layer 0: Client-Side Encryption (Browser/SDK)

**Principle**: Data is encrypted BEFORE leaving the user's device.

```rust
pub struct ClientEncryptionLayer {
    /// User's master encryption key (never leaves device)
    master_key: MasterKey,

    /// FHE key pair for homomorphic operations
    fhe_keys: FheKeyPair,

    /// ElGamal key pair for payments
    payment_keys: ElGamalKeyPair,

    /// Viewing keys for auditors (derived, optional)
    viewing_keys: Option<ViewingKeySet>,
}

impl ClientEncryptionLayer {
    /// Encrypt job payload before submission
    pub fn encrypt_job_payload(&self, payload: &[u8]) -> EncryptedPayload {
        // 1. Generate ephemeral AES-256-GCM key
        let session_key = generate_session_key();

        // 2. Encrypt payload with session key
        let encrypted_data = aes_gcm_encrypt(payload, &session_key);

        // 3. Encrypt session key with FHE public key (for computation)
        let fhe_encrypted_key = self.fhe_keys.public.encrypt(&session_key);

        // 4. Encrypt session key with worker's TEE attestation key
        let tee_encrypted_key = tee_encrypt(&session_key, &worker_attestation);

        EncryptedPayload {
            data: encrypted_data,
            fhe_key: fhe_encrypted_key,
            tee_key: tee_encrypted_key,
            commitment: compute_commitment(payload),
        }
    }

    /// Encrypt payment amount (ElGamal)
    pub fn encrypt_payment(&self, amount: u256) -> EncryptedPayment {
        let (ciphertext, randomness) = self.payment_keys.encrypt(amount);
        let range_proof = create_range_proof(amount, &randomness, 64); // 64-bit

        EncryptedPayment {
            ciphertext,
            range_proof,
            commitment: pedersen_commit(amount, randomness),
        }
    }
}
```

### Layer 1: Transport Encryption

**Principle**: All network communication uses authenticated encryption.

```rust
pub struct TransportLayer {
    /// TLS 1.3 with certificate pinning
    tls_config: TlsConfig,

    /// Noise protocol for P2P (XX pattern)
    noise_config: NoiseConfig,

    /// Onion routing for metadata privacy (optional)
    onion_config: Option<OnionConfig>,
}

impl TransportLayer {
    /// Encrypt message for worker with forward secrecy
    pub fn encrypt_to_worker(&self, msg: &[u8], worker_id: &WorkerId) -> TransportMessage {
        // 1. Derive session key using X25519-ECDH + HKDF
        let (session_key, ephemeral_pk) = derive_session_key(worker_id);

        // 2. Encrypt with ChaCha20-Poly1305
        let ciphertext = chacha20_poly1305_encrypt(msg, &session_key);

        // 3. Optionally wrap in onion layers for metadata privacy
        let wrapped = if self.onion_config.is_some() {
            self.wrap_onion(ciphertext, worker_id)
        } else {
            ciphertext
        };

        TransportMessage {
            ephemeral_pk,
            ciphertext: wrapped,
            timestamp: now(),
        }
    }
}
```

### Layer 2: TEE Boundary Encryption

**Principle**: Data is only decrypted inside TEE hardware boundary.

```rust
pub struct TeeBoundary {
    /// TEE attestation quote (proves code/hardware integrity)
    attestation: AttestationQuote,

    /// Sealed storage key (bound to MRENCLAVE)
    sealed_key: SealedKey,

    /// Remote attestation service client
    ra_client: RemoteAttestationClient,
}

impl TeeBoundary {
    /// Decrypt user data ONLY inside TEE
    #[enclave_function]
    pub fn decrypt_in_tee(&self, encrypted: &EncryptedPayload) -> PlaintextData {
        // Verify we're running in genuine TEE
        assert!(is_inside_tee());

        // Decrypt session key with TEE's sealed key
        let session_key = unseal_key(&encrypted.tee_key, &self.sealed_key);

        // Decrypt payload
        let plaintext = aes_gcm_decrypt(&encrypted.data, &session_key);

        // CRITICAL: Plaintext NEVER leaves TEE memory
        // It's used only for computation, then wiped
        plaintext
    }

    /// Re-encrypt result for user
    #[enclave_function]
    pub fn encrypt_result_for_user(
        &self,
        result: &PlaintextData,
        user_pk: &FhePublicKey,
    ) -> EncryptedResult {
        // Encrypt with user's FHE key
        let fhe_encrypted = fhe_encrypt(result, user_pk);

        // Generate proof that encryption was done correctly
        let encryption_proof = create_encryption_proof(result, &fhe_encrypted);

        // Wipe plaintext from memory
        secure_zero(result);

        EncryptedResult {
            ciphertext: fhe_encrypted,
            encryption_proof,
            tee_attestation: self.attestation.clone(),
        }
    }
}
```

### Layer 3: FHE Computation Layer

**Principle**: All computation happens on encrypted data.

```rust
pub struct FheComputeLayer {
    /// Server key for homomorphic operations
    server_key: FheServerKey,

    /// Computation circuit (defines allowed operations)
    circuit: ComputeCircuit,

    /// IO commitment for proof binding
    io_binder: FheIOBinder,
}

impl FheComputeLayer {
    /// Execute computation on encrypted inputs
    pub fn execute_encrypted(
        &self,
        inputs: &[EncryptedValue],
        program: &FheProgram,
    ) -> ComputeResultWithProof<Vec<EncryptedValue>> {
        // Initialize IO binder
        let mut binder = FheIOBinder::new();
        for input in inputs {
            binder.add_encrypted_input(input);
        }

        // Execute program homomorphically (never decrypts!)
        let mut results = Vec::new();
        for op in &program.operations {
            let result = match op {
                FheOp::Add(a, b) => FheCompute::add(&inputs[*a], &inputs[*b], &self.server_key),
                FheOp::Mul(a, b) => FheCompute::mul(&inputs[*a], &inputs[*b], &self.server_key),
                FheOp::Compare(a, b) => FheCompute::lt(&inputs[*a], &inputs[*b], &self.server_key),
                // ... more operations
            };
            results.push(result?);
        }

        // Add outputs to IO binder
        for result in &results {
            binder.add_encrypted_output(result);
        }

        // Finalize commitment
        let io_commitment = binder.finalize();

        Ok(ComputeResultWithProof {
            result: results,
            io_commitment: Some(io_commitment),
            proof: None, // STWO proof added later
        })
    }
}
```

### Layer 4: Zero-Knowledge Proof Layer

**Principle**: Proofs verify correctness without revealing data.

```rust
pub struct ZkProofLayer {
    /// STWO prover (Circle STARK)
    stwo_prover: StwoProver,

    /// Proof compression
    compressor: ProofCompressor,

    /// Aggregation (batching)
    aggregator: ProofAggregator,
}

impl ZkProofLayer {
    /// Generate proof of correct FHE computation
    pub fn prove_fhe_computation(
        &self,
        trace: &FheExecutionTrace,
        io_commitment: &[u8; 32],
    ) -> StarkProof {
        // Build AIR constraints for FHE operations
        let air = FheAir::new(trace);

        // Generate Circle STARK proof
        let proof = self.stwo_prover.prove(&air, trace);

        // Embed IO commitment in proof
        let proof_with_io = embed_io_commitment(proof, io_commitment);

        // Compress for on-chain submission
        self.compressor.compress(&proof_with_io, CompressionLevel::Zstd)
    }

    /// Verify proof reveals nothing about inputs/outputs
    pub fn verify_zero_knowledge(&self, proof: &StarkProof) -> bool {
        // Statistical ZK: simulator can generate indistinguishable proofs
        // without knowing witness (FHE ciphertexts)
        self.stwo_prover.verify_zk_property(proof)
    }
}
```

### Layer 5: On-Chain Privacy Verification

**Principle**: Blockchain only sees commitments and proofs, never plaintext.

```cairo
// Cairo contract for privacy verification
#[starknet::contract]
mod PrivacyVerifier {
    struct Storage {
        // Commitment tree (hides actual values)
        commitment_tree_root: felt252,

        // Nullifier set (prevents double-spend)
        nullifier_set: Map<felt252, bool>,

        // Encrypted balances (ElGamal ciphertexts)
        encrypted_balances: Map<ContractAddress, EncryptedBalance>,

        // IO commitment registry (binds proofs to computations)
        io_commitments: Map<felt252, IOCommitmentRecord>,
    }

    /// Verify computation proof with full privacy
    fn verify_private_computation(
        ref self: ContractState,
        proof: StarkProof,
        io_commitment: felt252,
        encrypted_result_commitment: felt252,
    ) -> bool {
        // 1. Verify STWO proof is valid
        let proof_valid = self._verify_stark_proof(@proof);
        assert(proof_valid, 'Invalid STARK proof');

        // 2. Verify IO commitment is embedded in proof
        let io_valid = self._verify_io_commitment(@proof, io_commitment);
        assert(io_valid, 'IO commitment mismatch');

        // 3. Verify result commitment matches proof
        let result_valid = self._verify_result_commitment(@proof, encrypted_result_commitment);
        assert(result_valid, 'Result commitment mismatch');

        // 4. Register IO commitment (prevents replay)
        self.io_commitments.entry(io_commitment).write(IOCommitmentRecord {
            verified: true,
            timestamp: get_block_timestamp(),
            result_commitment: encrypted_result_commitment,
        });

        // NOTHING about the actual computation is revealed on-chain!
        // Only: proof is valid, commitments match, no replay
        true
    }

    /// Private transfer with encrypted amounts
    fn private_transfer(
        ref self: ContractState,
        sender_ciphertext: ElGamalCiphertext,
        receiver_ciphertext: ElGamalCiphertext,
        transfer_proof: TransferProof,
        nullifier: felt252,
    ) {
        // 1. Verify nullifier not used (prevents double-spend)
        assert(!self.nullifier_set.entry(nullifier).read(), 'Nullifier used');

        // 2. Verify same-encryption proof (sender encrypts same as receiver)
        let same_valid = self._verify_same_encryption(@transfer_proof);
        assert(same_valid, 'Different amounts encrypted');

        // 3. Verify range proof (non-negative amount)
        let range_valid = self._verify_range_proof(@transfer_proof, 64);
        assert(range_valid, 'Amount out of range');

        // 4. Verify balance sufficiency (encrypted balance >= encrypted amount)
        let balance_valid = self._verify_balance_proof(@transfer_proof);
        assert(balance_valid, 'Insufficient balance');

        // 5. Update encrypted balances homomorphically
        let sender_balance = self.encrypted_balances.entry(sender).read();
        let receiver_balance = self.encrypted_balances.entry(receiver).read();

        // Homomorphic subtraction/addition (no decryption!)
        self.encrypted_balances.entry(sender).write(
            elgamal_sub(sender_balance, sender_ciphertext)
        );
        self.encrypted_balances.entry(receiver).write(
            elgamal_add(receiver_balance, receiver_ciphertext)
        );

        // 6. Mark nullifier as used
        self.nullifier_set.entry(nullifier).write(true);

        // NOTHING about amounts or balances is revealed!
    }
}
```

### Layer 6: Compliance Privacy

**Principle**: Compliance verification without revealing transaction details.

```rust
pub struct CompliancePrivacyLayer {
    /// Threshold decryption keys for auditors
    auditor_keys: ThresholdKeySet,

    /// ZK compliance proofs
    compliance_prover: ComplianceProver,

    /// Encrypted audit log
    audit_log: EncryptedAuditLog,
}

impl CompliancePrivacyLayer {
    /// Generate ZK proof of AML compliance
    pub fn prove_aml_compliance(
        &self,
        transaction: &EncryptedTransaction,
        user_key: &ViewingKey,
    ) -> ComplianceProof {
        // Prove without revealing:
        // 1. Transaction amount < CTR threshold ($10,000)
        // 2. Sender/receiver not on sanctions list
        // 3. Transaction pattern not suspicious

        let proofs = vec![
            self.compliance_prover.prove_amount_threshold(
                transaction,
                10_000_00, // $10k in cents
            ),
            self.compliance_prover.prove_sanctions_clear(
                transaction,
                &self.sanctions_list_commitment,
            ),
            self.compliance_prover.prove_pattern_normal(
                transaction,
                &self.behavioral_model,
            ),
        ];

        ComplianceProof::aggregate(proofs)
    }

    /// Threshold decrypt for regulatory request (requires M-of-N auditors)
    pub async fn regulatory_decrypt(
        &self,
        transaction_id: &TransactionId,
        regulatory_request: &RegulatoryRequest,
        auditor_signatures: &[AuditorSignature],
    ) -> Option<DecryptedTransaction> {
        // Verify regulatory authority
        assert!(self.verify_regulatory_authority(regulatory_request));

        // Collect threshold signatures
        let valid_signatures = self.verify_auditor_signatures(auditor_signatures);
        assert!(valid_signatures.len() >= self.auditor_keys.threshold);

        // Threshold decrypt
        let shares: Vec<DecryptionShare> = valid_signatures
            .iter()
            .map(|sig| sig.decrypt_share)
            .collect();

        let decrypted = self.auditor_keys.threshold_decrypt(
            &self.get_encrypted_transaction(transaction_id),
            &shares,
        );

        // Log the regulatory access (encrypted)
        self.audit_log.log_regulatory_access(
            transaction_id,
            regulatory_request,
            &auditor_signatures,
        );

        Some(decrypted)
    }
}
```

---

## Privacy State Transitions

### State Enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyState {
    /// Raw plaintext (only exists on user device)
    Plaintext,

    /// Encrypted with user's key (can be stored/transmitted)
    UserEncrypted,

    /// Re-encrypted for FHE computation
    FheEncrypted,

    /// Result of FHE computation (still encrypted)
    FheResult,

    /// Has ZK proof attached (verifiable)
    ProvenEncrypted,

    /// Re-encrypted for user retrieval
    UserResultEncrypted,

    /// Encrypted for threshold auditor access
    AuditorEncrypted,

    /// Committed on-chain (hidden in commitment)
    Committed,

    /// Nullified (spent, cannot be reused)
    Nullified,
}

impl PrivacyState {
    /// Valid state transitions
    pub fn can_transition_to(&self, next: PrivacyState) -> bool {
        match (self, next) {
            // User encrypts their data
            (Plaintext, UserEncrypted) => true,

            // TEE re-encrypts for FHE (inside enclave only)
            (UserEncrypted, FheEncrypted) => true,

            // FHE computation produces result
            (FheEncrypted, FheResult) => true,

            // Proof attached to encrypted result
            (FheResult, ProvenEncrypted) => true,

            // Re-encrypt for user
            (ProvenEncrypted, UserResultEncrypted) => true,

            // User decrypts locally
            (UserResultEncrypted, Plaintext) => true,

            // Commit to chain
            (UserEncrypted, Committed) => true,
            (FheResult, Committed) => true,

            // Nullify (spend)
            (Committed, Nullified) => true,

            // Auditor access (threshold)
            (UserEncrypted, AuditorEncrypted) => true,
            (Committed, AuditorEncrypted) => true,

            _ => false,
        }
    }
}
```

### Privacy-Preserving Data Structure

```rust
/// Wrapper for data with privacy tracking
pub struct PrivateData<T> {
    /// Current privacy state
    state: PrivacyState,

    /// The data (encrypted in most states)
    data: PrivateDataInner,

    /// Commitments for verification
    commitment: Option<[u8; 32]>,

    /// Attached proofs
    proofs: Vec<AttachedProof>,

    /// IO binding commitment
    io_commitment: Option<[u8; 32]>,

    /// Audit trail (encrypted)
    audit_trail: Vec<EncryptedAuditEntry>,

    /// Phantom type marker
    _marker: PhantomData<T>,
}

enum PrivateDataInner {
    Plaintext(Vec<u8>),
    UserEncrypted(AesGcmCiphertext),
    FheEncrypted(FheCiphertext),
    ElGamalEncrypted(ElGamalCiphertext),
    Committed(Commitment),
    Nullified(Nullifier),
}

impl<T> PrivateData<T> {
    /// Encrypt plaintext data
    pub fn encrypt(plaintext: T, user_key: &UserEncryptionKey) -> Self {
        let serialized = serialize(&plaintext);
        let ciphertext = user_key.encrypt(&serialized);
        let commitment = compute_commitment(&serialized);

        Self {
            state: PrivacyState::UserEncrypted,
            data: PrivateDataInner::UserEncrypted(ciphertext),
            commitment: Some(commitment),
            proofs: vec![],
            io_commitment: None,
            audit_trail: vec![EncryptedAuditEntry::encryption(now())],
            _marker: PhantomData,
        }
    }

    /// Transition to FHE encryption (must be inside TEE)
    #[tee_only]
    pub fn convert_to_fhe(
        self,
        fhe_pk: &FhePublicKey,
        tee_attestation: &AttestationQuote,
    ) -> Result<Self, PrivacyError> {
        assert!(self.state.can_transition_to(PrivacyState::FheEncrypted));
        assert!(is_inside_tee());

        // Decrypt with TEE key, re-encrypt with FHE
        let plaintext = tee_decrypt(&self.data)?;
        let fhe_ciphertext = fhe_encrypt(&plaintext, fhe_pk);
        secure_zero(&plaintext);

        Ok(Self {
            state: PrivacyState::FheEncrypted,
            data: PrivateDataInner::FheEncrypted(fhe_ciphertext),
            commitment: self.commitment,
            proofs: vec![AttachedProof::TeeAttestation(tee_attestation.clone())],
            io_commitment: None,
            audit_trail: self.audit_trail.with_entry(
                EncryptedAuditEntry::fhe_conversion(now(), tee_attestation)
            ),
            _marker: PhantomData,
        })
    }

    /// Apply FHE operation
    pub fn apply_fhe_operation<U>(
        self,
        other: PrivateData<U>,
        op: FheOperation,
        server_key: &FheServerKey,
    ) -> Result<Self, PrivacyError> {
        assert_eq!(self.state, PrivacyState::FheEncrypted);
        assert_eq!(other.state, PrivacyState::FheEncrypted);

        let result = match op {
            FheOperation::Add => fhe_add(&self.data, &other.data, server_key),
            FheOperation::Mul => fhe_mul(&self.data, &other.data, server_key),
            // ...
        }?;

        // Build IO commitment
        let io_commitment = build_fhe_io_commitment(&self, &other, &result, op);

        Ok(Self {
            state: PrivacyState::FheResult,
            data: PrivateDataInner::FheEncrypted(result),
            commitment: None, // New commitment for result
            proofs: vec![],
            io_commitment: Some(io_commitment),
            audit_trail: self.audit_trail.with_entry(
                EncryptedAuditEntry::fhe_operation(now(), op)
            ),
            _marker: PhantomData,
        })
    }

    /// Attach ZK proof
    pub fn attach_proof(self, proof: StarkProof) -> Result<Self, PrivacyError> {
        assert!(self.state.can_transition_to(PrivacyState::ProvenEncrypted));

        Ok(Self {
            state: PrivacyState::ProvenEncrypted,
            proofs: self.proofs.with_proof(AttachedProof::Stark(proof)),
            ..self
        })
    }

    /// Verify all attached proofs
    pub fn verify(&self) -> bool {
        // Verify STARK proof
        let stark_valid = self.proofs.iter()
            .filter_map(|p| p.as_stark())
            .all(|p| verify_stark_proof(p));

        // Verify IO commitment matches proof
        let io_valid = self.io_commitment
            .map(|io| verify_io_commitment(&self.proofs, &io))
            .unwrap_or(true);

        // Verify TEE attestation if present
        let tee_valid = self.proofs.iter()
            .filter_map(|p| p.as_tee())
            .all(|a| verify_attestation(a));

        stark_valid && io_valid && tee_valid
    }
}
```

---

## Complete Privacy Flow Example

### AI Inference with Full Privacy

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PRIVATE AI INFERENCE FLOW                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  USER DEVICE                                                         │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ 1. User has sensitive data (e.g., medical image)           │     │
│  │    state: PLAINTEXT                                        │     │
│  │                                                            │     │
│  │ 2. Encrypt with FHE public key                             │     │
│  │    encrypted_data = FHE.encrypt(data, user_fhe_pk)         │     │
│  │    state: USER_ENCRYPTED → FHE_ENCRYPTED                   │     │
│  │                                                            │     │
│  │ 3. Generate encryption proof                               │     │
│  │    enc_proof = prove_valid_encryption(data, encrypted)     │     │
│  │                                                            │     │
│  │ 4. Compute commitment                                      │     │
│  │    commitment = H(encrypted_data)                          │     │
│  └────────────────────────────────────────────────────────────┘     │
│                              │                                       │
│                              ▼ (encrypted data + proof)              │
│  NETWORK (TLS 1.3 + Noise)                                          │
│                              │                                       │
│                              ▼                                       │
│  GPU WORKER (TEE: NVIDIA H100 CC)                                   │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ 5. Verify encryption proof (no decryption needed)          │     │
│  │    assert(verify_encryption_proof(enc_proof))              │     │
│  │                                                            │     │
│  │ 6. Execute AI model on FHE data                            │     │
│  │    // Model weights are FHE-encrypted too!                 │     │
│  │    for layer in model.layers:                              │     │
│  │        x = FHE.matmul(x, layer.weights_fhe)               │     │
│  │        x = FHE.relu(x) // Homomorphic ReLU                │     │
│  │    result_fhe = x                                          │     │
│  │    state: FHE_ENCRYPTED → FHE_RESULT                       │     │
│  │                                                            │     │
│  │ 7. Build IO commitment                                     │     │
│  │    io_commitment = H(input_fhe || result_fhe || model_id)  │     │
│  │                                                            │     │
│  │ 8. Generate STWO proof of correct execution                │     │
│  │    proof = STWO.prove(execution_trace, io_commitment)      │     │
│  │    state: FHE_RESULT → PROVEN_ENCRYPTED                    │     │
│  │                                                            │     │
│  │ 9. Attach TEE attestation                                  │     │
│  │    attestation = TEE.quote(H(proof || result_fhe))         │     │
│  └────────────────────────────────────────────────────────────┘     │
│                              │                                       │
│                              ▼ (encrypted result + proof + attest)   │
│  STARKNET (ON-CHAIN)                                                │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ 10. Verify STWO proof (reveals nothing about data)         │     │
│  │     assert(StwoVerifier.verify(proof))                     │     │
│  │                                                            │     │
│  │ 11. Verify IO commitment matches                           │     │
│  │     assert(proof.io_commitment == expected)                │     │
│  │                                                            │     │
│  │ 12. Verify TEE attestation                                 │     │
│  │     assert(TeeVerifier.verify(attestation))                │     │
│  │                                                            │     │
│  │ 13. Register result commitment                             │     │
│  │     results[job_id] = H(result_fhe)                        │     │
│  │     state: PROVEN_ENCRYPTED → COMMITTED                    │     │
│  │                                                            │     │
│  │ 14. Release payment (encrypted amount!)                    │     │
│  │     worker_balance += encrypted_payment                    │     │
│  └────────────────────────────────────────────────────────────┘     │
│                              │                                       │
│                              ▼ (encrypted result)                    │
│  USER DEVICE                                                         │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ 15. Decrypt result with user's FHE secret key              │     │
│  │     result = FHE.decrypt(result_fhe, user_fhe_sk)          │     │
│  │     state: USER_RESULT_ENCRYPTED → PLAINTEXT               │     │
│  │                                                            │     │
│  │ 16. Result visible ONLY to user!                           │     │
│  │     "AI prediction: benign"                                │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  PRIVACY GUARANTEES:                                                 │
│  ✓ Worker never sees plaintext data                                 │
│  ✓ Network never sees plaintext data                                │
│  ✓ Blockchain never sees plaintext data                             │
│  ✓ Only user can decrypt result                                     │
│  ✓ Proof verifies correctness without revealing data                │
│  ✓ IO commitment prevents proof reuse                               │
│  ✓ TEE attestation proves hardware integrity                        │
│  ✓ Payment amount is also encrypted!                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Security Properties

### 1. Data Confidentiality

| Layer | Protection | Against |
|-------|------------|---------|
| Client | FHE encryption | Worker, network, observers |
| Transport | TLS 1.3 + Noise | Network eavesdroppers |
| TEE | Hardware isolation | Compromised worker OS |
| Chain | Commitments only | Public blockchain observers |

### 2. Computation Integrity

| Mechanism | Guarantees |
|-----------|------------|
| STWO STARK | Correct program execution |
| IO Commitment | Proof bound to specific I/O |
| TEE Attestation | Genuine hardware, correct code |
| Range Proofs | Values in valid range |

### 3. Privacy Preservation

| Property | How Achieved |
|----------|--------------|
| Input privacy | FHE encryption |
| Output privacy | FHE encryption |
| Amount privacy | ElGamal + range proofs |
| Metadata privacy | Onion routing (optional) |
| Temporal privacy | Batched submissions |

### 4. Compliance Compatibility

| Requirement | Solution |
|-------------|----------|
| AML monitoring | ZK compliance proofs |
| Regulatory access | Threshold decryption (M-of-N) |
| Audit trail | Encrypted audit logs |
| Sanctions check | Set membership proofs |

---

## Implementation Priority

### Phase 1: Critical Fixes (Week 1)
1. Fix Schnorr signature arithmetic (curve order, not field prime)
2. Fix ElGamal H parameter (verifiable hash-to-curve)
3. Add client-side encryption SDK

### Phase 2: Core Privacy (Week 2-3)
4. Implement PrivacyState state machine
5. Implement PrivateData wrapper
6. Add FHE-to-UserEncrypted re-encryption in TEE

### Phase 3: Verification (Week 4-5)
7. Complete IO commitment verification on-chain
8. Add encryption proof verification
9. Implement compliance proofs

### Phase 4: Metadata Privacy (Week 6)
10. Optional onion routing for P2P
11. Batched transaction submission
12. Stealth addresses for workers

---

## Conclusion

The Ideal Encrypted Privacy State ensures:

1. **No plaintext ever leaves user device** (except final result)
2. **All computation on encrypted data** (FHE + TEE)
3. **Verifiable without revealing** (ZK proofs + commitments)
4. **Compliant without exposing** (threshold + ZK compliance)
5. **Auditable without decrypting** (encrypted audit logs)

This architecture provides **bank-grade privacy** while maintaining **full regulatory compliance** and **cryptographic verifiability**.
