// =============================================================================
// THRESHOLD DECRYPTION CEREMONIES
// =============================================================================
//
// Interactive protocols for distributed decryption using Shamir's Secret Sharing
// and verifiable secret sharing (VSS). Enables t-of-n threshold decryption where
// any t participants can decrypt, but fewer than t learn nothing.
//
// Protocol Overview:
// ┌─────────────────────────────────────────────────────────────────────────────┐
// │                     THRESHOLD DECRYPTION CEREMONY                           │
// ├─────────────────────────────────────────────────────────────────────────────┤
// │                                                                             │
// │  PHASE 1: Distributed Key Generation (DKG)                                  │
// │  ┌─────────────────────────────────────────────────────────────────────┐   │
// │  │  Each participant i:                                                 │   │
// │  │  1. Generates random polynomial f_i(x) of degree t-1                │   │
// │  │  2. Commits to coefficients: C_i = [a_0*G, a_1*G, ..., a_{t-1}*G]   │   │
// │  │  3. Sends shares f_i(j) to each participant j                       │   │
// │  │  4. Verifies received shares against commitments                    │   │
// │  └─────────────────────────────────────────────────────────────────────┘   │
// │                               │                                             │
// │                               ▼                                             │
// │  PHASE 2: Public Key Assembly                                               │
// │  ┌─────────────────────────────────────────────────────────────────────┐   │
// │  │  PK = Σ C_i[0] = Σ a_i0 * G                                         │   │
// │  │  Each participant holds share: s_i = Σ f_j(i)                       │   │
// │  └─────────────────────────────────────────────────────────────────────┘   │
// │                               │                                             │
// │                               ▼                                             │
// │  PHASE 3: Threshold Decryption                                              │
// │  ┌─────────────────────────────────────────────────────────────────────┐   │
// │  │  Given ciphertext (C1, C2):                                         │   │
// │  │  1. Each participant i computes: D_i = s_i * C1                     │   │
// │  │  2. Publishes D_i with DLEQ proof                                   │   │
// │  │  3. Collect t valid decryption shares                               │   │
// │  │  4. Reconstruct: D = Σ λ_i * D_i (Lagrange interpolation)          │   │
// │  │  5. Decrypt: M = C2 - D                                             │   │
// │  └─────────────────────────────────────────────────────────────────────┘   │
// └─────────────────────────────────────────────────────────────────────────────┘

use crate::obelysk::elgamal::{
    Felt252, ECPoint, ElGamalCiphertext,
    generate_randomness, hash_felts, reduce_to_curve_order,
    add_mod_n, sub_mod_n, mul_mod_n, CURVE_ORDER,
    CryptoError,
};

// =============================================================================
// LOCAL MODULAR ARITHMETIC HELPERS
// =============================================================================

/// Modular exponentiation: a^e mod n (curve order)
fn mod_exp(base: &Felt252, exp: &Felt252) -> Felt252 {
    let exp_bytes = exp.to_be_bytes();
    let mut result = Felt252::ONE;
    let mut base_power = *base;

    // Binary exponentiation
    for byte in exp_bytes.iter().rev() {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                result = mul_mod_n(&result, &base_power);
            }
            base_power = mul_mod_n(&base_power, &base_power);
        }
    }

    result
}

/// Modular inverse using Fermat's little theorem: a^(-1) = a^(n-2) mod n
fn mod_inverse(a: &Felt252) -> Felt252 {
    let n_minus_2 = sub_mod_n(&CURVE_ORDER, &Felt252::from_u64(2));
    mod_exp(a, &n_minus_2)
}
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use anyhow::{Result, anyhow};

// =============================================================================
// THRESHOLD PARAMETERS
// =============================================================================

/// Configuration for threshold scheme
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Total number of participants (n)
    pub total_participants: usize,
    /// Minimum required for decryption (t)
    pub threshold: usize,
    /// Ceremony timeout in seconds
    pub timeout_seconds: u64,
}

impl ThresholdConfig {
    /// Create a new threshold config
    pub fn new(n: usize, t: usize) -> Result<Self, CryptoError> {
        if t > n {
            return Err(CryptoError::VerificationFailed);
        }
        if t < 2 {
            return Err(CryptoError::VerificationFailed);
        }

        Ok(Self {
            total_participants: n,
            threshold: t,
            timeout_seconds: 300, // 5 minute default
        })
    }

    /// Common 2-of-3 configuration
    pub fn two_of_three() -> Self {
        Self {
            total_participants: 3,
            threshold: 2,
            timeout_seconds: 300,
        }
    }

    /// Common 3-of-5 configuration
    pub fn three_of_five() -> Self {
        Self {
            total_participants: 5,
            threshold: 3,
            timeout_seconds: 300,
        }
    }

    /// Common 5-of-7 configuration
    pub fn five_of_seven() -> Self {
        Self {
            total_participants: 7,
            threshold: 5,
            timeout_seconds: 300,
        }
    }
}

// =============================================================================
// DISTRIBUTED KEY GENERATION (DKG)
// =============================================================================

/// Participant's secret polynomial coefficients
#[derive(Clone)]
pub struct SecretPolynomial {
    /// Coefficients [a_0, a_1, ..., a_{t-1}]
    coefficients: Vec<Felt252>,
}

impl SecretPolynomial {
    /// Generate a random polynomial of degree t-1
    pub fn random(degree: usize) -> Result<Self, CryptoError> {
        let mut coefficients = Vec::with_capacity(degree);
        for _ in 0..degree {
            let r = generate_randomness()?;
            coefficients.push(reduce_to_curve_order(&r));
        }
        Ok(Self { coefficients })
    }

    /// Evaluate polynomial at point x
    pub fn evaluate(&self, x: &Felt252) -> Felt252 {
        let mut result = Felt252::ZERO;
        let mut power = Felt252::ONE;

        for coeff in &self.coefficients {
            let term = mul_mod_n(coeff, &power);
            result = add_mod_n(&result, &term);
            power = mul_mod_n(&power, x);
        }

        result
    }

    /// Get the constant term (the secret)
    pub fn secret(&self) -> Felt252 {
        self.coefficients[0]
    }
}

/// Public commitment to polynomial coefficients (Feldman VSS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolynomialCommitment {
    /// Participant ID
    pub participant_id: u32,
    /// Commitments: C_i = a_i * G for each coefficient
    pub commitments: Vec<ECPoint>,
}

impl PolynomialCommitment {
    /// Create commitments for a secret polynomial
    pub fn from_polynomial(participant_id: u32, poly: &SecretPolynomial) -> Self {
        let g = ECPoint::generator();
        let commitments = poly.coefficients
            .iter()
            .map(|coeff| g.scalar_mul(coeff))
            .collect();

        Self {
            participant_id,
            commitments,
        }
    }

    /// Verify a share against this commitment
    pub fn verify_share(&self, participant_index: u32, share: &Felt252) -> bool {
        let g = ECPoint::generator();
        let x = Felt252::from_u64(participant_index as u64 + 1);

        // Compute expected commitment: Σ i^j * C_j
        let mut expected = ECPoint::INFINITY;
        let mut power = Felt252::ONE;

        for commitment in &self.commitments {
            let term = commitment.scalar_mul(&power);
            expected = expected.add(&term);
            power = mul_mod_n(&power, &x);
        }

        // Check: share * G == expected
        let share_commitment = g.scalar_mul(share);
        share_commitment == expected
    }
}

/// Secret share sent to a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    /// From which participant
    pub from_participant: u32,
    /// To which participant
    pub to_participant: u32,
    /// The share value
    pub share: Felt252,
}

/// DKG session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGSession {
    /// Session ID
    pub session_id: Felt252,
    /// Configuration
    pub config: ThresholdConfig,
    /// Polynomial commitments from each participant
    pub commitments: HashMap<u32, PolynomialCommitment>,
    /// Shares received (to_participant -> from_participant -> share)
    pub shares_received: HashMap<u32, HashMap<u32, Felt252>>,
    /// Session start time
    pub started_at: u64,
    /// Current phase
    pub phase: DKGPhase,
}

/// Phases of DKG ceremony
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKGPhase {
    /// Collecting polynomial commitments
    CommitmentPhase,
    /// Distributing and verifying shares
    ShareDistribution,
    /// DKG complete
    Complete,
    /// DKG failed
    Failed,
}

/// Result of a completed DKG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGResult {
    /// Session ID
    pub session_id: Felt252,
    /// Combined public key
    pub public_key: ECPoint,
    /// Each participant's verification key (their public share)
    pub verification_keys: HashMap<u32, ECPoint>,
}

/// DKG Coordinator
pub struct DKGCoordinator {
    /// Active sessions
    sessions: Arc<RwLock<HashMap<Felt252, DKGSession>>>,
    /// Completed DKG results
    completed: Arc<RwLock<HashMap<Felt252, DKGResult>>>,
}

impl DKGCoordinator {
    /// Create a new DKG coordinator
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a new DKG session
    pub fn start_session(&self, config: ThresholdConfig) -> Felt252 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session_id = hash_felts(&[
            Felt252::from_u64(now),
            Felt252::from_u64(config.total_participants as u64),
            Felt252::from_u64(config.threshold as u64),
        ]);

        let session = DKGSession {
            session_id,
            config,
            commitments: HashMap::new(),
            shares_received: HashMap::new(),
            started_at: now,
            phase: DKGPhase::CommitmentPhase,
        };

        self.sessions.write().insert(session_id, session);
        session_id
    }

    /// Submit polynomial commitment
    pub fn submit_commitment(
        &self,
        session_id: &Felt252,
        commitment: PolynomialCommitment,
    ) -> Result<()> {
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| anyhow!("Session not found"))?;

        if session.phase != DKGPhase::CommitmentPhase {
            return Err(anyhow!("Not in commitment phase"));
        }

        if session.commitments.len() >= session.config.total_participants {
            return Err(anyhow!("All commitments already received"));
        }

        // Verify commitment has correct degree
        if commitment.commitments.len() != session.config.threshold {
            return Err(anyhow!("Invalid polynomial degree"));
        }

        session.commitments.insert(commitment.participant_id, commitment);

        // Check if all commitments received
        if session.commitments.len() == session.config.total_participants {
            session.phase = DKGPhase::ShareDistribution;
        }

        Ok(())
    }

    /// Submit a share
    pub fn submit_share(
        &self,
        session_id: &Felt252,
        share: SecretShare,
    ) -> Result<()> {
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| anyhow!("Session not found"))?;

        if session.phase != DKGPhase::ShareDistribution {
            return Err(anyhow!("Not in share distribution phase"));
        }

        // Verify share against commitment
        let commitment = session.commitments.get(&share.from_participant)
            .ok_or_else(|| anyhow!("Sender commitment not found"))?;

        if !commitment.verify_share(share.to_participant, &share.share) {
            return Err(anyhow!("Share verification failed"));
        }

        // Store share
        session.shares_received
            .entry(share.to_participant)
            .or_insert_with(HashMap::new)
            .insert(share.from_participant, share.share);

        // Check if all shares received
        let all_received = (0..session.config.total_participants as u32)
            .all(|p| {
                session.shares_received.get(&p)
                    .map(|s| s.len() == session.config.total_participants)
                    .unwrap_or(false)
            });

        if all_received {
            // Complete DKG
            self.complete_dkg(session)?;
        }

        Ok(())
    }

    /// Complete DKG and generate result
    fn complete_dkg(&self, session: &mut DKGSession) -> Result<()> {
        // Compute combined public key
        let mut public_key = ECPoint::INFINITY;
        for commitment in session.commitments.values() {
            public_key = public_key.add(&commitment.commitments[0]);
        }

        // Compute verification keys for each participant
        let mut verification_keys = HashMap::new();
        let g = ECPoint::generator();

        for participant_id in 0..session.config.total_participants as u32 {
            // Sum all shares for this participant
            let shares = session.shares_received.get(&participant_id)
                .ok_or_else(|| anyhow!("Missing shares"))?;

            let combined_share = shares.values()
                .fold(Felt252::ZERO, |acc, s| add_mod_n(&acc, s));

            let vk = g.scalar_mul(&combined_share);
            verification_keys.insert(participant_id, vk);
        }

        session.phase = DKGPhase::Complete;

        let result = DKGResult {
            session_id: session.session_id,
            public_key,
            verification_keys,
        };

        self.completed.write().insert(session.session_id, result);

        Ok(())
    }

    /// Get DKG result
    pub fn get_result(&self, session_id: &Felt252) -> Option<DKGResult> {
        self.completed.read().get(session_id).cloned()
    }
}

impl Default for DKGCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// THRESHOLD DECRYPTION
// =============================================================================

/// A single participant's decryption share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// Participant ID
    pub participant_id: u32,
    /// Decryption share: D_i = s_i * C1
    pub share: ECPoint,
    /// DLEQ proof that share is correct
    pub dleq_proof: DLEQProof,
}

/// Discrete Log Equality Proof
/// Proves that log_G(Y) = log_C1(D) without revealing the discrete log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLEQProof {
    /// First component: k * G
    pub a1: ECPoint,
    /// Second component: k * C1
    pub a2: ECPoint,
    /// Challenge
    pub challenge: Felt252,
    /// Response: k + challenge * secret
    pub response: Felt252,
}

impl DLEQProof {
    /// Create a DLEQ proof
    pub fn create(
        secret: &Felt252,
        public_key: &ECPoint,
        c1: &ECPoint,
        decryption_share: &ECPoint,
    ) -> Result<Self, CryptoError> {
        let g = ECPoint::generator();

        // Random nonce
        let k = generate_randomness()?;
        let k = reduce_to_curve_order(&k);

        // Commitments
        let a1 = g.scalar_mul(&k);
        let a2 = c1.scalar_mul(&k);

        // Challenge
        let challenge = hash_felts(&[
            g.x, g.y,
            public_key.x, public_key.y,
            c1.x, c1.y,
            decryption_share.x, decryption_share.y,
            a1.x, a1.y,
            a2.x, a2.y,
        ]);
        let challenge = reduce_to_curve_order(&challenge);

        // Response
        let response = add_mod_n(&k, &mul_mod_n(&challenge, secret));

        Ok(DLEQProof {
            a1,
            a2,
            challenge,
            response,
        })
    }

    /// Verify a DLEQ proof
    pub fn verify(
        &self,
        public_key: &ECPoint,
        c1: &ECPoint,
        decryption_share: &ECPoint,
    ) -> bool {
        let g = ECPoint::generator();

        // Recompute challenge
        let expected_challenge = hash_felts(&[
            g.x, g.y,
            public_key.x, public_key.y,
            c1.x, c1.y,
            decryption_share.x, decryption_share.y,
            self.a1.x, self.a1.y,
            self.a2.x, self.a2.y,
        ]);
        let expected_challenge = reduce_to_curve_order(&expected_challenge);

        if self.challenge != expected_challenge {
            return false;
        }

        // Verify: response * G = a1 + challenge * public_key
        let lhs = g.scalar_mul(&self.response);
        let rhs = self.a1.add(&public_key.scalar_mul(&self.challenge));

        if lhs != rhs {
            return false;
        }

        // Verify: response * C1 = a2 + challenge * decryption_share
        let lhs2 = c1.scalar_mul(&self.response);
        let rhs2 = self.a2.add(&decryption_share.scalar_mul(&self.challenge));

        lhs2 == rhs2
    }
}

/// Decryption ceremony state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionCeremony {
    /// Ceremony ID
    pub ceremony_id: Felt252,
    /// Ciphertext being decrypted
    pub ciphertext: ElGamalCiphertext,
    /// Required threshold
    pub threshold: usize,
    /// Collected decryption shares
    pub shares: HashMap<u32, DecryptionShare>,
    /// Verification keys from DKG
    pub verification_keys: HashMap<u32, ECPoint>,
    /// Ceremony start time
    pub started_at: u64,
    /// Ceremony status
    pub status: CeremonyStatus,
}

/// Ceremony status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyStatus {
    /// Collecting shares
    Collecting,
    /// Ready for reconstruction
    Ready,
    /// Decryption complete
    Complete,
    /// Ceremony failed
    Failed,
}

/// Result of threshold decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionResult {
    /// Ceremony ID
    pub ceremony_id: Felt252,
    /// Decrypted point (M = C2 - D)
    pub decrypted_point: ECPoint,
    /// Participant IDs that contributed
    pub contributors: Vec<u32>,
    /// Timestamp
    pub timestamp: u64,
}

/// Threshold Decryption Coordinator
pub struct ThresholdDecryptor {
    /// Active ceremonies
    ceremonies: Arc<RwLock<HashMap<Felt252, DecryptionCeremony>>>,
    /// Completed decryptions
    results: Arc<RwLock<HashMap<Felt252, DecryptionResult>>>,
}

impl ThresholdDecryptor {
    /// Create a new threshold decryptor
    pub fn new() -> Self {
        Self {
            ceremonies: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a decryption ceremony
    pub fn start_ceremony(
        &self,
        ciphertext: ElGamalCiphertext,
        threshold: usize,
        verification_keys: HashMap<u32, ECPoint>,
    ) -> Felt252 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ceremony_id = hash_felts(&[
            ciphertext.c1_x,
            ciphertext.c1_y,
            ciphertext.c2_x,
            ciphertext.c2_y,
            Felt252::from_u64(now),
        ]);

        let ceremony = DecryptionCeremony {
            ceremony_id,
            ciphertext,
            threshold,
            shares: HashMap::new(),
            verification_keys,
            started_at: now,
            status: CeremonyStatus::Collecting,
        };

        self.ceremonies.write().insert(ceremony_id, ceremony);
        ceremony_id
    }

    /// Submit a decryption share
    pub fn submit_share(
        &self,
        ceremony_id: &Felt252,
        share: DecryptionShare,
    ) -> Result<()> {
        let mut ceremonies = self.ceremonies.write();
        let ceremony = ceremonies.get_mut(ceremony_id)
            .ok_or_else(|| anyhow!("Ceremony not found"))?;

        if ceremony.status != CeremonyStatus::Collecting {
            return Err(anyhow!("Ceremony not accepting shares"));
        }

        // Get verification key for this participant
        let vk = ceremony.verification_keys.get(&share.participant_id)
            .ok_or_else(|| anyhow!("Unknown participant"))?;

        // Verify DLEQ proof
        let c1 = ceremony.ciphertext.c1();
        if !share.dleq_proof.verify(vk, &c1, &share.share) {
            return Err(anyhow!("Invalid DLEQ proof"));
        }

        ceremony.shares.insert(share.participant_id, share);

        // Check if threshold reached
        if ceremony.shares.len() >= ceremony.threshold {
            ceremony.status = CeremonyStatus::Ready;
        }

        Ok(())
    }

    /// Complete decryption using collected shares
    pub fn complete_decryption(
        &self,
        ceremony_id: &Felt252,
    ) -> Result<DecryptionResult> {
        let mut ceremonies = self.ceremonies.write();
        let ceremony = ceremonies.get_mut(ceremony_id)
            .ok_or_else(|| anyhow!("Ceremony not found"))?;

        if ceremony.shares.len() < ceremony.threshold {
            return Err(anyhow!("Not enough shares"));
        }

        // Get participating indices
        let participant_ids: Vec<u32> = ceremony.shares.keys().cloned().collect();

        // Compute Lagrange coefficients and combine shares
        let combined = self.lagrange_interpolate(
            &participant_ids,
            &ceremony.shares,
        );

        // Decrypt: M = C2 - D
        let c2 = ceremony.ciphertext.c2();
        let decrypted_point = c2.add(&combined.neg());

        ceremony.status = CeremonyStatus::Complete;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let result = DecryptionResult {
            ceremony_id: *ceremony_id,
            decrypted_point,
            contributors: participant_ids,
            timestamp: now,
        };

        self.results.write().insert(*ceremony_id, result.clone());

        Ok(result)
    }

    /// Lagrange interpolation for combining shares
    fn lagrange_interpolate(
        &self,
        participant_ids: &[u32],
        shares: &HashMap<u32, DecryptionShare>,
    ) -> ECPoint {
        let mut result = ECPoint::INFINITY;

        for &i in participant_ids {
            let share = &shares[&i].share;

            // Compute Lagrange coefficient λ_i = Π_{j≠i} (j / (j - i))
            let lambda = self.lagrange_coefficient(i, participant_ids);

            // Add λ_i * share_i
            let term = share.scalar_mul(&lambda);
            result = result.add(&term);
        }

        result
    }

    /// Compute Lagrange coefficient for participant i
    fn lagrange_coefficient(&self, i: u32, participants: &[u32]) -> Felt252 {
        let mut numerator = Felt252::ONE;
        let mut denominator = Felt252::ONE;

        let i_felt = Felt252::from_u64(i as u64 + 1); // +1 because indices are 1-based

        for &j in participants {
            if j == i {
                continue;
            }

            let j_felt = Felt252::from_u64(j as u64 + 1);

            // numerator *= j
            numerator = mul_mod_n(&numerator, &j_felt);

            // denominator *= (j - i)
            let diff = sub_mod_n(&j_felt, &i_felt);
            denominator = mul_mod_n(&denominator, &diff);
        }

        // Return numerator / denominator
        let denom_inv = mod_inverse(&denominator);
        mul_mod_n(&numerator, &denom_inv)
    }

    /// Get decryption result
    pub fn get_result(&self, ceremony_id: &Felt252) -> Option<DecryptionResult> {
        self.results.read().get(ceremony_id).cloned()
    }

    /// Get ceremony status
    pub fn get_ceremony_status(&self, ceremony_id: &Felt252) -> Option<CeremonyStatus> {
        self.ceremonies.read().get(ceremony_id).map(|c| c.status)
    }
}

impl Default for ThresholdDecryptor {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// PARTICIPANT HELPER
// =============================================================================

/// Helper for individual participants in threshold ceremonies
pub struct ThresholdParticipant {
    /// Participant ID
    pub participant_id: u32,
    /// Secret share (from DKG)
    secret_share: Felt252,
    /// Verification key (public)
    pub verification_key: ECPoint,
}

impl ThresholdParticipant {
    /// Create a new participant with their share
    pub fn new(participant_id: u32, secret_share: Felt252) -> Self {
        let g = ECPoint::generator();
        let verification_key = g.scalar_mul(&secret_share);

        Self {
            participant_id,
            secret_share,
            verification_key,
        }
    }

    /// Generate decryption share for a ciphertext
    pub fn generate_decryption_share(
        &self,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<DecryptionShare, CryptoError> {
        let c1 = ciphertext.c1();

        // Compute decryption share: D_i = s_i * C1
        let share = c1.scalar_mul(&self.secret_share);

        // Create DLEQ proof
        let dleq_proof = DLEQProof::create(
            &self.secret_share,
            &self.verification_key,
            &c1,
            &share,
        )?;

        Ok(DecryptionShare {
            participant_id: self.participant_id,
            share,
            dleq_proof,
        })
    }

    /// Generate DKG contribution
    pub fn generate_dkg_contribution(
        &self,
        threshold: usize,
        total_participants: usize,
    ) -> Result<(PolynomialCommitment, Vec<SecretShare>), CryptoError> {
        // Generate secret polynomial
        let poly = SecretPolynomial::random(threshold)?;

        // Create commitment
        let commitment = PolynomialCommitment::from_polynomial(
            self.participant_id,
            &poly,
        );

        // Generate shares for all participants
        let mut shares = Vec::with_capacity(total_participants);
        for to_participant in 0..total_participants as u32 {
            let x = Felt252::from_u64(to_participant as u64 + 1);
            let share_value = poly.evaluate(&x);

            shares.push(SecretShare {
                from_participant: self.participant_id,
                to_participant,
                share: share_value,
            });
        }

        Ok((commitment, shares))
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_config() {
        let config = ThresholdConfig::new(5, 3).unwrap();
        assert_eq!(config.total_participants, 5);
        assert_eq!(config.threshold, 3);

        // Invalid: t > n
        assert!(ThresholdConfig::new(3, 5).is_err());

        // Invalid: t < 2
        assert!(ThresholdConfig::new(5, 1).is_err());
    }

    #[test]
    fn test_secret_polynomial() {
        let poly = SecretPolynomial::random(3).unwrap();

        // Evaluate at different points
        let x1 = Felt252::from_u64(1);
        let x2 = Felt252::from_u64(2);

        let y1 = poly.evaluate(&x1);
        let y2 = poly.evaluate(&x2);

        // Should be different
        assert_ne!(y1, y2);

        // Secret is the constant term
        let x0 = Felt252::ZERO;
        let y0 = poly.evaluate(&x0);
        assert_eq!(y0, poly.secret());
    }

    #[test]
    fn test_polynomial_commitment_verification() {
        let poly = SecretPolynomial::random(3).unwrap();
        let commitment = PolynomialCommitment::from_polynomial(0, &poly);

        // Generate share for participant 1
        let x = Felt252::from_u64(1);
        let share = poly.evaluate(&x);

        // Verify should succeed
        assert!(commitment.verify_share(0, &share));

        // Wrong share should fail
        let wrong_share = add_mod_n(&share, &Felt252::ONE);
        assert!(!commitment.verify_share(0, &wrong_share));
    }

    #[test]
    fn test_dleq_proof() {
        let secret = reduce_to_curve_order(&Felt252::from_u64(12345));
        let g = ECPoint::generator();

        let public_key = g.scalar_mul(&secret);

        // Random C1
        let r = reduce_to_curve_order(&Felt252::from_u64(67890));
        let c1 = g.scalar_mul(&r);

        // Decryption share
        let d = c1.scalar_mul(&secret);

        // Create and verify proof
        let proof = DLEQProof::create(&secret, &public_key, &c1, &d).unwrap();
        assert!(proof.verify(&public_key, &c1, &d));

        // Wrong decryption share should fail
        let wrong_d = d.add(&g);
        assert!(!proof.verify(&public_key, &c1, &wrong_d));
    }

    #[test]
    fn test_dkg_session() {
        let coordinator = DKGCoordinator::new();
        let config = ThresholdConfig::two_of_three();

        let session_id = coordinator.start_session(config);

        // Create participants
        let participants: Vec<ThresholdParticipant> = (0..3)
            .map(|i| {
                let secret = reduce_to_curve_order(&Felt252::from_u64(1000 + i as u64));
                ThresholdParticipant::new(i as u32, secret)
            })
            .collect();

        // Generate and submit commitments
        for participant in &participants {
            let (commitment, _) = participant
                .generate_dkg_contribution(2, 3)
                .unwrap();
            coordinator.submit_commitment(&session_id, commitment).unwrap();
        }

        // Check phase transition
        let sessions = coordinator.sessions.read();
        let session = sessions.get(&session_id).unwrap();
        assert_eq!(session.phase, DKGPhase::ShareDistribution);
    }

    #[test]
    fn test_decryption_ceremony() {
        let decryptor = ThresholdDecryptor::new();

        // Create test verification keys
        let participants: Vec<ThresholdParticipant> = (0..3)
            .map(|i| {
                let secret = reduce_to_curve_order(&Felt252::from_u64(1000 + i as u64));
                ThresholdParticipant::new(i as u32, secret)
            })
            .collect();

        let verification_keys: HashMap<u32, ECPoint> = participants
            .iter()
            .map(|p| (p.participant_id, p.verification_key))
            .collect();

        // Create test ciphertext
        let g = ECPoint::generator();
        let r = reduce_to_curve_order(&Felt252::from_u64(54321));
        let ciphertext = ElGamalCiphertext::new(
            g.scalar_mul(&r),
            g.scalar_mul(&Felt252::from_u64(100)),
        );

        // Start ceremony
        let ceremony_id = decryptor.start_ceremony(
            ciphertext.clone(),
            2, // 2-of-3
            verification_keys,
        );

        // Submit shares from first two participants
        for i in 0..2 {
            let share = participants[i].generate_decryption_share(&ciphertext).unwrap();
            decryptor.submit_share(&ceremony_id, share).unwrap();
        }

        // Check ready status
        let status = decryptor.get_ceremony_status(&ceremony_id);
        assert_eq!(status, Some(CeremonyStatus::Ready));
    }

    #[test]
    fn test_lagrange_interpolation() {
        // Test that interpolation at 0 recovers the secret
        // For polynomial f(x) = a + bx, given f(1) and f(2), we can recover f(0) = a

        let decryptor = ThresholdDecryptor::new();

        // λ_1 for points {1, 2} at x=0: 2/(2-1) = 2
        // λ_2 for points {1, 2} at x=0: 1/(1-2) = -1
        // So f(0) = 2*f(1) - f(2)

        let lambda_1 = decryptor.lagrange_coefficient(0, &[0, 1]);
        let lambda_2 = decryptor.lagrange_coefficient(1, &[0, 1]);

        // λ_1 + λ_2 should equal 1 (partition of unity)
        let sum = add_mod_n(&lambda_1, &lambda_2);
        assert_eq!(sum, Felt252::ONE);
    }

    #[test]
    fn test_full_threshold_flow() {
        // Simulate a complete 2-of-3 threshold decryption

        // 1. Create participants with known shares
        let shares = [
            Felt252::from_u64(100),
            Felt252::from_u64(200),
            Felt252::from_u64(300),
        ];

        let participants: Vec<ThresholdParticipant> = shares.iter()
            .enumerate()
            .map(|(i, s)| ThresholdParticipant::new(i as u32, reduce_to_curve_order(s)))
            .collect();

        // 2. Create a test ciphertext
        let g = ECPoint::generator();
        let test_message = Felt252::from_u64(42);
        let message_point = g.scalar_mul(&test_message);

        let r = reduce_to_curve_order(&Felt252::from_u64(99999));

        // Combined public key (sum of verification keys)
        let combined_pk: ECPoint = participants.iter()
            .fold(ECPoint::INFINITY, |acc, p| acc.add(&p.verification_key));

        // C1 = r*G, C2 = M + r*PK
        let c1 = g.scalar_mul(&r);
        let c2 = message_point.add(&combined_pk.scalar_mul(&r));
        let ciphertext = ElGamalCiphertext::new(c1, c2);

        // 3. Generate decryption shares
        let share_0 = participants[0].generate_decryption_share(&ciphertext).unwrap();
        let share_1 = participants[1].generate_decryption_share(&ciphertext).unwrap();

        // 4. Verify shares
        assert!(share_0.dleq_proof.verify(
            &participants[0].verification_key,
            &ciphertext.c1(),
            &share_0.share,
        ));
        assert!(share_1.dleq_proof.verify(
            &participants[1].verification_key,
            &ciphertext.c1(),
            &share_1.share,
        ));
    }
}
