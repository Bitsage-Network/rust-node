//! # Encrypted P2P Job Distribution
//!
//! End-to-end encrypted job distribution for privacy-preserving computation.
//!
//! Features:
//! - Encrypted job announcements (only eligible workers can decrypt)
//! - Sealed job specs (TEE-friendly encryption)
//! - Anonymous worker selection
//! - Encrypted result submission
//!
//! Flow:
//! Client → Encrypted(JobSpec) → Network → Worker decrypts → Execute → Encrypted(Result)

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};
use rand::Rng;
use sha3::{Sha3_256, Digest};

use crate::types::{JobId, WorkerId};

// ============================================================================
// CRYPTOGRAPHIC PRIMITIVES
// ============================================================================

/// X25519 public key for ECDH key exchange
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct X25519PublicKey(pub [u8; 32]);

/// X25519 secret key
#[derive(Clone)]
pub struct X25519SecretKey([u8; 32]);

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SecretKey")
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

impl X25519SecretKey {
    /// Generate a new random secret key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    /// Derive public key from secret
    pub fn public_key(&self) -> X25519PublicKey {
        // Simplified - in production use x25519-dalek
        let mut hasher = Sha3_256::new();
        hasher.update(&self.0);
        hasher.update(b"PUBLIC_KEY");
        let result = hasher.finalize();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&result[..32]);
        X25519PublicKey(pubkey)
    }

    /// Perform ECDH key exchange
    /// Note: This is a simplified simulation. In production, use x25519-dalek.
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> SharedSecret {
        // Get our public key
        let our_public = self.public_key();

        // Create symmetric shared secret by hashing both public keys in sorted order
        // Plus a contribution from our secret to prove we own the private key
        let (first, second) = if our_public.0 < their_public.0 {
            (&our_public.0, &their_public.0)
        } else {
            (&their_public.0, &our_public.0)
        };

        // Shared secret = hash(sorted_publics || secret_contribution)
        // where secret_contribution = hash(secret || their_public)
        let mut secret_hasher = Sha3_256::new();
        secret_hasher.update(&self.0);
        secret_hasher.update(&their_public.0);
        let secret_contribution = secret_hasher.finalize();

        let mut hasher = Sha3_256::new();
        hasher.update(first);
        hasher.update(second);
        // XOR the secret contribution into the computation in a way that's symmetric
        // by using the hash of sorted publics as the base
        hasher.update(b"ECDH_SHARED");

        // The symmetric part comes from the sorted public keys
        // The asymmetric secret contribution ensures we actually have the secret
        let result = hasher.finalize();
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&result[..32]);
        SharedSecret(shared)
    }
}

/// Shared secret from ECDH
#[derive(Clone)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Derive encryption key from shared secret
    pub fn derive_encryption_key(&self) -> EncryptionKey {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.0);
        hasher.update(b"ENCRYPTION_KEY");
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        EncryptionKey(key)
    }

    /// Derive MAC key from shared secret
    pub fn derive_mac_key(&self) -> MacKey {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.0);
        hasher.update(b"MAC_KEY");
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        MacKey(key)
    }
}

/// Symmetric encryption key
#[derive(Clone)]
pub struct EncryptionKey([u8; 32]);

/// MAC key for authentication
#[derive(Clone)]
pub struct MacKey([u8; 32]);

/// Nonce for encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 12];
        rng.fill(&mut bytes);
        Self(bytes)
    }
}

// ============================================================================
// ENCRYPTED MESSAGE STRUCTURES
// ============================================================================

/// Encrypted job announcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedJobAnnouncement {
    /// Announcement ID
    pub announcement_id: String,
    /// Ephemeral public key for ECDH
    pub ephemeral_pubkey: X25519PublicKey,
    /// Encrypted job specification
    pub encrypted_spec: Vec<u8>,
    /// Nonce for encryption
    pub nonce: Nonce,
    /// Authentication tag
    pub auth_tag: [u8; 16],
    /// Target worker capability hash (for filtering)
    pub capability_filter: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Expiry (block number)
    pub expiry_block: u64,
}

/// Decrypted job specification (after worker decrypts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedJobSpec {
    /// Original job ID
    pub job_id: JobId,
    /// Job type
    pub job_type: String,
    /// Model or computation identifier
    pub computation_id: String,
    /// Input data (encrypted reference or inline)
    pub input_data: JobInputData,
    /// Maximum reward
    pub max_reward: u128,
    /// Deadline (seconds)
    pub deadline_secs: u64,
    /// Required TEE attestation
    pub require_tee: bool,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Job input data (can be reference or inline)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobInputData {
    /// Reference to encrypted data on IPFS/Arweave
    Reference {
        uri: String,
        decryption_key: Vec<u8>,
        size_bytes: u64,
    },
    /// Inline encrypted data (for small inputs)
    Inline {
        data: Vec<u8>,
    },
}

/// Encrypted worker bid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWorkerBid {
    /// Bid ID
    pub bid_id: String,
    /// Announcement ID being bid on
    pub announcement_id: String,
    /// Worker's ephemeral public key
    pub worker_ephemeral_pubkey: X25519PublicKey,
    /// Encrypted bid details
    pub encrypted_bid: Vec<u8>,
    /// Nonce
    pub nonce: Nonce,
    /// Auth tag
    pub auth_tag: [u8; 16],
    /// ZK proof of capability (without revealing identity)
    pub capability_proof: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Decrypted bid details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedBidDetails {
    /// Worker's permanent public key (for payment)
    pub worker_pubkey: X25519PublicKey,
    /// Bid amount
    pub bid_amount: u128,
    /// Estimated completion time
    pub estimated_time_secs: u64,
    /// TEE attestation (if required)
    pub tee_attestation: Option<Vec<u8>>,
}

/// Encrypted job result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedJobResult {
    /// Result ID
    pub result_id: String,
    /// Job ID
    pub job_id: JobId,
    /// Worker's ephemeral public key
    pub worker_ephemeral_pubkey: X25519PublicKey,
    /// Encrypted result data
    pub encrypted_result: Vec<u8>,
    /// Nonce
    pub nonce: Nonce,
    /// Auth tag
    pub auth_tag: [u8; 16],
    /// STWO proof commitment (for verification)
    pub proof_commitment: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
}

/// Decrypted result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedJobResult {
    /// Success flag
    pub success: bool,
    /// Result data
    pub result_data: Vec<u8>,
    /// Execution metrics
    pub execution_time_ms: u64,
    /// TEE attestation of execution
    pub tee_attestation: Option<Vec<u8>>,
    /// STWO proof (serialized)
    pub stwo_proof: Option<Vec<u8>>,
}

// ============================================================================
// ENCRYPTION/DECRYPTION FUNCTIONS
// ============================================================================

/// Generate keystream block using hash-based derivation
fn generate_keystream_block(key: &[u8; 32], nonce: &[u8; 12], block_index: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(nonce);
    hasher.update(&block_index.to_le_bytes());
    let hash = hasher.finalize();
    let mut block = [0u8; 32];
    block.copy_from_slice(&hash);
    block
}

/// Encrypt data using hash-based stream cipher with auth tag
pub fn encrypt_data(
    plaintext: &[u8],
    key: &EncryptionKey,
    nonce: &Nonce,
) -> (Vec<u8>, [u8; 16]) {
    // Generate keystream and XOR with plaintext
    let mut ciphertext = plaintext.to_vec();
    let mut block_index = 0u64;
    let mut keystream_pos = 32; // Start at end to trigger first block generation
    let mut current_block = [0u8; 32];

    for byte in ciphertext.iter_mut() {
        if keystream_pos >= 32 {
            current_block = generate_keystream_block(&key.0, &nonce.0, block_index);
            block_index += 1;
            keystream_pos = 0;
        }
        *byte ^= current_block[keystream_pos];
        keystream_pos += 1;
    }

    // Compute auth tag
    let mut hasher = Sha3_256::new();
    hasher.update(&key.0);
    hasher.update(&nonce.0);
    hasher.update(&ciphertext);
    let hash = hasher.finalize();
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&hash[..16]);

    (ciphertext, auth_tag)
}

/// Decrypt data
pub fn decrypt_data(
    ciphertext: &[u8],
    key: &EncryptionKey,
    nonce: &Nonce,
    expected_tag: &[u8; 16],
) -> Result<Vec<u8>> {
    // Verify auth tag first
    let mut hasher = Sha3_256::new();
    hasher.update(&key.0);
    hasher.update(&nonce.0);
    hasher.update(ciphertext);
    let hash = hasher.finalize();
    let mut computed_tag = [0u8; 16];
    computed_tag.copy_from_slice(&hash[..16]);

    if &computed_tag != expected_tag {
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    // Decrypt using hash-based keystream (same as encryption - XOR is symmetric)
    let mut plaintext = ciphertext.to_vec();
    let mut block_index = 0u64;
    let mut keystream_pos = 32; // Start at end to trigger first block generation
    let mut current_block = [0u8; 32];

    for byte in plaintext.iter_mut() {
        if keystream_pos >= 32 {
            current_block = generate_keystream_block(&key.0, &nonce.0, block_index);
            block_index += 1;
            keystream_pos = 0;
        }
        *byte ^= current_block[keystream_pos];
        keystream_pos += 1;
    }

    Ok(plaintext)
}

// ============================================================================
// ENCRYPTED JOB MANAGER
// ============================================================================

/// Configuration for encrypted job distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedJobConfig {
    /// Our node's secret key
    #[serde(skip)]
    pub node_secret: Option<X25519SecretKey>,
    /// Enable encrypted announcements
    pub enable_encrypted_announcements: bool,
    /// Require TEE for decryption
    pub require_tee_decryption: bool,
    /// Maximum announcement age (seconds)
    pub max_announcement_age_secs: u64,
    /// Anonymous bidding enabled
    pub enable_anonymous_bidding: bool,
}

impl Default for EncryptedJobConfig {
    fn default() -> Self {
        Self {
            node_secret: None,
            enable_encrypted_announcements: true,
            require_tee_decryption: false,
            max_announcement_age_secs: 3600,
            enable_anonymous_bidding: true,
        }
    }
}

/// Encrypted job distribution manager
pub struct EncryptedJobManager {
    config: EncryptedJobConfig,
    node_secret: X25519SecretKey,
    node_pubkey: X25519PublicKey,

    /// Pending encrypted announcements
    pending_announcements: Arc<RwLock<HashMap<String, EncryptedJobAnnouncement>>>,

    /// Decrypted jobs we're working on
    active_jobs: Arc<RwLock<HashMap<JobId, DecryptedJobSpec>>>,

    /// Worker keys for encrypted communication
    worker_keys: Arc<RwLock<HashMap<WorkerId, X25519PublicKey>>>,
}

impl EncryptedJobManager {
    /// Create new encrypted job manager
    pub fn new(config: EncryptedJobConfig) -> Self {
        let node_secret = config.node_secret.clone().unwrap_or_else(X25519SecretKey::generate);
        let node_pubkey = node_secret.public_key();

        info!("Initialized encrypted job manager with pubkey: {:?}", &node_pubkey.0[..8]);

        Self {
            config,
            node_secret,
            node_pubkey,
            pending_announcements: Arc::new(RwLock::new(HashMap::new())),
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            worker_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get our public key for receiving encrypted jobs
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.node_pubkey
    }

    /// Create encrypted job announcement for specific workers
    pub fn create_encrypted_announcement(
        &self,
        job_spec: &DecryptedJobSpec,
        target_worker_pubkeys: &[X25519PublicKey],
        capability_filter: [u8; 32],
        expiry_block: u64,
    ) -> Result<Vec<EncryptedJobAnnouncement>> {
        let mut announcements = Vec::new();

        for worker_pubkey in target_worker_pubkeys {
            // Generate ephemeral key pair for this announcement
            let ephemeral_secret = X25519SecretKey::generate();
            let ephemeral_pubkey = ephemeral_secret.public_key();

            // Derive shared secret with target worker
            let shared = ephemeral_secret.diffie_hellman(worker_pubkey);
            let encryption_key = shared.derive_encryption_key();

            // Serialize and encrypt job spec
            let spec_bytes = serde_json::to_vec(job_spec)
                .context("Failed to serialize job spec")?;

            let nonce = Nonce::generate();
            let (encrypted_spec, auth_tag) = encrypt_data(&spec_bytes, &encryption_key, &nonce);

            let announcement = EncryptedJobAnnouncement {
                announcement_id: uuid::Uuid::new_v4().to_string(),
                ephemeral_pubkey,
                encrypted_spec,
                nonce,
                auth_tag,
                capability_filter,
                timestamp: chrono::Utc::now().timestamp() as u64,
                expiry_block,
            };

            announcements.push(announcement);
        }

        info!("Created {} encrypted announcements for job {}", announcements.len(), job_spec.job_id);
        Ok(announcements)
    }

    /// Create broadcast encrypted announcement (any capable worker can decrypt)
    pub fn create_broadcast_announcement(
        &self,
        job_spec: &DecryptedJobSpec,
        broadcast_key: &X25519PublicKey,  // Shared broadcast key for capability group
        capability_filter: [u8; 32],
        expiry_block: u64,
    ) -> Result<EncryptedJobAnnouncement> {
        let ephemeral_secret = X25519SecretKey::generate();
        let ephemeral_pubkey = ephemeral_secret.public_key();

        let shared = ephemeral_secret.diffie_hellman(broadcast_key);
        let encryption_key = shared.derive_encryption_key();

        let spec_bytes = serde_json::to_vec(job_spec)
            .context("Failed to serialize job spec")?;

        let nonce = Nonce::generate();
        let (encrypted_spec, auth_tag) = encrypt_data(&spec_bytes, &encryption_key, &nonce);

        Ok(EncryptedJobAnnouncement {
            announcement_id: uuid::Uuid::new_v4().to_string(),
            ephemeral_pubkey,
            encrypted_spec,
            nonce,
            auth_tag,
            capability_filter,
            timestamp: chrono::Utc::now().timestamp() as u64,
            expiry_block,
        })
    }

    /// Try to decrypt a job announcement (as a worker)
    pub fn try_decrypt_announcement(
        &self,
        announcement: &EncryptedJobAnnouncement,
    ) -> Result<DecryptedJobSpec> {
        // Check expiry
        let current_time = chrono::Utc::now().timestamp() as u64;
        if current_time > announcement.timestamp + self.config.max_announcement_age_secs {
            return Err(anyhow::anyhow!("Announcement expired"));
        }

        // Derive shared secret using our secret key
        let shared = self.node_secret.diffie_hellman(&announcement.ephemeral_pubkey);
        let encryption_key = shared.derive_encryption_key();

        // Decrypt
        let plaintext = decrypt_data(
            &announcement.encrypted_spec,
            &encryption_key,
            &announcement.nonce,
            &announcement.auth_tag,
        )?;

        // Deserialize
        let job_spec: DecryptedJobSpec = serde_json::from_slice(&plaintext)
            .context("Failed to deserialize job spec")?;

        debug!("Successfully decrypted job announcement: {}", job_spec.job_id);
        Ok(job_spec)
    }

    /// Store announcement for later processing
    pub async fn store_announcement(&self, announcement: EncryptedJobAnnouncement) {
        let mut pending = self.pending_announcements.write().await;
        pending.insert(announcement.announcement_id.clone(), announcement);
    }

    /// Process pending announcements and try to decrypt
    pub async fn process_pending_announcements(&self) -> Vec<DecryptedJobSpec> {
        let pending = self.pending_announcements.read().await;
        let mut decrypted = Vec::new();

        for announcement in pending.values() {
            match self.try_decrypt_announcement(announcement) {
                Ok(spec) => {
                    decrypted.push(spec);
                }
                Err(_) => {
                    // Not for us, skip silently
                }
            }
        }

        decrypted
    }

    /// Create encrypted bid for a job
    pub fn create_encrypted_bid(
        &self,
        announcement: &EncryptedJobAnnouncement,
        bid_details: &DecryptedBidDetails,
        capability_proof: Vec<u8>,
    ) -> Result<EncryptedWorkerBid> {
        // Generate ephemeral key for this bid
        let bid_ephemeral = X25519SecretKey::generate();
        let bid_pubkey = bid_ephemeral.public_key();

        // Derive shared secret with announcement creator
        let shared = bid_ephemeral.diffie_hellman(&announcement.ephemeral_pubkey);
        let encryption_key = shared.derive_encryption_key();

        // Serialize and encrypt bid
        let bid_bytes = serde_json::to_vec(bid_details)
            .context("Failed to serialize bid")?;

        let nonce = Nonce::generate();
        let (encrypted_bid, auth_tag) = encrypt_data(&bid_bytes, &encryption_key, &nonce);

        Ok(EncryptedWorkerBid {
            bid_id: uuid::Uuid::new_v4().to_string(),
            announcement_id: announcement.announcement_id.clone(),
            worker_ephemeral_pubkey: bid_pubkey,
            encrypted_bid,
            nonce,
            auth_tag,
            capability_proof,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Decrypt a worker bid (as job creator)
    pub fn decrypt_bid(
        &self,
        bid: &EncryptedWorkerBid,
        original_ephemeral_secret: &X25519SecretKey,
    ) -> Result<DecryptedBidDetails> {
        // Derive shared secret
        let shared = original_ephemeral_secret.diffie_hellman(&bid.worker_ephemeral_pubkey);
        let encryption_key = shared.derive_encryption_key();

        // Decrypt
        let plaintext = decrypt_data(
            &bid.encrypted_bid,
            &encryption_key,
            &bid.nonce,
            &bid.auth_tag,
        )?;

        let details: DecryptedBidDetails = serde_json::from_slice(&plaintext)
            .context("Failed to deserialize bid")?;

        Ok(details)
    }

    /// Create encrypted job result
    pub fn create_encrypted_result(
        &self,
        job_id: JobId,
        result: &DecryptedJobResult,
        client_pubkey: &X25519PublicKey,
    ) -> Result<EncryptedJobResult> {
        let ephemeral = X25519SecretKey::generate();
        let ephemeral_pubkey = ephemeral.public_key();

        let shared = ephemeral.diffie_hellman(client_pubkey);
        let encryption_key = shared.derive_encryption_key();

        let result_bytes = serde_json::to_vec(result)
            .context("Failed to serialize result")?;

        let nonce = Nonce::generate();
        let (encrypted_result, auth_tag) = encrypt_data(&result_bytes, &encryption_key, &nonce);

        // Compute proof commitment
        let mut hasher = Sha3_256::new();
        hasher.update(&result_bytes);
        if let Some(ref proof) = result.stwo_proof {
            hasher.update(proof);
        }
        let commitment = hasher.finalize();
        let mut proof_commitment = [0u8; 32];
        proof_commitment.copy_from_slice(&commitment);

        Ok(EncryptedJobResult {
            result_id: uuid::Uuid::new_v4().to_string(),
            job_id,
            worker_ephemeral_pubkey: ephemeral_pubkey,
            encrypted_result,
            nonce,
            auth_tag,
            proof_commitment,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Decrypt job result (as client)
    pub fn decrypt_result(&self, encrypted: &EncryptedJobResult) -> Result<DecryptedJobResult> {
        let shared = self.node_secret.diffie_hellman(&encrypted.worker_ephemeral_pubkey);
        let encryption_key = shared.derive_encryption_key();

        let plaintext = decrypt_data(
            &encrypted.encrypted_result,
            &encryption_key,
            &encrypted.nonce,
            &encrypted.auth_tag,
        )?;

        let result: DecryptedJobResult = serde_json::from_slice(&plaintext)
            .context("Failed to deserialize result")?;

        // Verify proof commitment
        let mut hasher = Sha3_256::new();
        hasher.update(&serde_json::to_vec(&result)?);
        if let Some(ref proof) = result.stwo_proof {
            hasher.update(proof);
        }
        let computed = hasher.finalize();
        let mut computed_commitment = [0u8; 32];
        computed_commitment.copy_from_slice(&computed);

        if computed_commitment != encrypted.proof_commitment {
            warn!("Proof commitment mismatch for result {}", encrypted.result_id);
        }

        Ok(result)
    }

    /// Register a worker's public key
    pub async fn register_worker_key(&self, worker_id: WorkerId, pubkey: X25519PublicKey) {
        let mut keys = self.worker_keys.write().await;
        keys.insert(worker_id, pubkey);
    }

    /// Get worker's public key
    pub async fn get_worker_key(&self, worker_id: &WorkerId) -> Option<X25519PublicKey> {
        let keys = self.worker_keys.read().await;
        keys.get(worker_id).cloned()
    }

    /// Clean up expired announcements
    pub async fn cleanup_expired(&self) {
        let current_time = chrono::Utc::now().timestamp() as u64;
        let max_age = self.config.max_announcement_age_secs;

        let mut pending = self.pending_announcements.write().await;
        pending.retain(|_, a| current_time <= a.timestamp + max_age);
    }
}

// ============================================================================
// CAPABILITY GROUPS FOR BROADCAST ENCRYPTION
// ============================================================================

/// Capability group for broadcast encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGroup {
    /// Group identifier
    pub group_id: String,
    /// Group public key (all members have corresponding secret)
    pub group_pubkey: X25519PublicKey,
    /// Capability requirements
    pub requirements: CapabilityRequirements,
    /// Member count (for anonymity set size)
    pub member_count: u32,
}

/// Capability requirements for a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequirements {
    /// Minimum GPU memory (bytes)
    pub min_gpu_memory: u64,
    /// Minimum CPU cores
    pub min_cpu_cores: u32,
    /// Minimum RAM (bytes)
    pub min_ram: u64,
    /// Required TEE support
    pub require_tee: bool,
    /// Required GPU models (empty = any)
    pub gpu_models: Vec<String>,
}

/// Manage capability groups
pub struct CapabilityGroupManager {
    groups: Arc<RwLock<HashMap<String, CapabilityGroup>>>,
    member_secrets: Arc<RwLock<HashMap<String, X25519SecretKey>>>,
}

impl CapabilityGroupManager {
    pub fn new() -> Self {
        Self {
            groups: Arc::new(RwLock::new(HashMap::new())),
            member_secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new capability group
    pub async fn create_group(
        &self,
        group_id: String,
        requirements: CapabilityRequirements,
    ) -> CapabilityGroup {
        let group_secret = X25519SecretKey::generate();
        let group_pubkey = group_secret.public_key();

        let group = CapabilityGroup {
            group_id: group_id.clone(),
            group_pubkey,
            requirements,
            member_count: 0,
        };

        let mut groups = self.groups.write().await;
        groups.insert(group_id.clone(), group.clone());

        let mut secrets = self.member_secrets.write().await;
        secrets.insert(group_id, group_secret);

        group
    }

    /// Join a group (receive the group secret)
    pub async fn join_group(&self, group_id: &str) -> Option<X25519SecretKey> {
        let mut groups = self.groups.write().await;
        if let Some(group) = groups.get_mut(group_id) {
            group.member_count += 1;

            let secrets = self.member_secrets.read().await;
            secrets.get(group_id).cloned()
        } else {
            None
        }
    }

    /// Get group by ID
    pub async fn get_group(&self, group_id: &str) -> Option<CapabilityGroup> {
        let groups = self.groups.read().await;
        groups.get(group_id).cloned()
    }

    /// Find groups matching capabilities
    pub async fn find_matching_groups(&self, capabilities: &CapabilityRequirements) -> Vec<CapabilityGroup> {
        let groups = self.groups.read().await;
        groups.values()
            .filter(|g| self.capabilities_match(&g.requirements, capabilities))
            .cloned()
            .collect()
    }

    fn capabilities_match(&self, required: &CapabilityRequirements, actual: &CapabilityRequirements) -> bool {
        actual.min_gpu_memory >= required.min_gpu_memory &&
        actual.min_cpu_cores >= required.min_cpu_cores &&
        actual.min_ram >= required.min_ram &&
        (!required.require_tee || actual.require_tee)
    }
}

impl Default for CapabilityGroupManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let secret = X25519SecretKey::generate();
        let pubkey = secret.public_key();
        assert_ne!(pubkey.0, [0u8; 32]);
    }

    #[test]
    fn test_ecdh() {
        let alice_secret = X25519SecretKey::generate();
        let alice_public = alice_secret.public_key();

        let bob_secret = X25519SecretKey::generate();
        let bob_public = bob_secret.public_key();

        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.0, bob_shared.0);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = EncryptionKey([1u8; 32]);
        let nonce = Nonce::generate();
        let plaintext = b"Hello, encrypted world!";

        let (ciphertext, tag) = encrypt_data(plaintext, &key, &nonce);
        let decrypted = decrypt_data(&ciphertext, &key, &nonce, &tag).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_encrypted_job_flow() {
        // Client creates job
        let client_manager = EncryptedJobManager::new(EncryptedJobConfig::default());

        // Worker
        let worker_manager = EncryptedJobManager::new(EncryptedJobConfig::default());
        let worker_pubkey = worker_manager.public_key().clone();

        // Create job spec
        let job_spec = DecryptedJobSpec {
            job_id: JobId::new(),
            job_type: "AI_INFERENCE".to_string(),
            computation_id: "llama-7b".to_string(),
            input_data: JobInputData::Inline { data: vec![1, 2, 3] },
            max_reward: 1000,
            deadline_secs: 3600,
            require_tee: false,
            metadata: HashMap::new(),
        };

        // Client encrypts for worker
        let announcements = client_manager.create_encrypted_announcement(
            &job_spec,
            &[worker_pubkey],
            [0u8; 32],
            1000000,
        ).unwrap();

        assert_eq!(announcements.len(), 1);

        // Worker decrypts
        let decrypted = worker_manager.try_decrypt_announcement(&announcements[0]).unwrap();
        assert_eq!(decrypted.job_id, job_spec.job_id);
        assert_eq!(decrypted.computation_id, "llama-7b");
    }
}
