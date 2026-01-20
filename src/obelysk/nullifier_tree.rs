// Nullifier Tree - Incremental Merkle Tree for Privacy Nullifiers
//
// This module implements an Incremental Merkle Tree (IMT) for efficient
// nullifier management in privacy transactions. Based on protocols like
// Tornado Cash and Semaphore.
//
// Properties:
// - Append-only: Nullifiers can only be added, never removed
// - Fixed depth: 20 levels (supports 1M+ nullifiers)
// - Poseidon hash: Consistent with existing cryptographic primitives
// - Efficient proofs: O(log n) membership proofs

use std::collections::HashMap;
use std::sync::RwLock;
use crate::obelysk::elgamal::{Felt252, hash_felts};

/// Tree depth (20 levels = 2^20 = ~1M nullifiers)
pub const TREE_DEPTH: usize = 20;

/// Domain separator for nullifier tree hashing
const NULLIFIER_TREE_DOMAIN: u64 = 0x4E554C4C49464945; // "NULLIFIE" in hex

/// Pre-computed zero values for each level of the tree
/// zero[0] = hash(0, 0), zero[i] = hash(zero[i-1], zero[i-1])
fn compute_zero_values() -> [Felt252; TREE_DEPTH + 1] {
    let mut zeros = [Felt252::ZERO; TREE_DEPTH + 1];
    zeros[0] = Felt252::ZERO;

    for i in 1..=TREE_DEPTH {
        zeros[i] = hash_nodes(&zeros[i - 1], &zeros[i - 1]);
    }

    zeros
}

/// Hash two tree nodes together with domain separation
fn hash_nodes(left: &Felt252, right: &Felt252) -> Felt252 {
    hash_felts(&[
        Felt252::from_u64(NULLIFIER_TREE_DOMAIN),
        *left,
        *right,
    ])
}

/// Merkle proof for nullifier membership
#[derive(Debug, Clone, PartialEq)]
pub struct NullifierMerkleProof {
    /// Path from leaf to root (sibling hashes)
    pub path: Vec<Felt252>,
    /// Direction at each level (false = left, true = right)
    pub indices: Vec<bool>,
    /// The nullifier being proven
    pub nullifier: Felt252,
    /// Root at time of proof generation
    pub root: Felt252,
}

impl NullifierMerkleProof {
    /// Verify the proof is valid
    pub fn verify(&self) -> bool {
        if self.path.len() != TREE_DEPTH || self.indices.len() != TREE_DEPTH {
            return false;
        }

        let mut current = self.nullifier;

        for i in 0..TREE_DEPTH {
            current = if self.indices[i] {
                // Leaf is on the right
                hash_nodes(&self.path[i], &current)
            } else {
                // Leaf is on the left
                hash_nodes(&current, &self.path[i])
            };
        }

        current == self.root
    }

    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * (TREE_DEPTH + 2) + TREE_DEPTH);

        // Nullifier (32 bytes)
        bytes.extend_from_slice(&self.nullifier.to_be_bytes());

        // Root (32 bytes)
        bytes.extend_from_slice(&self.root.to_be_bytes());

        // Path (32 * TREE_DEPTH bytes)
        for sibling in &self.path {
            bytes.extend_from_slice(&sibling.to_be_bytes());
        }

        // Indices (TREE_DEPTH bits, packed into bytes)
        let mut index_bytes = vec![0u8; (TREE_DEPTH + 7) / 8];
        for (i, &is_right) in self.indices.iter().enumerate() {
            if is_right {
                index_bytes[i / 8] |= 1 << (i % 8);
            }
        }
        bytes.extend_from_slice(&index_bytes);

        bytes
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let expected_len = 32 * (TREE_DEPTH + 2) + (TREE_DEPTH + 7) / 8;
        if bytes.len() < expected_len {
            return None;
        }

        let nullifier = Felt252::from_be_bytes(bytes[0..32].try_into().ok()?);
        let root = Felt252::from_be_bytes(bytes[32..64].try_into().ok()?);

        let mut path = Vec::with_capacity(TREE_DEPTH);
        for i in 0..TREE_DEPTH {
            let start = 64 + i * 32;
            path.push(Felt252::from_be_bytes(bytes[start..start + 32].try_into().ok()?));
        }

        let index_start = 64 + TREE_DEPTH * 32;
        let mut indices = Vec::with_capacity(TREE_DEPTH);
        for i in 0..TREE_DEPTH {
            let is_right = (bytes[index_start + i / 8] >> (i % 8)) & 1 == 1;
            indices.push(is_right);
        }

        Some(NullifierMerkleProof {
            path,
            indices,
            nullifier,
            root,
        })
    }
}

/// Non-membership proof (proves nullifier is NOT in tree)
#[derive(Debug, Clone)]
pub struct NonMembershipProof {
    /// The nullifier we're proving is not in the tree
    pub nullifier: Felt252,
    /// Path to the position where nullifier would be
    pub path: Vec<Felt252>,
    /// Direction indices
    pub indices: Vec<bool>,
    /// Current root
    pub root: Felt252,
    /// The leaf at this position (should be zero/empty)
    pub leaf_value: Felt252,
}

impl NonMembershipProof {
    /// Verify the nullifier is NOT in the tree
    pub fn verify(&self) -> bool {
        if self.path.len() != TREE_DEPTH || self.indices.len() != TREE_DEPTH {
            return false;
        }

        // The leaf should be empty (zero)
        if self.leaf_value != Felt252::ZERO {
            return false;
        }

        // Verify the path leads to the root
        let mut current = self.leaf_value;

        for i in 0..TREE_DEPTH {
            current = if self.indices[i] {
                hash_nodes(&self.path[i], &current)
            } else {
                hash_nodes(&current, &self.path[i])
            };
        }

        current == self.root
    }
}

/// Incremental Merkle Tree for nullifiers
///
/// This implementation stores all internal nodes for accurate proof generation.
#[derive(Debug)]
pub struct IncrementalMerkleTree {
    /// Current tree root
    root: Felt252,
    /// Number of leaves inserted
    next_index: u64,
    /// Filled subtrees at each level (for efficient insertion)
    filled_subtrees: Vec<Felt252>,
    /// Pre-computed zero values for each level
    zeros: [Felt252; TREE_DEPTH + 1],
    /// All nullifiers in the tree (for proof generation)
    nullifiers: HashMap<Felt252, u64>,
    /// Historical roots for verification
    root_history: Vec<Felt252>,
    /// Maximum number of historical roots to keep
    max_root_history: usize,
    /// All internal node hashes: (level, index) -> hash
    nodes: HashMap<(usize, u64), Felt252>,
}

impl IncrementalMerkleTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        let zeros = compute_zero_values();
        let root = zeros[TREE_DEPTH];

        IncrementalMerkleTree {
            root,
            next_index: 0,
            filled_subtrees: zeros[..TREE_DEPTH].to_vec(),
            zeros,
            nullifiers: HashMap::new(),
            root_history: vec![root],
            max_root_history: 100,
            nodes: HashMap::new(),
        }
    }

    /// Get current root
    pub fn root(&self) -> Felt252 {
        self.root
    }

    /// Get number of nullifiers in tree
    pub fn size(&self) -> u64 {
        self.next_index
    }

    /// Check if tree is full
    pub fn is_full(&self) -> bool {
        self.next_index >= (1u64 << TREE_DEPTH)
    }

    /// Check if a nullifier exists in the tree
    pub fn contains(&self, nullifier: &Felt252) -> bool {
        self.nullifiers.contains_key(nullifier)
    }

    /// Check if a root is valid (current or historical)
    pub fn is_known_root(&self, root: &Felt252) -> bool {
        self.root_history.contains(root)
    }

    /// Insert a nullifier into the tree
    /// Returns the new root and the index where it was inserted
    pub fn insert(&mut self, nullifier: Felt252) -> Result<(Felt252, u64), NullifierTreeError> {
        if self.is_full() {
            return Err(NullifierTreeError::TreeFull);
        }

        if self.nullifiers.contains_key(&nullifier) {
            return Err(NullifierTreeError::DuplicateNullifier);
        }

        let index = self.next_index;
        let mut current_index = index;
        let mut current_hash = nullifier;

        // Store leaf
        self.nodes.insert((0, index), nullifier);

        // Update path from leaf to root
        for level in 0..TREE_DEPTH {
            let parent_index = current_index / 2;

            if current_index % 2 == 0 {
                // Left child: combine with zero on the right
                self.filled_subtrees[level] = current_hash;
                current_hash = hash_nodes(&current_hash, &self.zeros[level]);
            } else {
                // Right child: combine with filled subtree on the left
                current_hash = hash_nodes(&self.filled_subtrees[level], &current_hash);
            }

            // Store this node hash
            self.nodes.insert((level + 1, parent_index), current_hash);
            current_index = parent_index;
        }

        // Update state
        self.root = current_hash;
        self.next_index += 1;
        self.nullifiers.insert(nullifier, index);

        // Update root history
        self.root_history.push(self.root);
        if self.root_history.len() > self.max_root_history {
            self.root_history.remove(0);
        }

        Ok((self.root, index))
    }

    /// Generate membership proof for a nullifier
    pub fn generate_proof(&self, nullifier: &Felt252) -> Result<NullifierMerkleProof, NullifierTreeError> {
        let index = self.nullifiers.get(nullifier)
            .ok_or(NullifierTreeError::NullifierNotFound)?;

        self.generate_proof_at_index(*index, *nullifier)
    }

    /// Generate proof for nullifier at specific index
    fn generate_proof_at_index(&self, index: u64, nullifier: Felt252) -> Result<NullifierMerkleProof, NullifierTreeError> {
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut indices = Vec::with_capacity(TREE_DEPTH);
        let mut current_index = index;

        // Build path by finding sibling at each level
        for level in 0..TREE_DEPTH {
            let is_right = current_index % 2 == 1;
            indices.push(is_right);

            let sibling_index = if is_right {
                current_index - 1
            } else {
                current_index + 1
            };

            // Get sibling hash
            let sibling = self.get_node_hash(level, sibling_index);
            path.push(sibling);

            current_index /= 2;
        }

        Ok(NullifierMerkleProof {
            path,
            indices,
            nullifier,
            root: self.root,
        })
    }

    /// Get hash of node at specific level and index
    fn get_node_hash(&self, level: usize, index: u64) -> Felt252 {
        // Look up in the nodes HashMap first
        if let Some(&hash) = self.nodes.get(&(level, index)) {
            return hash;
        }

        // If not found, return zero value for this level
        self.zeros[level]
    }

    /// Batch insert multiple nullifiers
    pub fn batch_insert(&mut self, nullifiers: Vec<Felt252>) -> Result<Vec<(Felt252, u64)>, NullifierTreeError> {
        let mut results = Vec::with_capacity(nullifiers.len());

        for nullifier in nullifiers {
            let result = self.insert(nullifier)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Get all nullifiers in the tree (for debugging/testing)
    pub fn get_all_nullifiers(&self) -> Vec<(Felt252, u64)> {
        self.nullifiers.iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Serialize tree state for persistence
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Root (32 bytes)
        bytes.extend_from_slice(&self.root.to_be_bytes());

        // Next index (8 bytes)
        bytes.extend_from_slice(&self.next_index.to_le_bytes());

        // Filled subtrees (32 * TREE_DEPTH bytes)
        for subtree in &self.filled_subtrees {
            bytes.extend_from_slice(&subtree.to_be_bytes());
        }

        // Number of nullifiers (8 bytes)
        let num_nullifiers = self.nullifiers.len() as u64;
        bytes.extend_from_slice(&num_nullifiers.to_le_bytes());

        // Nullifiers (40 bytes each: 32 for nullifier + 8 for index)
        for (nullifier, index) in &self.nullifiers {
            bytes.extend_from_slice(&nullifier.to_be_bytes());
            bytes.extend_from_slice(&index.to_le_bytes());
        }

        bytes
    }

    /// Deserialize tree state
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 + 8 + 32 * TREE_DEPTH + 8 {
            return None;
        }

        let root = Felt252::from_be_bytes(bytes[0..32].try_into().ok()?);
        let next_index = u64::from_le_bytes(bytes[32..40].try_into().ok()?);

        let mut filled_subtrees = Vec::with_capacity(TREE_DEPTH);
        for i in 0..TREE_DEPTH {
            let start = 40 + i * 32;
            filled_subtrees.push(Felt252::from_be_bytes(bytes[start..start + 32].try_into().ok()?));
        }

        let num_nullifiers_start = 40 + TREE_DEPTH * 32;
        let num_nullifiers = u64::from_le_bytes(
            bytes[num_nullifiers_start..num_nullifiers_start + 8].try_into().ok()?
        ) as usize;

        let mut nullifiers = HashMap::with_capacity(num_nullifiers);
        let mut offset = num_nullifiers_start + 8;

        for _ in 0..num_nullifiers {
            if offset + 40 > bytes.len() {
                return None;
            }
            let nullifier = Felt252::from_be_bytes(bytes[offset..offset + 32].try_into().ok()?);
            let index = u64::from_le_bytes(bytes[offset + 32..offset + 40].try_into().ok()?);
            nullifiers.insert(nullifier, index);
            offset += 40;
        }

        let zeros = compute_zero_values();

        // Rebuild nodes HashMap by re-inserting all nullifiers
        let mut nodes = HashMap::new();
        let mut rebuilt_filled = zeros[..TREE_DEPTH].to_vec();

        // Sort nullifiers by index for proper rebuilding
        let mut sorted_nullifiers: Vec<_> = nullifiers.iter().collect();
        sorted_nullifiers.sort_by_key(|(_, &idx)| idx);

        for (&nullifier, &index) in sorted_nullifiers {
            nodes.insert((0, index), nullifier);

            let mut current_index = index;
            let mut current_hash = nullifier;

            for level in 0..TREE_DEPTH {
                let parent_index = current_index / 2;

                if current_index % 2 == 0 {
                    rebuilt_filled[level] = current_hash;
                    current_hash = hash_nodes(&current_hash, &zeros[level]);
                } else {
                    current_hash = hash_nodes(&rebuilt_filled[level], &current_hash);
                }

                nodes.insert((level + 1, parent_index), current_hash);
                current_index = parent_index;
            }
        }

        Some(IncrementalMerkleTree {
            root,
            next_index,
            filled_subtrees,
            zeros,
            nullifiers,
            root_history: vec![root],
            max_root_history: 100,
            nodes,
        })
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for the Merkle tree
pub struct ConcurrentNullifierTree {
    inner: RwLock<IncrementalMerkleTree>,
}

impl ConcurrentNullifierTree {
    /// Create a new concurrent tree
    pub fn new() -> Self {
        ConcurrentNullifierTree {
            inner: RwLock::new(IncrementalMerkleTree::new()),
        }
    }

    /// Get current root
    pub fn root(&self) -> Felt252 {
        self.inner.read().unwrap().root()
    }

    /// Check if nullifier exists
    pub fn contains(&self, nullifier: &Felt252) -> bool {
        self.inner.read().unwrap().contains(nullifier)
    }

    /// Insert nullifier (thread-safe)
    pub fn insert(&self, nullifier: Felt252) -> Result<(Felt252, u64), NullifierTreeError> {
        self.inner.write().unwrap().insert(nullifier)
    }

    /// Generate proof (thread-safe)
    pub fn generate_proof(&self, nullifier: &Felt252) -> Result<NullifierMerkleProof, NullifierTreeError> {
        self.inner.read().unwrap().generate_proof(nullifier)
    }

    /// Check if root is known
    pub fn is_known_root(&self, root: &Felt252) -> bool {
        self.inner.read().unwrap().is_known_root(root)
    }

    /// Get tree size
    pub fn size(&self) -> u64 {
        self.inner.read().unwrap().size()
    }
}

impl Default for ConcurrentNullifierTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors for nullifier tree operations
#[derive(Debug, Clone, PartialEq)]
pub enum NullifierTreeError {
    TreeFull,
    DuplicateNullifier,
    NullifierNotFound,
    InvalidProof,
    SerializationError,
}

impl std::fmt::Display for NullifierTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NullifierTreeError::TreeFull => write!(f, "Nullifier tree is full"),
            NullifierTreeError::DuplicateNullifier => write!(f, "Nullifier already exists"),
            NullifierTreeError::NullifierNotFound => write!(f, "Nullifier not found in tree"),
            NullifierTreeError::InvalidProof => write!(f, "Invalid merkle proof"),
            NullifierTreeError::SerializationError => write!(f, "Serialization error"),
        }
    }
}

impl std::error::Error for NullifierTreeError {}

/// Compute nullifier from secret and commitment
/// nullifier = H(secret, commitment, domain)
pub fn compute_nullifier(secret: &Felt252, commitment: &Felt252) -> Felt252 {
    hash_felts(&[
        Felt252::from_u64(NULLIFIER_TREE_DOMAIN),
        *secret,
        *commitment,
    ])
}

/// Verify a merkle proof against a known root
pub fn verify_nullifier_proof(proof: &NullifierMerkleProof, expected_root: &Felt252) -> bool {
    proof.root == *expected_root && proof.verify()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_values_consistency() {
        let zeros = compute_zero_values();

        // First zero should be ZERO
        assert_eq!(zeros[0], Felt252::ZERO);

        // Each subsequent zero should be hash of previous with itself
        for i in 1..=TREE_DEPTH {
            let expected = hash_nodes(&zeros[i - 1], &zeros[i - 1]);
            assert_eq!(zeros[i], expected);
        }
    }

    #[test]
    fn test_empty_tree_root() {
        let tree = IncrementalMerkleTree::new();
        let zeros = compute_zero_values();

        // Empty tree root should equal the zero value at top level
        assert_eq!(tree.root(), zeros[TREE_DEPTH]);
    }

    #[test]
    fn test_insert_single_nullifier() {
        let mut tree = IncrementalMerkleTree::new();
        let nullifier = Felt252::from_u64(12345);

        let (new_root, index) = tree.insert(nullifier).unwrap();

        assert_eq!(index, 0);
        assert_eq!(tree.size(), 1);
        assert!(tree.contains(&nullifier));
        assert_ne!(new_root, compute_zero_values()[TREE_DEPTH]);
    }

    #[test]
    fn test_insert_multiple_nullifiers() {
        let mut tree = IncrementalMerkleTree::new();

        for i in 0..10 {
            let nullifier = Felt252::from_u64(i * 1000 + 1);
            let (_, index) = tree.insert(nullifier).unwrap();
            assert_eq!(index, i);
        }

        assert_eq!(tree.size(), 10);
    }

    #[test]
    fn test_duplicate_nullifier_rejected() {
        let mut tree = IncrementalMerkleTree::new();
        let nullifier = Felt252::from_u64(99999);

        tree.insert(nullifier).unwrap();

        let result = tree.insert(nullifier);
        assert_eq!(result, Err(NullifierTreeError::DuplicateNullifier));
    }

    #[test]
    fn test_membership_proof() {
        let mut tree = IncrementalMerkleTree::new();

        // Insert some nullifiers
        let nullifiers: Vec<Felt252> = (0..5)
            .map(|i| Felt252::from_u64(i * 12345 + 1))
            .collect();

        for nullifier in &nullifiers {
            tree.insert(*nullifier).unwrap();
        }

        // Generate and verify proof for each
        for nullifier in &nullifiers {
            let proof = tree.generate_proof(nullifier).unwrap();
            assert!(proof.verify());
            assert_eq!(proof.nullifier, *nullifier);
            assert_eq!(proof.root, tree.root());
        }
    }

    #[test]
    fn test_proof_serialization() {
        let mut tree = IncrementalMerkleTree::new();
        let nullifier = Felt252::from_u64(54321);

        tree.insert(nullifier).unwrap();

        let proof = tree.generate_proof(&nullifier).unwrap();
        let bytes = proof.to_bytes();
        let restored = NullifierMerkleProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof, restored);
        assert!(restored.verify());
    }

    #[test]
    fn test_tree_serialization() {
        let mut tree = IncrementalMerkleTree::new();

        for i in 0..3 {
            tree.insert(Felt252::from_u64(i * 1111 + 1)).unwrap();
        }

        let bytes = tree.serialize();
        let restored = IncrementalMerkleTree::deserialize(&bytes).unwrap();

        assert_eq!(tree.root(), restored.root());
        assert_eq!(tree.size(), restored.size());
    }

    #[test]
    fn test_root_history() {
        let mut tree = IncrementalMerkleTree::new();
        let initial_root = tree.root();

        let (root1, _) = tree.insert(Felt252::from_u64(1)).unwrap();
        let (root2, _) = tree.insert(Felt252::from_u64(2)).unwrap();

        assert!(tree.is_known_root(&initial_root));
        assert!(tree.is_known_root(&root1));
        assert!(tree.is_known_root(&root2));

        // Unknown root should fail
        let unknown = Felt252::from_u64(999999);
        assert!(!tree.is_known_root(&unknown));
    }

    #[test]
    fn test_concurrent_tree() {
        let tree = ConcurrentNullifierTree::new();

        let nullifier = Felt252::from_u64(77777);
        tree.insert(nullifier).unwrap();

        assert!(tree.contains(&nullifier));
        assert_eq!(tree.size(), 1);

        let proof = tree.generate_proof(&nullifier).unwrap();
        assert!(proof.verify());
    }

    #[test]
    fn test_compute_nullifier() {
        let secret = Felt252::from_u64(12345);
        let commitment = Felt252::from_u64(67890);

        let nullifier = compute_nullifier(&secret, &commitment);

        // Should be deterministic
        let nullifier2 = compute_nullifier(&secret, &commitment);
        assert_eq!(nullifier, nullifier2);

        // Different inputs should give different nullifiers
        let nullifier3 = compute_nullifier(&secret, &Felt252::from_u64(99999));
        assert_ne!(nullifier, nullifier3);
    }

    #[test]
    fn test_batch_insert() {
        let mut tree = IncrementalMerkleTree::new();

        let nullifiers: Vec<Felt252> = (0..5)
            .map(|i| Felt252::from_u64(i * 10000 + 1))
            .collect();

        let results = tree.batch_insert(nullifiers.clone()).unwrap();

        assert_eq!(results.len(), 5);
        assert_eq!(tree.size(), 5);

        for nullifier in &nullifiers {
            assert!(tree.contains(nullifier));
        }
    }
}
