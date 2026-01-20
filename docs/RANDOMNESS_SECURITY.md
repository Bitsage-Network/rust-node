# Randomness Security in BitSage Obelysk

## Overview

BitSage uses cryptographically secure randomness for all ElGamal encryption operations and zero-knowledge proofs. This document explains the security requirements and implementation.

## Security Requirements

### 1. Secure Random Number Generation

**Implementation:** `getrandom` crate v0.2
- **Linux:** `/dev/urandom` (CSPRNG)
- **macOS/iOS:** `SecRandomCopyBytes` (Apple Security Framework)
- **Windows:** `BCryptGenRandom` (CNG API)

**Why not `rand` crate?**
The `rand` crate provides deterministic PRNGs which are NOT suitable for cryptographic operations. We use `getrandom` which directly accesses OS-level CSPRNGs.

### 2. Randomness Usage

#### Payment Claim Nonces (Fixed)

**Before (INSECURE):**
```rust
// ⚠️ INSECURE: Deterministic nonce generation
let nonce = hash_felts(&[
    self.keypair.secret_key,
    Felt252::from_u128(job_id),
]);
```

**Problems:**
- Nonce is predictable from job_id
- Secret key used in deterministic hash (potential leakage)
- Cross-transaction correlation possible
- Vulnerable to chosen-plaintext attacks

**After (SECURE):**
```rust
// ✅ SECURE: Cryptographically secure randomness
let nonce = generate_randomness()
    .map_err(|e| anyhow!("Failed to generate secure nonce: {:?}", e))?;
```

**Benefits:**
- Unpredictable nonces
- No secret key exposure
- No cross-transaction correlation
- Replay protection via on-chain nullifier tracking

### 3. Replay Protection

Payment claims use **two layers of protection**:

1. **Random Nonce:** Generated using `getrandom` for each claim
2. **On-Chain Nullifier:** Smart contract tracks used nullifiers in `Map<felt252, bool>`

This allows:
- Safe retry of failed transactions (new nonce = new nullifier)
- Prevention of replay attacks
- No need for deterministic nonces

### 4. Randomness in ElGamal Operations

#### Encryption
```rust
pub fn encrypt_secure(amount: u64, public_key: &ECPoint) -> Result<ElGamalCiphertext> {
    let randomness = generate_randomness()?;
    Ok(encrypt(amount, public_key, &randomness))
}
```

#### Keypair Generation
```rust
pub fn generate_keypair() -> Result<KeyPair> {
    let secret_key = generate_randomness()?;
    Ok(KeyPair::from_secret(secret_key))
}
```

#### Decryption Proofs
```rust
pub fn create_decryption_proof_secure(
    keypair: &KeyPair,
    ciphertext: &ElGamalCiphertext,
) -> Result<EncryptionProof> {
    let nonce = generate_nonce()?;  // Uses generate_randomness()
    Ok(create_decryption_proof(keypair, ciphertext, &nonce))
}
```

## Implementation Details

### Core Function

```rust
/// Generate cryptographically secure randomness
///
/// Uses getrandom which provides access to OS random number generator:
/// - On Linux: /dev/urandom
/// - On macOS/iOS: SecRandomCopyBytes
/// - On Windows: BCryptGenRandom
/// - Value is automatically reduced mod STARK_PRIME by FieldElement
pub fn generate_randomness() -> Result<Felt252, CryptoError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::RngFailed)?;

    // Clear top bits for better distribution (STARK prime is ~2^251)
    // This ensures uniform distribution in the valid range
    bytes[0] &= 0x07;

    // FieldElement automatically handles modular reduction
    let felt = Felt252::from_be_bytes(&bytes);

    Ok(felt)
}
```

### Performance

Benchmarks on macOS (M1):
- **Average:** 5,700ns per call
- **Throughput:** ~175,000 random values/second
- **10,000 calls:** ~57ms

This is fast enough for all production use cases.

## Testing

Run security tests:
```bash
cargo test --test secure_randomness_test -- --nocapture
```

Tests verify:
- ✅ Uniqueness (1000 random values, no duplicates)
- ✅ Non-zero values (100 samples)
- ✅ Keypair uniqueness (100 keypairs)
- ✅ Performance (< 1ms per call)

## Security Audit Checklist

- [x] Use `getrandom` instead of `rand` for all crypto operations
- [x] Payment nonces use secure randomness (not deterministic)
- [x] ElGamal encryption uses secure randomness
- [x] Keypair generation uses secure randomness
- [x] Decryption proofs use secure nonces
- [x] No hardcoded test randomness in production code
- [x] Replay protection via on-chain nullifiers
- [x] Performance acceptable (< 1ms per call)

## Migration from Deterministic Nonces

### Before (v0.1.0)
```rust
// Deterministic nonce
let nonce = hash_felts(&[sk, job_id]);
```

### After (v0.2.0+)
```rust
// Secure random nonce
let nonce = generate_randomness()?;
```

**Note:** This is a **breaking change** for payment claims. Old deterministic nonces will not work with the new implementation. Workers must upgrade to v0.2.0+ for secure payment claims.

## References

- [getrandom crate documentation](https://docs.rs/getrandom/)
- [NIST SP 800-90A](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final) - Random Number Generation
- [RFC 4086](https://www.rfc-editor.org/rfc/rfc4086) - Randomness Requirements for Security

## Contact

For security issues related to randomness, contact: security@bitsage.network

---

*Last Updated: 2026-01-01*
*Version: 0.2.0*
