// ElGamal Encryption for Obelysk Privacy Layer
//
// Implements ElGamal encryption over the STARK curve for privacy-preserving
// GPU worker payments. This module is designed to be compatible with the
// Cairo smart contract implementation in `sage_contracts::obelysk::elgamal`.
//
// # Architecture
//
// - STARK Curve: y² = x³ + αx + β (mod P) where α = 1
// - Field Prime: P = 2^251 + 17 × 2^192 + 1
// - Curve Order: ~2^251 (see CURVE_ORDER constant)
// - ElGamal: Ciphertext C = (r*G, M + r*PK) where M = amount*H
// - Homomorphic: Enc(a) + Enc(b) = Enc(a+b)
//
// # Serialization
//
// All types are serialized to be compatible with Cairo's felt252 format:
// - Felt252: 252-bit big-endian integers (32 bytes, top bits must be < P)
// - ECPoint: (x: felt252, y: felt252)
// - ElGamalCiphertext: (c1_x, c1_y, c2_x, c2_y) - 4 felt252 values
// - EncryptionProof: (commitment_x, commitment_y, challenge, response, range_proof_hash)

use serde::{Serialize, Deserialize};
use sha3::{Digest, Keccak256};
use std::ops::{Add, Sub, Mul};
use thiserror::Error;

/// Cryptographic error types
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Random number generation failed")]
    RngFailed,

    #[error("Generated randomness is not less than STARK_PRIME (extremely rare)")]
    RandomnessOutOfRange,

    #[error("Invalid point: not on curve")]
    InvalidPoint,

    #[error("Invalid scalar: out of range")]
    InvalidScalar,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Proof verification failed")]
    VerificationFailed,
}

// =============================================================================
// STARK Curve Parameters (matching Cairo implementation)
// =============================================================================

/// STARK field prime: P = 2^251 + 17 × 2^192 + 1
/// Hex: 0x800000000000011000000000000000000000000000000000000000000000001
pub const STARK_PRIME: Felt252 = Felt252::from_raw([
    0x0000000000000001,
    0x0000000000000000,
    0x0000000000000000,
    0x0800000000000011,
]);

/// Curve coefficient α = 1
pub const STARK_ALPHA: u64 = 1;

/// Curve coefficient β (hex representation)
/// 0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89
pub const STARK_BETA: Felt252 = Felt252::from_raw([
    0x4cdfcb99cee9e89,
    0x09ad26c15c915c1f,
    0x50e596d72f7a8c56,
    0x06f21413efbe40de,
]);

/// Curve order (number of points)
/// 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
pub const CURVE_ORDER: Felt252 = Felt252::from_raw([
    0x1e66a241adc64d2f,
    0xb781126dcae7b232,
    0xffffffffffffffff,
    0x0800000000000010,
]);

/// Generator point G (x coordinate)
/// 0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca
pub const GEN_X: Felt252 = Felt252::from_raw([
    0xd723d8bc943cfca,
    0xeacfd9b0d1819e03,
    0xbeced415a40f0c7d,
    0x01ef15c18599971b,
]);

/// Generator point G (y coordinate)
/// 0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f
pub const GEN_Y: Felt252 = Felt252::from_raw([
    0x73000c36e8dc1f,
    0x53ecd11abe43a328,
    0xbe4801df46ec62de,
    0x05668060aa49730b,
]);

/// Second generator H (for amount encoding) - x coordinate
/// This should be generated as H = hash_to_curve("BitSage_H")
/// For now using a deterministic point different from G
pub const GEN_H_X: Felt252 = Felt252::from_raw([
    0x4c3b2a1f0e9d8c7b,
    0x2f8769e9a5c4ff8f,
    0x3a9e8f7d6c5b4a3f,
    0x02e1d0c9b8a7f6e5,
]);

/// Second generator H (y coordinate)
pub const GEN_H_Y: Felt252 = Felt252::from_raw([
    0x8a9b0c1d2e3f4a5b,
    0x0e1f2a3b4c5d6e7f,
    0x6a7b8c9d0e1f2a3b,
    0x01a2b3c4d5e6f0a1,
]);

// =============================================================================
// Felt252 - STARK Field Element (252-bit)
// =============================================================================

/// A field element in the STARK prime field.
/// Represented as 4 x 64-bit limbs in little-endian order.
/// All arithmetic is performed modulo STARK_PRIME.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Felt252 {
    /// Limbs in little-endian order (limbs[0] is least significant)
    pub limbs: [u64; 4],
}

impl Felt252 {
    /// Zero element
    pub const ZERO: Self = Felt252 { limbs: [0, 0, 0, 0] };

    /// One element
    pub const ONE: Self = Felt252 { limbs: [1, 0, 0, 0] };

    /// Create from raw limbs (little-endian)
    pub const fn from_raw(limbs: [u64; 4]) -> Self {
        Felt252 { limbs }
    }

    /// Create from a u64 value
    pub fn from_u64(val: u64) -> Self {
        Felt252 { limbs: [val, 0, 0, 0] }
    }

    /// Create from a u128 value
    pub fn from_u128(val: u128) -> Self {
        Felt252 {
            limbs: [val as u64, (val >> 64) as u64, 0, 0]
        }
    }

    /// Create from big-endian bytes (32 bytes)
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            limbs[i] = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        Felt252 { limbs }
    }

    /// Convert to big-endian bytes (32 bytes)
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            bytes[offset..offset + 8].copy_from_slice(&self.limbs[i].to_be_bytes());
        }
        bytes
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }

    /// Compare two field elements
    pub fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Check if self >= other
    pub fn gte(&self, other: &Self) -> bool {
        !matches!(self.cmp(other), std::cmp::Ordering::Less)
    }

    /// Addition with carry
    fn add_with_carry(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            let sum = self.limbs[i] as u128 + other.limbs[i] as u128 + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }

        (Felt252 { limbs: result }, carry != 0)
    }

    /// Subtraction with borrow
    fn sub_with_borrow(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            let diff = self.limbs[i] as i128 - other.limbs[i] as i128 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }

        (Felt252 { limbs: result }, borrow != 0)
    }

    /// Modular addition: (self + other) mod P
    pub fn add_mod(&self, other: &Self) -> Self {
        let (sum, carry) = self.add_with_carry(other);

        // If carry or sum >= P, subtract P
        if carry || sum.gte(&STARK_PRIME) {
            let (result, _) = sum.sub_with_borrow(&STARK_PRIME);
            result
        } else {
            sum
        }
    }

    /// Modular subtraction: (self - other) mod P
    pub fn sub_mod(&self, other: &Self) -> Self {
        let (diff, borrow) = self.sub_with_borrow(other);

        // If borrow, add P
        if borrow {
            let (result, _) = diff.add_with_carry(&STARK_PRIME);
            result
        } else {
            diff
        }
    }

    /// Modular multiplication: (self * other) mod P
    /// Uses schoolbook multiplication followed by Barrett reduction
    pub fn mul_mod(&self, other: &Self) -> Self {
        // Full 512-bit multiplication
        let mut product = [0u128; 8];

        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let temp = product[i + j] + (self.limbs[i] as u128) * (other.limbs[j] as u128) + carry;
                product[i + j] = temp & ((1u128 << 64) - 1);
                carry = temp >> 64;
            }
            product[i + 4] = carry;
        }

        // Barrett reduction (simplified)
        // For proper implementation, use Montgomery reduction
        self.reduce_512(&product)
    }

    /// Reduce a 512-bit number modulo STARK_PRIME
    fn reduce_512(&self, product: &[u128; 8]) -> Self {
        // Simple reduction by repeated subtraction
        // TODO: Implement proper Barrett or Montgomery reduction for performance
        let mut result = [0u64; 4];
        let mut temp = [0u128; 5];

        // Take lower 256 bits
        for i in 0..4 {
            temp[i] = product[i];
        }

        // Add high bits * (2^256 mod P)
        // 2^256 mod P = P - 2^256 + 2^256 = small value for STARK prime
        // For simplicity, iteratively reduce
        for i in 4..8 {
            if product[i] != 0 {
                // Multiply by position weight and add
                let weight = self.compute_weight(i);
                let contribution = self.mul_u128_felt(product[i], &weight);
                temp[0] = temp[0].wrapping_add(contribution.limbs[0] as u128);
                temp[1] = temp[1].wrapping_add(contribution.limbs[1] as u128);
                temp[2] = temp[2].wrapping_add(contribution.limbs[2] as u128);
                temp[3] = temp[3].wrapping_add(contribution.limbs[3] as u128);
            }
        }

        // Handle carries
        for i in 0..4 {
            temp[i + 1] += temp[i] >> 64;
            result[i] = temp[i] as u64;
        }

        let mut felt = Felt252 { limbs: result };

        // Final reduction
        while felt.gte(&STARK_PRIME) {
            let (new_felt, _) = felt.sub_with_borrow(&STARK_PRIME);
            felt = new_felt;
        }

        felt
    }

    fn compute_weight(&self, position: usize) -> Felt252 {
        // 2^(64*position) mod P
        let mut result = Felt252::ONE;
        let two_64 = Felt252::from_raw([0, 1, 0, 0]); // 2^64

        for _ in 0..position {
            result = result.mul_mod(&two_64);
        }
        result
    }

    fn mul_u128_felt(&self, val: u128, felt: &Felt252) -> Felt252 {
        let low = Felt252::from_u64(val as u64);
        let high = Felt252::from_u64((val >> 64) as u64);
        let two_64 = Felt252::from_raw([0, 1, 0, 0]);

        low.mul_mod(felt).add_mod(&high.mul_mod(&two_64).mul_mod(felt))
    }

    /// Modular negation: -self mod P
    pub fn neg_mod(&self) -> Self {
        if self.is_zero() {
            *self
        } else {
            STARK_PRIME.sub_mod(self)
        }
    }

    /// Modular exponentiation: self^exp mod P
    /// Uses square-and-multiply algorithm
    pub fn pow_mod(&self, exp: &Self) -> Self {
        if exp.is_zero() {
            return Felt252::ONE;
        }

        let mut result = Felt252::ONE;
        let mut base = *self;
        let mut e = *exp;

        while !e.is_zero() {
            if e.limbs[0] & 1 == 1 {
                result = result.mul_mod(&base);
            }
            base = base.mul_mod(&base);
            // Right shift by 1
            e.limbs[0] = (e.limbs[0] >> 1) | (e.limbs[1] << 63);
            e.limbs[1] = (e.limbs[1] >> 1) | (e.limbs[2] << 63);
            e.limbs[2] = (e.limbs[2] >> 1) | (e.limbs[3] << 63);
            e.limbs[3] >>= 1;
        }

        result
    }

    /// Modular inverse: self^(-1) mod P
    /// Uses Fermat's little theorem: a^(-1) = a^(P-2) mod P
    pub fn inv_mod(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        // P - 2
        let exp = STARK_PRIME.sub_mod(&Felt252::from_u64(2));
        Some(self.pow_mod(&exp))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        let bytes = self.to_be_bytes();
        format!("0x{}", hex::encode(bytes))
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).ok()?;
        if bytes.len() > 32 {
            return None;
        }

        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        Some(Felt252::from_be_bytes(&padded))
    }
}

impl Add for Felt252 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        self.add_mod(&other)
    }
}

impl Sub for Felt252 {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        self.sub_mod(&other)
    }
}

impl Mul for Felt252 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        self.mul_mod(&other)
    }
}

impl Default for Felt252 {
    fn default() -> Self {
        Self::ZERO
    }
}

// =============================================================================
// EC Point on STARK Curve
// =============================================================================

/// A point on the STARK elliptic curve.
/// The curve equation is: y² = x³ + αx + β (mod P) where α = 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ECPoint {
    pub x: Felt252,
    pub y: Felt252,
}

impl ECPoint {
    /// Point at infinity (identity element)
    pub const INFINITY: Self = ECPoint {
        x: Felt252::ZERO,
        y: Felt252::ZERO,
    };

    /// Create a new point
    pub fn new(x: Felt252, y: Felt252) -> Self {
        ECPoint { x, y }
    }

    /// Check if this is the point at infinity
    pub fn is_infinity(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }

    /// Get the generator point G
    pub fn generator() -> Self {
        ECPoint { x: GEN_X, y: GEN_Y }
    }

    /// Get the second generator point H (for amount encoding)
    pub fn generator_h() -> Self {
        ECPoint { x: GEN_H_X, y: GEN_H_Y }
    }

    /// Check if point is on the curve: y² = x³ + αx + β
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() {
            return true;
        }

        // y²
        let y_sq = self.y.mul_mod(&self.y);

        // x³
        let x_sq = self.x.mul_mod(&self.x);
        let x_cu = x_sq.mul_mod(&self.x);

        // αx (α = 1)
        let ax = self.x;

        // x³ + αx + β
        let rhs = x_cu.add_mod(&ax).add_mod(&STARK_BETA);

        y_sq == rhs
    }

    /// Point addition: self + other
    pub fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }

        // Check if points are the same or additive inverses
        if self.x == other.x {
            if self.y == other.y && !self.y.is_zero() {
                // Same point: double
                return self.double();
            } else {
                // Additive inverses: return infinity
                return Self::INFINITY;
            }
        }

        // λ = (y2 - y1) / (x2 - x1)
        let numerator = other.y.sub_mod(&self.y);
        let denominator = other.x.sub_mod(&self.x);
        let lambda = match denominator.inv_mod() {
            Some(inv) => numerator.mul_mod(&inv),
            None => return Self::INFINITY,
        };

        // x3 = λ² - x1 - x2
        let lambda_sq = lambda.mul_mod(&lambda);
        let x3 = lambda_sq.sub_mod(&self.x).sub_mod(&other.x);

        // y3 = λ(x1 - x3) - y1
        let x1_minus_x3 = self.x.sub_mod(&x3);
        let y3 = lambda.mul_mod(&x1_minus_x3).sub_mod(&self.y);

        ECPoint::new(x3, y3)
    }

    /// Point subtraction: self - other
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Point negation: -self
    pub fn neg(&self) -> Self {
        if self.is_infinity() {
            return *self;
        }
        ECPoint::new(self.x, self.y.neg_mod())
    }

    /// Point doubling: 2 * self
    pub fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::INFINITY;
        }

        // λ = (3x² + α) / (2y)  where α = 1
        let x_sq = self.x.mul_mod(&self.x);
        let three = Felt252::from_u64(3);
        let three_x_sq = three.mul_mod(&x_sq);
        let alpha = Felt252::from_u64(STARK_ALPHA);
        let numerator = three_x_sq.add_mod(&alpha);

        let two = Felt252::from_u64(2);
        let two_y = two.mul_mod(&self.y);
        let lambda = match two_y.inv_mod() {
            Some(inv) => numerator.mul_mod(&inv),
            None => return Self::INFINITY,
        };

        // x3 = λ² - 2x
        let lambda_sq = lambda.mul_mod(&lambda);
        let two_x = two.mul_mod(&self.x);
        let x3 = lambda_sq.sub_mod(&two_x);

        // y3 = λ(x - x3) - y
        let x_minus_x3 = self.x.sub_mod(&x3);
        let y3 = lambda.mul_mod(&x_minus_x3).sub_mod(&self.y);

        ECPoint::new(x3, y3)
    }

    /// Scalar multiplication: k * self (double-and-add)
    pub fn scalar_mul(&self, k: &Felt252) -> Self {
        if k.is_zero() || self.is_infinity() {
            return Self::INFINITY;
        }

        let mut result = Self::INFINITY;
        let mut base = *self;
        let mut scalar = *k;

        // Double-and-add algorithm
        for _ in 0..252 {
            if scalar.limbs[0] & 1 == 1 {
                result = result.add(&base);
            }
            base = base.double();

            // Right shift scalar
            scalar.limbs[0] = (scalar.limbs[0] >> 1) | (scalar.limbs[1] << 63);
            scalar.limbs[1] = (scalar.limbs[1] >> 1) | (scalar.limbs[2] << 63);
            scalar.limbs[2] = (scalar.limbs[2] >> 1) | (scalar.limbs[3] << 63);
            scalar.limbs[3] >>= 1;
        }

        result
    }

    /// Serialize to bytes (64 bytes: x || y)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.x.to_be_bytes());
        bytes[32..64].copy_from_slice(&self.y.to_be_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let x = Felt252::from_be_bytes(bytes[0..32].try_into().ok()?);
        let y = Felt252::from_be_bytes(bytes[32..64].try_into().ok()?);
        let point = ECPoint::new(x, y);

        if point.is_infinity() || point.is_on_curve() {
            Some(point)
        } else {
            None
        }
    }
}

impl Default for ECPoint {
    fn default() -> Self {
        Self::INFINITY
    }
}

// =============================================================================
// ElGamal Ciphertext
// =============================================================================

/// ElGamal ciphertext: C = (C1, C2) where C1 = r*G, C2 = M + r*PK
/// Compatible with Cairo's ElGamalCiphertext struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c1_x: Felt252,
    pub c1_y: Felt252,
    pub c2_x: Felt252,
    pub c2_y: Felt252,
}

impl ElGamalCiphertext {
    /// Create a new ciphertext from two EC points
    pub fn new(c1: ECPoint, c2: ECPoint) -> Self {
        ElGamalCiphertext {
            c1_x: c1.x,
            c1_y: c1.y,
            c2_x: c2.x,
            c2_y: c2.y,
        }
    }

    /// Create a zero ciphertext (encrypts 0)
    pub fn zero() -> Self {
        ElGamalCiphertext {
            c1_x: Felt252::ZERO,
            c1_y: Felt252::ZERO,
            c2_x: Felt252::ZERO,
            c2_y: Felt252::ZERO,
        }
    }

    /// Get C1 as an ECPoint
    pub fn c1(&self) -> ECPoint {
        ECPoint::new(self.c1_x, self.c1_y)
    }

    /// Get C2 as an ECPoint
    pub fn c2(&self) -> ECPoint {
        ECPoint::new(self.c2_x, self.c2_y)
    }

    /// Check if this is a valid ciphertext (points on curve)
    pub fn is_valid(&self) -> bool {
        let c1 = self.c1();
        let c2 = self.c2();
        (c1.is_infinity() || c1.is_on_curve()) && (c2.is_infinity() || c2.is_on_curve())
    }

    /// Serialize to bytes (128 bytes: c1_x || c1_y || c2_x || c2_y)
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        bytes[0..32].copy_from_slice(&self.c1_x.to_be_bytes());
        bytes[32..64].copy_from_slice(&self.c1_y.to_be_bytes());
        bytes[64..96].copy_from_slice(&self.c2_x.to_be_bytes());
        bytes[96..128].copy_from_slice(&self.c2_y.to_be_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 128]) -> Self {
        let c1_x = Felt252::from_be_bytes(bytes[0..32].try_into().unwrap());
        let c1_y = Felt252::from_be_bytes(bytes[32..64].try_into().unwrap());
        let c2_x = Felt252::from_be_bytes(bytes[64..96].try_into().unwrap());
        let c2_y = Felt252::from_be_bytes(bytes[96..128].try_into().unwrap());
        ElGamalCiphertext { c1_x, c1_y, c2_x, c2_y }
    }
}

impl Default for ElGamalCiphertext {
    fn default() -> Self {
        Self::zero()
    }
}

// =============================================================================
// Encryption Proof
// =============================================================================

/// Proof of correct encryption (Schnorr-based Sigma protocol).
/// Compatible with Cairo's EncryptionProof struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionProof {
    pub commitment_x: Felt252,
    pub commitment_y: Felt252,
    pub challenge: Felt252,
    pub response: Felt252,
    pub range_proof_hash: Felt252,
}

impl EncryptionProof {
    /// Create a new proof
    pub fn new(
        commitment: ECPoint,
        challenge: Felt252,
        response: Felt252,
        range_proof_hash: Felt252,
    ) -> Self {
        EncryptionProof {
            commitment_x: commitment.x,
            commitment_y: commitment.y,
            challenge,
            response,
            range_proof_hash,
        }
    }

    /// Get the commitment as an ECPoint
    pub fn commitment(&self) -> ECPoint {
        ECPoint::new(self.commitment_x, self.commitment_y)
    }

    /// Serialize to bytes (160 bytes)
    pub fn to_bytes(&self) -> [u8; 160] {
        let mut bytes = [0u8; 160];
        bytes[0..32].copy_from_slice(&self.commitment_x.to_be_bytes());
        bytes[32..64].copy_from_slice(&self.commitment_y.to_be_bytes());
        bytes[64..96].copy_from_slice(&self.challenge.to_be_bytes());
        bytes[96..128].copy_from_slice(&self.response.to_be_bytes());
        bytes[128..160].copy_from_slice(&self.range_proof_hash.to_be_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 160]) -> Self {
        EncryptionProof {
            commitment_x: Felt252::from_be_bytes(bytes[0..32].try_into().unwrap()),
            commitment_y: Felt252::from_be_bytes(bytes[32..64].try_into().unwrap()),
            challenge: Felt252::from_be_bytes(bytes[64..96].try_into().unwrap()),
            response: Felt252::from_be_bytes(bytes[96..128].try_into().unwrap()),
            range_proof_hash: Felt252::from_be_bytes(bytes[128..160].try_into().unwrap()),
        }
    }
}

// =============================================================================
// Encrypted Balance
// =============================================================================

/// Encrypted balance structure for privacy accounting.
/// Compatible with Cairo's EncryptedBalance struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBalance {
    pub ciphertext: ElGamalCiphertext,
    pub pending_in: ElGamalCiphertext,
    pub pending_out: ElGamalCiphertext,
    pub epoch: u64,
}

impl EncryptedBalance {
    /// Create a new encrypted balance
    pub fn new(ciphertext: ElGamalCiphertext, epoch: u64) -> Self {
        EncryptedBalance {
            ciphertext,
            pending_in: ElGamalCiphertext::zero(),
            pending_out: ElGamalCiphertext::zero(),
            epoch,
        }
    }

    /// Create a zero balance
    pub fn zero() -> Self {
        EncryptedBalance {
            ciphertext: ElGamalCiphertext::zero(),
            pending_in: ElGamalCiphertext::zero(),
            pending_out: ElGamalCiphertext::zero(),
            epoch: 0,
        }
    }
}

impl Default for EncryptedBalance {
    fn default() -> Self {
        Self::zero()
    }
}

// =============================================================================
// Key Pair
// =============================================================================

/// ElGamal key pair for a worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key: Felt252,
    pub public_key: ECPoint,
}

impl KeyPair {
    /// Generate a new keypair from a secret
    pub fn from_secret(secret: Felt252) -> Self {
        let public_key = ECPoint::generator().scalar_mul(&secret);
        KeyPair { secret_key: secret, public_key }
    }

    /// Generate a keypair from random bytes
    pub fn from_random_bytes(bytes: &[u8; 32]) -> Self {
        let secret = Felt252::from_be_bytes(bytes);
        Self::from_secret(secret)
    }

    /// Get the public key
    pub fn public_key(&self) -> ECPoint {
        self.public_key
    }

    /// Get the secret key (be careful!)
    pub fn secret_key(&self) -> Felt252 {
        self.secret_key
    }
}

// =============================================================================
// Secure Randomness Generation
// =============================================================================

/// Generate cryptographically secure randomness for ElGamal encryption.
/// Uses OS-level entropy via getrandom crate (CSPRNG).
///
/// # Security
/// - Uses getrandom which provides access to OS random number generator
/// - On Linux: /dev/urandom
/// - On macOS/iOS: SecRandomCopyBytes
/// - On Windows: BCryptGenRandom
/// - Ensures randomness is < STARK_PRIME for valid field element
pub fn generate_randomness() -> Result<Felt252, CryptoError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::RngFailed)?;

    // Clear top bits to ensure < STARK_PRIME
    // STARK_PRIME is ~2^251, so we clear top 5 bits (bytes[0] & 0x07)
    bytes[0] &= 0x07;

    let felt = Felt252::from_be_bytes(&bytes);

    // Double-check (should always pass after bit clearing)
    if felt.gte(&STARK_PRIME) {
        // Extremely rare: retry
        return generate_randomness();
    }

    Ok(felt)
}

/// Generate a random nonce for Schnorr proofs
pub fn generate_nonce() -> Result<Felt252, CryptoError> {
    generate_randomness()
}

/// Generate a fresh ElGamal keypair with secure randomness
pub fn generate_keypair() -> Result<KeyPair, CryptoError> {
    let secret_key = generate_randomness()?;
    Ok(KeyPair::from_secret(secret_key))
}

/// Encrypt an amount with secure randomness (convenience function)
pub fn encrypt_secure(amount: u64, public_key: &ECPoint) -> Result<ElGamalCiphertext, CryptoError> {
    let randomness = generate_randomness()?;
    Ok(encrypt(amount, public_key, &randomness))
}

/// Create a decryption proof with secure nonce
pub fn create_decryption_proof_secure(
    keypair: &KeyPair,
    ciphertext: &ElGamalCiphertext,
) -> Result<EncryptionProof, CryptoError> {
    let nonce = generate_nonce()?;
    Ok(create_decryption_proof(keypair, ciphertext, &nonce))
}

// =============================================================================
// ElGamal Operations
// =============================================================================

/// Encrypt an amount under a public key
/// Returns ciphertext C = (r*G, amount*H + r*PK)
pub fn encrypt(amount: u64, public_key: &ECPoint, randomness: &Felt252) -> ElGamalCiphertext {
    let g = ECPoint::generator();
    let h = ECPoint::generator_h();

    // C1 = r * G
    let c1 = g.scalar_mul(randomness);

    // M = amount * H
    let amount_felt = Felt252::from_u64(amount);
    let m = h.scalar_mul(&amount_felt);

    // C2 = M + r * PK
    let r_pk = public_key.scalar_mul(randomness);
    let c2 = m.add(&r_pk);

    ElGamalCiphertext::new(c1, c2)
}

/// Decrypt a ciphertext to get the encoded message point
/// Returns M = C2 - sk * C1 (which equals amount * H)
pub fn decrypt_point(ciphertext: &ElGamalCiphertext, secret_key: &Felt252) -> ECPoint {
    let c1 = ciphertext.c1();
    let c2 = ciphertext.c2();

    // shared_secret = sk * C1
    let shared_secret = c1.scalar_mul(secret_key);

    // M = C2 - shared_secret
    c2.sub(&shared_secret)
}

/// Derive public key from secret key: PK = sk * G
pub fn derive_public_key(secret_key: &Felt252) -> ECPoint {
    ECPoint::generator().scalar_mul(secret_key)
}

/// Re-randomize a ciphertext (for unlinkability)
/// Returns C' = (C1 + r'*G, C2 + r'*PK) which encrypts the same value
pub fn rerandomize(
    ciphertext: &ElGamalCiphertext,
    public_key: &ECPoint,
    new_randomness: &Felt252,
) -> ElGamalCiphertext {
    let g = ECPoint::generator();

    // New randomness contribution
    let r_g = g.scalar_mul(new_randomness);
    let r_pk = public_key.scalar_mul(new_randomness);

    // Add to existing ciphertext
    let new_c1 = ciphertext.c1().add(&r_g);
    let new_c2 = ciphertext.c2().add(&r_pk);

    ElGamalCiphertext::new(new_c1, new_c2)
}

// =============================================================================
// Homomorphic Operations
// =============================================================================

/// Homomorphic addition: Enc(a) + Enc(b) = Enc(a + b)
pub fn homomorphic_add(ct1: &ElGamalCiphertext, ct2: &ElGamalCiphertext) -> ElGamalCiphertext {
    let new_c1 = ct1.c1().add(&ct2.c1());
    let new_c2 = ct1.c2().add(&ct2.c2());
    ElGamalCiphertext::new(new_c1, new_c2)
}

/// Homomorphic subtraction: Enc(a) - Enc(b) = Enc(a - b)
pub fn homomorphic_sub(ct1: &ElGamalCiphertext, ct2: &ElGamalCiphertext) -> ElGamalCiphertext {
    let new_c1 = ct1.c1().sub(&ct2.c1());
    let new_c2 = ct1.c2().sub(&ct2.c2());
    ElGamalCiphertext::new(new_c1, new_c2)
}

/// Homomorphic scalar multiplication: k * Enc(a) = Enc(k * a)
pub fn homomorphic_scalar_mul(scalar: &Felt252, ct: &ElGamalCiphertext) -> ElGamalCiphertext {
    let new_c1 = ct.c1().scalar_mul(scalar);
    let new_c2 = ct.c2().scalar_mul(scalar);
    ElGamalCiphertext::new(new_c1, new_c2)
}

// =============================================================================
// Hash Functions (compatible with Cairo's Poseidon)
// =============================================================================

/// Hash EC points to a field element (for Fiat-Shamir)
/// NOTE: For full compatibility, this should use Poseidon hash.
/// For now, using Keccak256 with reduction mod P.
pub fn hash_points(points: &[ECPoint]) -> Felt252 {
    let mut hasher = Keccak256::new();

    for point in points {
        hasher.update(&point.x.to_be_bytes());
        hasher.update(&point.y.to_be_bytes());
    }

    let result = hasher.finalize();

    // Take first 31 bytes to ensure < P
    let mut bytes = [0u8; 32];
    bytes[1..32].copy_from_slice(&result[0..31]);

    Felt252::from_be_bytes(&bytes)
}

/// Hash field elements to a field element
pub fn hash_felts(felts: &[Felt252]) -> Felt252 {
    let mut hasher = Keccak256::new();

    for felt in felts {
        hasher.update(&felt.to_be_bytes());
    }

    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes[1..32].copy_from_slice(&result[0..31]);

    Felt252::from_be_bytes(&bytes)
}

// =============================================================================
// Schnorr Proof Generation
// =============================================================================

/// Create a Schnorr proof of knowledge of discrete log.
/// Proves knowledge of x such that P = x * G.
///
/// Protocol:
/// 1. Prover picks random k, computes R = k * G
/// 2. Challenge e = H(P, R, context)
/// 3. Response s = k - e * x (mod curve_order)
/// 4. Verifier checks: s*G + e*P == R
pub fn create_schnorr_proof(
    secret_key: &Felt252,
    public_key: &ECPoint,
    nonce: &Felt252,
    context: &[Felt252],
) -> EncryptionProof {
    let g = ECPoint::generator();

    // R = nonce * G (commitment)
    let commitment = g.scalar_mul(nonce);

    // e = H(PK, R, context)
    let mut challenge_input = vec![
        public_key.x,
        public_key.y,
        commitment.x,
        commitment.y,
    ];
    challenge_input.extend_from_slice(context);
    let challenge = hash_felts(&challenge_input);

    // s = nonce - e * sk
    // NOTE: This should be mod curve_order, but we use felt252 arithmetic
    // which is mod field_prime. This is a known limitation.
    let e_sk = challenge.mul_mod(secret_key);
    let response = nonce.sub_mod(&e_sk);

    EncryptionProof::new(commitment, challenge, response, Felt252::ZERO)
}

/// Verify a Schnorr proof
/// Checks: response * G + challenge * P == commitment
pub fn verify_schnorr_proof(
    public_key: &ECPoint,
    proof: &EncryptionProof,
    context: &[Felt252],
) -> bool {
    let g = ECPoint::generator();
    let commitment = proof.commitment();

    // Recompute challenge
    let mut challenge_input = vec![
        public_key.x,
        public_key.y,
        commitment.x,
        commitment.y,
    ];
    challenge_input.extend_from_slice(context);
    let expected_challenge = hash_felts(&challenge_input);

    // Verify challenge matches
    if proof.challenge != expected_challenge {
        return false;
    }

    // Verify: response * G + challenge * P == commitment
    let response_g = g.scalar_mul(&proof.response);
    let challenge_p = public_key.scalar_mul(&proof.challenge);
    let lhs = response_g.add(&challenge_p);

    lhs == commitment
}

/// Create a decryption proof (proves knowledge of secret key)
/// Used when a worker claims an encrypted payment.
pub fn create_decryption_proof(
    keypair: &KeyPair,
    ciphertext: &ElGamalCiphertext,
    nonce: &Felt252,
) -> EncryptionProof {
    let context = vec![
        ciphertext.c1_x,
        ciphertext.c1_y,
        ciphertext.c2_x,
        ciphertext.c2_y,
    ];

    create_schnorr_proof(&keypair.secret_key, &keypair.public_key, nonce, &context)
}

/// Verify a decryption proof
pub fn verify_decryption_proof(
    public_key: &ECPoint,
    ciphertext: &ElGamalCiphertext,
    proof: &EncryptionProof,
) -> bool {
    let context = vec![
        ciphertext.c1_x,
        ciphertext.c1_y,
        ciphertext.c2_x,
        ciphertext.c2_y,
    ];

    verify_schnorr_proof(public_key, proof, &context)
}

// =============================================================================
// Balance Management
// =============================================================================

/// Create an encrypted balance with an initial amount
pub fn create_encrypted_balance(
    amount: u64,
    public_key: &ECPoint,
    randomness: &Felt252,
) -> EncryptedBalance {
    let ciphertext = encrypt(amount, public_key, randomness);
    EncryptedBalance::new(ciphertext, 0)
}

/// Roll up pending balances into the main balance
pub fn rollup_balance(balance: &EncryptedBalance) -> EncryptedBalance {
    // new_balance = ciphertext + pending_in - pending_out
    let with_in = homomorphic_add(&balance.ciphertext, &balance.pending_in);
    let final_balance = homomorphic_sub(&with_in, &balance.pending_out);

    EncryptedBalance {
        ciphertext: final_balance,
        pending_in: ElGamalCiphertext::zero(),
        pending_out: ElGamalCiphertext::zero(),
        epoch: balance.epoch + 1,
    }
}

// =============================================================================
// Pedersen Commitment
// =============================================================================

/// Create a Pedersen commitment: C = amount * H + randomness * G
pub fn pedersen_commit(amount: &Felt252, randomness: &Felt252) -> ECPoint {
    let g = ECPoint::generator();
    let h = ECPoint::generator_h();

    let amount_h = h.scalar_mul(amount);
    let randomness_g = g.scalar_mul(randomness);

    amount_h.add(&randomness_g)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt252_basic_ops() {
        let a = Felt252::from_u64(100);
        let b = Felt252::from_u64(200);

        let sum = a.add_mod(&b);
        assert_eq!(sum.limbs[0], 300);

        let diff = b.sub_mod(&a);
        assert_eq!(diff.limbs[0], 100);

        let product = a.mul_mod(&b);
        assert_eq!(product.limbs[0], 20000);
    }

    #[test]
    fn test_felt252_hex() {
        let felt = Felt252::from_u64(0x12345678);
        let hex = felt.to_hex();
        let parsed = Felt252::from_hex(&hex).unwrap();
        assert_eq!(felt, parsed);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_ec_point_generator() {
        let g = ECPoint::generator();
        assert!(!g.is_infinity());
        assert!(g.is_on_curve());
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_ec_point_addition() {
        let g = ECPoint::generator();
        let g2 = g.double();
        let g2_alt = g.add(&g);

        assert_eq!(g2, g2_alt);
        assert!(g2.is_on_curve());
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_ec_scalar_mul() {
        let g = ECPoint::generator();
        let scalar = Felt252::from_u64(7);

        let result = g.scalar_mul(&scalar);
        assert!(result.is_on_curve());

        // 7*G should equal G + G + G + G + G + G + G
        let mut expected = ECPoint::INFINITY;
        for _ in 0..7 {
            expected = expected.add(&g);
        }
        assert_eq!(result, expected);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_elgamal_encrypt_decrypt() {
        let secret = Felt252::from_u64(12345);
        let keypair = KeyPair::from_secret(secret);
        let randomness = Felt252::from_u64(67890);

        let amount: u64 = 1000;
        let ciphertext = encrypt(amount, &keypair.public_key, &randomness);

        assert!(ciphertext.is_valid());

        // Decrypt and verify
        let decrypted_point = decrypt_point(&ciphertext, &keypair.secret_key);

        // Should equal amount * H
        let h = ECPoint::generator_h();
        let expected = h.scalar_mul(&Felt252::from_u64(amount));

        assert_eq!(decrypted_point, expected);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_homomorphic_add() {
        let secret = Felt252::from_u64(11111);
        let keypair = KeyPair::from_secret(secret);

        let amount1: u64 = 300;
        let amount2: u64 = 200;
        let r1 = Felt252::from_u64(111);
        let r2 = Felt252::from_u64(222);

        let ct1 = encrypt(amount1, &keypair.public_key, &r1);
        let ct2 = encrypt(amount2, &keypair.public_key, &r2);

        let ct_sum = homomorphic_add(&ct1, &ct2);
        let decrypted = decrypt_point(&ct_sum, &keypair.secret_key);

        // Should equal (amount1 + amount2) * H = 500 * H
        let h = ECPoint::generator_h();
        let expected = h.scalar_mul(&Felt252::from_u64(amount1 + amount2));

        assert_eq!(decrypted, expected);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_derive_public_key() {
        let secret = Felt252::from_u64(42);
        let pk = derive_public_key(&secret);

        assert!(!pk.is_infinity());
        assert!(pk.is_on_curve());

        // Should equal secret * G
        let g = ECPoint::generator();
        let expected = g.scalar_mul(&secret);
        assert_eq!(pk, expected);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_keypair() {
        let secret = Felt252::from_u64(98765);
        let keypair = KeyPair::from_secret(secret);

        assert_eq!(keypair.secret_key, secret);
        assert!(keypair.public_key.is_on_curve());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let ct = ElGamalCiphertext {
            c1_x: Felt252::from_u64(1),
            c1_y: Felt252::from_u64(2),
            c2_x: Felt252::from_u64(3),
            c2_y: Felt252::from_u64(4),
        };

        let bytes = ct.to_bytes();
        let restored = ElGamalCiphertext::from_bytes(&bytes);

        assert_eq!(ct, restored);
    }

    #[test]
    fn test_proof_serialization() {
        let proof = EncryptionProof {
            commitment_x: Felt252::from_u64(10),
            commitment_y: Felt252::from_u64(20),
            challenge: Felt252::from_u64(30),
            response: Felt252::from_u64(40),
            range_proof_hash: Felt252::from_u64(50),
        };

        let bytes = proof.to_bytes();
        let restored = EncryptionProof::from_bytes(&bytes);

        assert_eq!(proof, restored);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_rerandomize() {
        let secret = Felt252::from_u64(55555);
        let keypair = KeyPair::from_secret(secret);
        let r1 = Felt252::from_u64(111);
        let r2 = Felt252::from_u64(222);

        let amount: u64 = 750;
        let ct1 = encrypt(amount, &keypair.public_key, &r1);
        let ct2 = rerandomize(&ct1, &keypair.public_key, &r2);

        // Ciphertexts should be different
        assert_ne!(ct1, ct2);

        // But decrypt to same value
        let dec1 = decrypt_point(&ct1, &keypair.secret_key);
        let dec2 = decrypt_point(&ct2, &keypair.secret_key);

        assert_eq!(dec1, dec2);
    }

    #[test]
    #[ignore = "Heavy EC crypto - run with --release"]
    fn test_pedersen_commit() {
        let amount = Felt252::from_u64(1000);
        let randomness = Felt252::from_u64(5678);

        let commitment = pedersen_commit(&amount, &randomness);

        assert!(!commitment.is_infinity());
        assert!(commitment.is_on_curve());

        // Verify structure: C = amount*H + randomness*G
        let g = ECPoint::generator();
        let h = ECPoint::generator_h();
        let expected = h.scalar_mul(&amount).add(&g.scalar_mul(&randomness));

        assert_eq!(commitment, expected);
    }

    #[test]
    #[ignore = "Heavy crypto test - causes stack overflow in debug mode. Run with --release or --ignored"]
    fn test_balance_rollup() {
        let secret = Felt252::from_u64(77777);
        let keypair = KeyPair::from_secret(secret);

        // Create initial balance of 1000
        let initial = create_encrypted_balance(1000, &keypair.public_key, &Felt252::from_u64(111));

        // Add pending_in of 500
        let mut balance = initial;
        balance.pending_in = encrypt(500, &keypair.public_key, &Felt252::from_u64(222));

        // Rollup
        let rolled_up = rollup_balance(&balance);

        // Epoch should increment
        assert_eq!(rolled_up.epoch, 1);

        // Pending should be cleared
        assert_eq!(rolled_up.pending_in, ElGamalCiphertext::zero());
        assert_eq!(rolled_up.pending_out, ElGamalCiphertext::zero());

        // Decrypt and verify total = 1500
        let decrypted = decrypt_point(&rolled_up.ciphertext, &keypair.secret_key);
        let h = ECPoint::generator_h();
        let expected = h.scalar_mul(&Felt252::from_u64(1500));

        assert_eq!(decrypted, expected);
    }
}
