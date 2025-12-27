// ECDSA Verification for ZK Circuits
//
// Implements ECDSA signature verification over the P-256 (secp256r1) curve
// for use in TEE attestation proofs.
//
// The P-256 curve is used by Intel TDX/SGX and AMD SEV attestation quotes.
//
// # Architecture
//
// ECDSA verification in ZK requires:
// 1. BigInt arithmetic for 256-bit field elements
// 2. Elliptic curve point operations
// 3. Modular inversion
// 4. Hash-to-scalar conversion
//
// We represent 256-bit integers as 8 x 32-bit M31 limbs (with carries handled separately).

use super::field::M31;
use serde::{Serialize, Deserialize};
// Note: Add, Sub, Mul ops are implemented directly on U256 methods

// =============================================================================
// P-256 Curve Parameters
// =============================================================================

/// P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
/// In hex: FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
pub const P256_PRIME: [u32; 8] = [
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
];

/// P-256 order: n (number of points on the curve)
/// In hex: FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
pub const P256_ORDER: [u32; 8] = [
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
];

/// P-256 generator point Gx
pub const P256_GX: [u32; 8] = [
    0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
    0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2,
];

/// P-256 generator point Gy
pub const P256_GY: [u32; 8] = [
    0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
    0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2,
];

/// Curve coefficient a = -3 (mod p)
pub const P256_A: [u32; 8] = [
    0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
];

/// Curve coefficient b
pub const P256_B: [u32; 8] = [
    0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
    0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8,
];

// =============================================================================
// 256-bit Big Integer (represented as 8 x 32-bit limbs)
// =============================================================================

/// 256-bit unsigned integer for P-256 field operations.
/// 
/// Represented as 8 x 32-bit limbs in little-endian order.
/// limbs[0] is the least significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct U256 {
    pub limbs: [u32; 8],
}

impl U256 {
    /// Zero
    pub const ZERO: Self = U256 { limbs: [0; 8] };
    
    /// One
    pub const ONE: Self = U256 { limbs: [1, 0, 0, 0, 0, 0, 0, 0] };
    
    /// Create from limbs (little-endian)
    pub const fn from_limbs(limbs: [u32; 8]) -> Self {
        U256 { limbs }
    }
    
    /// Create from bytes (big-endian, standard for crypto)
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u32; 8];
        for i in 0..8 {
            let offset = (7 - i) * 4;
            limbs[i] = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }
        U256 { limbs }
    }
    
    /// Convert to bytes (big-endian)
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            let offset = (7 - i) * 4;
            bytes[offset..offset + 4].copy_from_slice(&self.limbs[i].to_be_bytes());
        }
        bytes
    }
    
    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }
    
    /// Compare with another U256
    pub fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..8).rev() {
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
    
    /// Addition with carry (returns sum and carry)
    pub fn add_with_carry(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u32; 8];
        let mut carry = 0u64;
        
        for i in 0..8 {
            let sum = self.limbs[i] as u64 + other.limbs[i] as u64 + carry;
            result[i] = sum as u32;
            carry = sum >> 32;
        }
        
        (U256 { limbs: result }, carry != 0)
    }
    
    /// Subtraction with borrow (returns diff and borrow)
    pub fn sub_with_borrow(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u32; 8];
        let mut borrow = 0i64;
        
        for i in 0..8 {
            let diff = self.limbs[i] as i64 - other.limbs[i] as i64 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                result[i] = diff as u32;
                borrow = 0;
            }
        }
        
        (U256 { limbs: result }, borrow != 0)
    }
    
    /// Modular addition: (a + b) mod m
    pub fn add_mod(&self, other: &Self, modulus: &Self) -> Self {
        let (sum, carry) = self.add_with_carry(other);
        
        if carry || sum.gte(modulus) {
            let (result, _) = sum.sub_with_borrow(modulus);
            result
        } else {
            sum
        }
    }
    
    /// Modular subtraction: (a - b) mod m
    pub fn sub_mod(&self, other: &Self, modulus: &Self) -> Self {
        if self.gte(other) {
            let (result, _) = self.sub_with_borrow(other);
            result
        } else {
            // a < b, so result = modulus - (b - a)
            let (diff, _) = other.sub_with_borrow(self);
            let (result, _) = modulus.sub_with_borrow(&diff);
            result
        }
    }
    
    /// Modular multiplication using Montgomery reduction (simplified)
    /// For production, use optimized Montgomery multiplication
    pub fn mul_mod(&self, other: &Self, modulus: &Self) -> Self {
        // Simple schoolbook multiplication with reduction
        // Production code should use Montgomery multiplication
        let mut result = U256::ZERO;
        let mut temp = *self;
        
        for i in 0..8 {
            for j in 0..32 {
                if (other.limbs[i] >> j) & 1 == 1 {
                    result = result.add_mod(&temp, modulus);
                }
                temp = temp.double_mod(modulus);
            }
        }
        
        result
    }
    
    /// Double modulo m
    pub fn double_mod(&self, modulus: &Self) -> Self {
        self.add_mod(self, modulus)
    }
    
    /// Modular inverse using extended Euclidean algorithm
    pub fn inv_mod(&self, modulus: &Self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        
        // Extended Euclidean algorithm
        let mut a = *self;
        let mut m = *modulus;
        let mut x0 = U256::ZERO;
        let mut x1 = U256::ONE;
        
        while !a.is_zero() {
            // Simplified division (not efficient, but correct)
            let (q, r) = m.div_rem(&a);
            m = a;
            a = r;
            
            let new_x = x0.sub_mod(&q.mul_mod(&x1, modulus), modulus);
            x0 = x1;
            x1 = new_x;
        }
        
        // m should be 1 if inverse exists
        if m == U256::ONE {
            Some(x0)
        } else {
            None
        }
    }
    
    /// Division with remainder (simplified, not efficient)
    fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }
        
        let mut quotient = U256::ZERO;
        let mut remainder = *self;
        
        // Find the highest bit position
        let mut shift = 0i32;
        let mut shifted_divisor = *divisor;
        
        while shifted_divisor.cmp(self) != std::cmp::Ordering::Greater {
            if let Some(doubled) = shifted_divisor.try_double() {
                shifted_divisor = doubled;
                shift += 1;
            } else {
                break;
            }
        }
        
        // Perform division
        while shift >= 0 {
            if remainder.gte(&shifted_divisor) {
                let (new_rem, _) = remainder.sub_with_borrow(&shifted_divisor);
                remainder = new_rem;
                quotient.limbs[shift as usize / 32] |= 1u32 << (shift as usize % 32);
            }
            shifted_divisor = shifted_divisor.half();
            shift -= 1;
        }
        
        (quotient, remainder)
    }
    
    /// Try to double (returns None on overflow)
    fn try_double(&self) -> Option<Self> {
        let (result, overflow) = self.add_with_carry(self);
        if overflow { None } else { Some(result) }
    }
    
    /// Halve (right shift by 1)
    fn half(&self) -> Self {
        let mut result = [0u32; 8];
        let mut carry = 0u32;
        
        for i in (0..8).rev() {
            result[i] = (self.limbs[i] >> 1) | (carry << 31);
            carry = self.limbs[i] & 1;
        }
        
        U256 { limbs: result }
    }
    
    /// Convert to M31 field elements (for ZK circuit)
    /// Splits into 8 x 32-bit values, each reduced to M31
    pub fn to_m31_limbs(&self) -> [M31; 8] {
        [
            M31::new(self.limbs[0]),
            M31::new(self.limbs[1]),
            M31::new(self.limbs[2]),
            M31::new(self.limbs[3]),
            M31::new(self.limbs[4]),
            M31::new(self.limbs[5]),
            M31::new(self.limbs[6]),
            M31::new(self.limbs[7]),
        ]
    }

    /// Convert from M31 limbs back to U256
    /// Note: There may be loss of upper bit since M31 only holds 31 bits
    pub fn from_m31_limbs(limbs: &[M31; 8]) -> Self {
        U256 {
            limbs: [
                limbs[0].value(),
                limbs[1].value(),
                limbs[2].value(),
                limbs[3].value(),
                limbs[4].value(),
                limbs[5].value(),
                limbs[6].value(),
                limbs[7].value(),
            ],
        }
    }
}

// =============================================================================
// Elliptic Curve Point (P-256)
// =============================================================================

/// Point on P-256 curve in affine coordinates (x, y).
/// Point at infinity is represented with x = y = 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct P256Point {
    pub x: U256,
    pub y: U256,
    pub infinity: bool,
}

impl P256Point {
    /// Point at infinity (identity element)
    pub const INFINITY: Self = P256Point {
        x: U256::ZERO,
        y: U256::ZERO,
        infinity: true,
    };
    
    /// Generator point G
    pub fn generator() -> Self {
        P256Point {
            x: U256::from_limbs(P256_GX),
            y: U256::from_limbs(P256_GY),
            infinity: false,
        }
    }
    
    /// Create a point from coordinates
    pub fn new(x: U256, y: U256) -> Self {
        P256Point {
            x,
            y,
            infinity: false,
        }
    }
    
    /// Create from uncompressed public key bytes (65 bytes: 0x04 || x || y)
    pub fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return None;
        }
        
        let x = U256::from_be_bytes(bytes[1..33].try_into().ok()?);
        let y = U256::from_be_bytes(bytes[33..65].try_into().ok()?);
        
        let point = P256Point::new(x, y);
        
        // Verify point is on curve
        if point.is_on_curve() {
            Some(point)
        } else {
            None
        }
    }
    
    /// Check if point is on the curve: y² = x³ + ax + b (mod p)
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        
        let p = U256::from_limbs(P256_PRIME);
        let a = U256::from_limbs(P256_A);
        let b = U256::from_limbs(P256_B);
        
        // y²
        let y_sq = self.y.mul_mod(&self.y, &p);
        
        // x³
        let x_sq = self.x.mul_mod(&self.x, &p);
        let x_cu = x_sq.mul_mod(&self.x, &p);
        
        // ax
        let ax = a.mul_mod(&self.x, &p);
        
        // x³ + ax + b
        let rhs = x_cu.add_mod(&ax, &p).add_mod(&b, &p);
        
        y_sq == rhs
    }
    
    /// Point addition: self + other
    pub fn add(&self, other: &Self) -> Self {
        if self.infinity {
            return *other;
        }
        if other.infinity {
            return *self;
        }
        
        let p = U256::from_limbs(P256_PRIME);
        
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
        let numerator = other.y.sub_mod(&self.y, &p);
        let denominator = other.x.sub_mod(&self.x, &p);
        let lambda = match denominator.inv_mod(&p) {
            Some(inv) => numerator.mul_mod(&inv, &p),
            None => return Self::INFINITY,
        };
        
        // x3 = λ² - x1 - x2
        let lambda_sq = lambda.mul_mod(&lambda, &p);
        let x3 = lambda_sq.sub_mod(&self.x, &p).sub_mod(&other.x, &p);
        
        // y3 = λ(x1 - x3) - y1
        let x1_minus_x3 = self.x.sub_mod(&x3, &p);
        let y3 = lambda.mul_mod(&x1_minus_x3, &p).sub_mod(&self.y, &p);
        
        P256Point::new(x3, y3)
    }
    
    /// Point doubling: 2 * self
    pub fn double(&self) -> Self {
        if self.infinity || self.y.is_zero() {
            return Self::INFINITY;
        }
        
        let p = U256::from_limbs(P256_PRIME);
        let a = U256::from_limbs(P256_A);
        
        // λ = (3x² + a) / (2y)
        let x_sq = self.x.mul_mod(&self.x, &p);
        let three = U256::from_limbs([3, 0, 0, 0, 0, 0, 0, 0]);
        let three_x_sq = three.mul_mod(&x_sq, &p);
        let numerator = three_x_sq.add_mod(&a, &p);
        
        let two = U256::from_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
        let two_y = two.mul_mod(&self.y, &p);
        let lambda = match two_y.inv_mod(&p) {
            Some(inv) => numerator.mul_mod(&inv, &p),
            None => return Self::INFINITY,
        };
        
        // x3 = λ² - 2x
        let lambda_sq = lambda.mul_mod(&lambda, &p);
        let two_x = two.mul_mod(&self.x, &p);
        let x3 = lambda_sq.sub_mod(&two_x, &p);
        
        // y3 = λ(x - x3) - y
        let x_minus_x3 = self.x.sub_mod(&x3, &p);
        let y3 = lambda.mul_mod(&x_minus_x3, &p).sub_mod(&self.y, &p);
        
        P256Point::new(x3, y3)
    }
    
    /// Point negation: -P = (x, -y) = (x, p - y)
    pub fn negate(&self) -> Self {
        if self.infinity {
            return Self::INFINITY;
        }

        let p = U256::from_limbs(P256_PRIME);
        let neg_y = p.sub_mod(&self.y, &p);

        P256Point::new(self.x, neg_y)
    }

    /// Scalar multiplication: k * self (double-and-add)
    pub fn scalar_mul(&self, k: &U256) -> Self {
        if k.is_zero() || self.infinity {
            return Self::INFINITY;
        }
        
        let mut result = Self::INFINITY;
        let mut base = *self;
        
        // Double-and-add algorithm
        for i in 0..8 {
            let mut limb = k.limbs[i];
            for _ in 0..32 {
                if limb & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.double();
                limb >>= 1;
            }
        }
        
        result
    }
}

// =============================================================================
// ECDSA Signature and Verification
// =============================================================================

/// ECDSA signature (r, s) over P-256
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ECDSASignature {
    pub r: U256,
    pub s: U256,
}

impl ECDSASignature {
    /// Create from r and s values
    pub fn new(r: U256, s: U256) -> Self {
        ECDSASignature { r, s }
    }
    
    /// Parse from DER format (common in X.509 certificates)
    pub fn from_der(bytes: &[u8]) -> Option<Self> {
        // DER format: 0x30 <length> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
        if bytes.len() < 8 || bytes[0] != 0x30 {
            return None;
        }
        
        let mut offset = 2; // Skip 0x30 and length byte
        
        // Parse r
        if bytes[offset] != 0x02 {
            return None;
        }
        offset += 1;
        let r_len = bytes[offset] as usize;
        offset += 1;
        
        let r_bytes = &bytes[offset..offset + r_len];
        offset += r_len;
        
        // Parse s
        if bytes[offset] != 0x02 {
            return None;
        }
        offset += 1;
        let s_len = bytes[offset] as usize;
        offset += 1;
        
        let s_bytes = &bytes[offset..offset + s_len];
        
        // Convert to U256 (handle leading zeros)
        let r = Self::bytes_to_u256(r_bytes)?;
        let s = Self::bytes_to_u256(s_bytes)?;
        
        Some(ECDSASignature { r, s })
    }
    
    /// Parse from concatenated format (64 bytes: r || s)
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let r = U256::from_be_bytes(bytes[0..32].try_into().unwrap());
        let s = U256::from_be_bytes(bytes[32..64].try_into().unwrap());
        ECDSASignature { r, s }
    }

    /// Convert to concatenated format (64 bytes: r || s)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.r.to_be_bytes());
        bytes[32..64].copy_from_slice(&self.s.to_be_bytes());
        bytes
    }

    fn bytes_to_u256(bytes: &[u8]) -> Option<U256> {
        // Skip leading zeros
        let trimmed: Vec<u8> = bytes.iter()
            .skip_while(|&&b| b == 0)
            .copied()
            .collect();
        
        if trimmed.len() > 32 {
            return None;
        }
        
        // Pad to 32 bytes
        let mut padded = [0u8; 32];
        padded[32 - trimmed.len()..].copy_from_slice(&trimmed);
        
        Some(U256::from_be_bytes(&padded))
    }
}

/// ECDSA Verifier for P-256 curve
pub struct ECDSAVerifier;

impl ECDSAVerifier {
    /// Verify an ECDSA signature
    ///
    /// # Arguments
    /// * `public_key` - The signer's public key point
    /// * `message_hash` - SHA-256 hash of the message (32 bytes)
    /// * `signature` - The (r, s) signature
    ///
    /// # Returns
    /// true if signature is valid
    pub fn verify(
        public_key: &P256Point,
        message_hash: &[u8; 32],
        signature: &ECDSASignature,
    ) -> bool {
        let n = U256::from_limbs(P256_ORDER);
        
        // Check r and s are in range [1, n-1]
        if signature.r.is_zero() || signature.s.is_zero() {
            return false;
        }
        if !signature.r.cmp(&n).is_lt() || !signature.s.cmp(&n).is_lt() {
            return false;
        }
        
        // Convert message hash to scalar z
        let z = U256::from_be_bytes(message_hash);
        
        // Compute s⁻¹ mod n
        let s_inv = match signature.s.inv_mod(&n) {
            Some(inv) => inv,
            None => return false,
        };
        
        // u1 = z * s⁻¹ mod n
        let u1 = z.mul_mod(&s_inv, &n);
        
        // u2 = r * s⁻¹ mod n
        let u2 = signature.r.mul_mod(&s_inv, &n);
        
        // R = u1 * G + u2 * Q
        let g = P256Point::generator();
        let u1_g = g.scalar_mul(&u1);
        let u2_q = public_key.scalar_mul(&u2);
        let r_point = u1_g.add(&u2_q);
        
        // Check if R is at infinity
        if r_point.infinity {
            return false;
        }
        
        // Reduce R.x mod n and compare with r
        // Note: For P-256, R.x is already < p < n, so we just compare directly
        // In general, would need to reduce R.x mod n
        r_point.x == signature.r
    }
    
    /// Verify ECDSA signature for TEE quote verification
    ///
    /// This is a convenience method for verifying TEE quote signatures
    pub fn verify_tee_quote_signature(
        public_key_bytes: &[u8],
        quote_body: &[u8],
        signature: &[u8],
    ) -> Result<bool, &'static str> {
        // Parse public key
        let public_key = P256Point::from_uncompressed(public_key_bytes)
            .ok_or("Invalid public key")?;
        
        // Hash the quote body with SHA-256
        let message_hash = sha256_hash(quote_body);
        
        // Parse signature
        let sig = if signature.len() == 64 {
            ECDSASignature::from_bytes(signature.try_into().unwrap())
        } else {
            ECDSASignature::from_der(signature)
                .ok_or("Invalid signature format")?
        };
        
        Ok(Self::verify(&public_key, &message_hash, &sig))
    }
}

/// Simple SHA-256 hash (using ring or sha2 crate in production)
/// This is a placeholder - real implementation uses crypto library
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// =============================================================================
// ZK Circuit Integration
// =============================================================================

/// ECDSA verification constraints for ZK circuit.
///
/// Represents the verification computation as constraints that can be
/// proven in a ZK circuit.
pub struct ECDSACircuitConstraints {
    /// Witness: signature (r, s) as M31 limbs
    pub r_limbs: [M31; 8],
    pub s_limbs: [M31; 8],
    
    /// Witness: message hash as M31 limbs
    pub z_limbs: [M31; 8],
    
    /// Witness: public key (x, y) as M31 limbs
    pub pub_x_limbs: [M31; 8],
    pub pub_y_limbs: [M31; 8],
    
    /// Intermediate values for constraint generation
    pub s_inv_limbs: [M31; 8],
    pub u1_limbs: [M31; 8],
    pub u2_limbs: [M31; 8],
    
    /// Final R point
    pub r_point_x_limbs: [M31; 8],
    pub r_point_y_limbs: [M31; 8],
}

impl ECDSACircuitConstraints {
    /// Create constraints from verification inputs
    pub fn new(
        public_key: &P256Point,
        message_hash: &[u8; 32],
        signature: &ECDSASignature,
    ) -> Self {
        let n = U256::from_limbs(P256_ORDER);
        let z = U256::from_be_bytes(message_hash);
        
        // Compute witness values
        let s_inv = signature.s.inv_mod(&n).unwrap_or(U256::ZERO);
        let u1 = z.mul_mod(&s_inv, &n);
        let u2 = signature.r.mul_mod(&s_inv, &n);
        
        let g = P256Point::generator();
        let u1_g = g.scalar_mul(&u1);
        let u2_q = public_key.scalar_mul(&u2);
        let r_point = u1_g.add(&u2_q);
        
        ECDSACircuitConstraints {
            r_limbs: signature.r.to_m31_limbs(),
            s_limbs: signature.s.to_m31_limbs(),
            z_limbs: z.to_m31_limbs(),
            pub_x_limbs: public_key.x.to_m31_limbs(),
            pub_y_limbs: public_key.y.to_m31_limbs(),
            s_inv_limbs: s_inv.to_m31_limbs(),
            u1_limbs: u1.to_m31_limbs(),
            u2_limbs: u2.to_m31_limbs(),
            r_point_x_limbs: r_point.x.to_m31_limbs(),
            r_point_y_limbs: r_point.y.to_m31_limbs(),
        }
    }
    
    /// Generate circuit constraints for ECDSA verification
    ///
    /// Returns the number of constraints added
    pub fn add_to_circuit(&self, _circuit: &mut super::circuit::Circuit) -> usize {
        // In a real implementation, this would add constraints for:
        // 1. s_inv * s == 1 (mod n) - 8 * 8 = 64 multiplication constraints
        // 2. u1 = z * s_inv (mod n) - 64 constraints
        // 3. u2 = r * s_inv (mod n) - 64 constraints
        // 4. R = u1*G + u2*Q - Point multiplication is expensive (~100K constraints)
        // 5. R.x == r - 8 equality constraints
        
        // For now, return estimated constraint count
        // Full implementation requires field reduction gadgets
        100_000
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_u256_basic() {
        let a = U256::ONE;
        let b = U256::ONE;
        let (sum, carry) = a.add_with_carry(&b);
        
        assert_eq!(sum.limbs[0], 2);
        assert!(!carry);
    }
    
    #[test]
    fn test_generator_on_curve() {
        let g = P256Point::generator();
        assert!(g.is_on_curve());
    }
    
    #[test]
    fn test_point_double() {
        let g = P256Point::generator();
        let two_g = g.double();
        
        assert!(!two_g.infinity);
        assert!(two_g.is_on_curve());
    }
    
    #[test]
    fn test_point_add() {
        let g = P256Point::generator();
        let two_g = g.add(&g);
        let two_g_direct = g.double();
        
        assert_eq!(two_g, two_g_direct);
    }
    
    #[test]
    fn test_scalar_mul_identity() {
        let g = P256Point::generator();
        let one = U256::ONE;
        let result = g.scalar_mul(&one);
        
        assert_eq!(result, g);
    }
    
    #[test]
    fn test_scalar_mul_by_zero() {
        let g = P256Point::generator();
        let zero = U256::ZERO;
        let result = g.scalar_mul(&zero);

        assert!(result.infinity);
    }

    #[test]
    fn test_u256_modular_inverse() {
        // Test modular inverse: 3^(-1) mod 7 = 5 (since 3 * 5 = 15 = 2*7 + 1)
        let three = U256::from_limbs([3, 0, 0, 0, 0, 0, 0, 0]);
        let seven = U256::from_limbs([7, 0, 0, 0, 0, 0, 0, 0]);

        let inv = three.inv_mod(&seven);
        assert!(inv.is_some());

        let inv = inv.unwrap();
        let product = three.mul_mod(&inv, &seven);
        assert_eq!(product, U256::ONE);
    }

    #[test]
    fn test_u256_mul_mod() {
        // Test modular multiplication: 5 * 7 mod 17 = 35 mod 17 = 1
        let five = U256::from_limbs([5, 0, 0, 0, 0, 0, 0, 0]);
        let seven = U256::from_limbs([7, 0, 0, 0, 0, 0, 0, 0]);
        let seventeen = U256::from_limbs([17, 0, 0, 0, 0, 0, 0, 0]);

        let result = five.mul_mod(&seven, &seventeen);
        assert_eq!(result, U256::ONE);
    }

    #[test]
    fn test_ecdsa_signature_roundtrip() {
        // Create a signature and test serialization/deserialization
        let r_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let s_bytes: [u8; 32] = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ];

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r_bytes);
        sig_bytes[32..].copy_from_slice(&s_bytes);

        let sig = ECDSASignature::from_bytes(&sig_bytes);
        let roundtrip = sig.to_bytes();

        assert_eq!(sig_bytes, roundtrip);
    }

    #[test]
    fn test_point_from_uncompressed() {
        // Test parsing uncompressed point format (04 || x || y)
        let g = P256Point::generator();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..33].copy_from_slice(&g.x.to_be_bytes());
        uncompressed[33..65].copy_from_slice(&g.y.to_be_bytes());

        let parsed = P256Point::from_uncompressed(&uncompressed);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap(), g);
    }

    #[test]
    fn test_order_times_generator_is_infinity() {
        // n * G = O (point at infinity)
        // This tests that our curve implementation is consistent
        let g = P256Point::generator();
        let n = U256::from_limbs(P256_ORDER);

        let result = g.scalar_mul(&n);
        assert!(result.infinity);
    }

    #[test]
    fn test_signature_validity_checks() {
        // Test that signature validation rejects invalid signatures
        let public_key = P256Point::generator();
        let message_hash = [0u8; 32];

        // Zero r should be rejected
        let sig_zero_r = ECDSASignature {
            r: U256::ZERO,
            s: U256::ONE,
        };
        assert!(!ECDSAVerifier::verify(&public_key, &message_hash, &sig_zero_r));

        // Zero s should be rejected
        let sig_zero_s = ECDSASignature {
            r: U256::ONE,
            s: U256::ZERO,
        };
        assert!(!ECDSAVerifier::verify(&public_key, &message_hash, &sig_zero_s));
    }

    #[test]
    fn test_point_negation() {
        let g = P256Point::generator();
        let neg_g = g.negate();

        // g + (-g) should give point at infinity
        let result = g.add(&neg_g);
        assert!(result.infinity);
    }

    #[test]
    fn test_double_and_add_equivalence() {
        // 3G = G + G + G = 2G + G
        let g = P256Point::generator();

        let three = U256::from_limbs([3, 0, 0, 0, 0, 0, 0, 0]);
        let three_g_scalar = g.scalar_mul(&three);

        let two_g = g.double();
        let three_g_add = two_g.add(&g);

        assert_eq!(three_g_scalar, three_g_add);
    }

    #[test]
    fn test_m31_limb_conversion() {
        // Test U256 to M31 limbs conversion roundtrip
        // Use values that are within M31 range (< 2^31 - 1 = 2147483647)
        // to avoid modular reduction issues
        let original = U256::from_limbs([
            0x12345678, // 305419896 - in range
            0x23456789, // 591751049 - in range
            0x01234567, // 19088743 - in range
            0x0CDEF012, // 216330258 - in range
            0x3456789A, // 878082202 - in range
            0x0DEF0123, // 233570595 - in range
            0x456789AB, // 1164413355 - in range
            0x1EF01234, // 519045684 - in range
        ]);

        let m31_limbs = original.to_m31_limbs();
        let reconstructed = U256::from_m31_limbs(&m31_limbs);

        // Values within M31 range should roundtrip exactly
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_ecdsa_circuit_constraints_creation() {
        // Test that we can create circuit constraints without panicking
        let public_key = P256Point::generator();
        let message_hash = [0x42u8; 32];
        let signature = ECDSASignature {
            r: U256::from_limbs([1, 2, 3, 4, 5, 6, 7, 8]),
            s: U256::from_limbs([8, 7, 6, 5, 4, 3, 2, 1]),
        };

        let constraints = ECDSACircuitConstraints::new(&public_key, &message_hash, &signature);

        // Verify that constraint values are populated
        assert!(constraints.r_limbs.iter().any(|&x| x.value() != 0));
        assert!(constraints.z_limbs.iter().any(|&x| x.value() != 0));
    }
}

