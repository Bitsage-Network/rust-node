// Mersenne-31 Field Operations
// 
// M31 = 2^31 - 1 (prime field optimized for 32-bit hardware)
//
// Key advantages:
// - Fits in 32-bit register (single-cycle arithmetic)
// - Fast reduction: (x & 0x7FFFFFFF) + (x >> 31)
// - SIMD-friendly (AVX-512 can do 16 ops in parallel)
// - GPU-optimized (matches 32-bit integer units)

use std::ops::{Add, Sub, Mul, Neg};
use serde::{Serialize, Deserialize};

/// Mersenne-31 prime: 2^31 - 1 = 2147483647
pub const M31_PRIME: u32 = (1u32 << 31) - 1;

/// Mersenne-31 Field Element
/// 
/// Represents an element in the finite field F_p where p = 2^31 - 1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct M31(u32);

impl M31 {
    /// Zero element
    pub const ZERO: Self = M31(0);
    
    /// One element
    pub const ONE: Self = M31(1);
    
    /// The modulus (2^31 - 1)
    pub const MODULUS: u32 = M31_PRIME;
    
    /// Create a new M31 element from a u32
    /// Automatically reduces modulo 2^31 - 1
    pub fn new(value: u32) -> Self {
        M31(Self::reduce(value))
    }
    
    /// Create from u32 (alias for new, for clarity)
    pub fn from_u32(value: u32) -> Self {
        M31::new(value)
    }
    
    /// Create from i32 (handles negatives)
    pub fn from_i32(value: i32) -> Self {
        if value >= 0 {
            M31::new(value as u32)
        } else {
            // Handle negative: p - |value|
            let abs = value.unsigned_abs();
            M31::new(M31_PRIME - Self::reduce(abs))
        }
    }
    
    /// Get the raw value (always < M31_PRIME)
    pub fn value(&self) -> u32 {
        self.0
    }
    
    /// Fast reduction modulo 2^31 - 1
    /// 
    /// Uses the identity: x mod (2^31 - 1) = (x & 0x7FFFFFFF) + (x >> 31)
    /// This is the key optimization that makes M31 so fast
    #[inline]
    fn reduce(x: u32) -> u32 {
        let low = x & 0x7FFFFFFF;  // x mod 2^31
        let high = x >> 31;         // x / 2^31
        
        // Since 2^31 ≡ 1 (mod 2^31-1), we have:
        // x = low + high * 2^31 ≡ low + high (mod 2^31-1)
        let sum = low + high;
        
        // Final reduction (sum might be 2^31-1, which equals 0)
        if sum >= M31_PRIME {
            sum - M31_PRIME
        } else {
            sum
        }
    }
    
    /// Fast reduction for 64-bit products
    #[inline]
    fn reduce64(x: u64) -> u32 {
        // Split into two 32-bit halves and reduce
        let low = (x & 0xFFFFFFFF) as u32;
        let high = (x >> 32) as u32;
        
        // First reduction
        let partial = Self::reduce(low) as u64 + (high as u64);
        
        // Second reduction (partial fits in 33 bits)
        Self::reduce(partial as u32)
    }
    
    /// Multiplicative inverse (for division)
    /// Uses Fermat's Little Theorem: a^(p-1) ≡ 1, so a^(-1) ≡ a^(p-2)
    pub fn inverse(&self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        
        // Compute self^(M31_PRIME - 2) via binary exponentiation
        let mut result = M31::ONE;
        let mut base = *self;
        let mut exp = M31_PRIME - 2;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        
        Some(result)
    }
    
    /// Power function
    pub fn pow(&self, mut exp: u32) -> Self {
        let mut result = M31::ONE;
        let mut base = *self;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        
        result
    }
    
    /// Check if element is zero
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
    
    /// Check if element is positive (for ReLU, etc.)
    pub fn is_positive(&self) -> bool {
        self.0 > 0 && self.0 <= (M31_PRIME / 2)
    }
}

// Arithmetic Operations

impl Add for M31 {
    type Output = Self;
    
    #[inline]
    fn add(self, rhs: Self) -> Self {
        let sum = self.0 as u64 + rhs.0 as u64;
        M31(if sum >= M31_PRIME as u64 {
            (sum - M31_PRIME as u64) as u32
        } else {
            sum as u32
        })
    }
}

impl Sub for M31 {
    type Output = Self;
    
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            M31(self.0 - rhs.0)
        } else {
            M31(M31_PRIME - (rhs.0 - self.0))
        }
    }
}

impl Mul for M31 {
    type Output = Self;
    
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let product = (self.0 as u64) * (rhs.0 as u64);
        M31(Self::reduce64(product))
    }
}

impl Neg for M31 {
    type Output = Self;
    
    #[inline]
    fn neg(self) -> Self {
        if self.0 == 0 {
            M31::ZERO
        } else {
            M31(M31_PRIME - self.0)
        }
    }
}

// Conversions

impl From<u32> for M31 {
    fn from(value: u32) -> Self {
        M31::new(value)
    }
}

impl From<i32> for M31 {
    fn from(value: i32) -> Self {
        M31::from_i32(value)
    }
}

impl From<u8> for M31 {
    fn from(value: u8) -> Self {
        M31::new(value as u32)
    }
}

impl From<i8> for M31 {
    fn from(value: i8) -> Self {
        M31::from_i32(value as i32)
    }
}

// Display

impl std::fmt::Display for M31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "M31({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_arithmetic() {
        let a = M31::new(5);
        let b = M31::new(7);
        
        assert_eq!(a + b, M31::new(12));
        assert_eq!(b - a, M31::new(2));
        assert_eq!(a * b, M31::new(35));
    }
    
    #[test]
    fn test_reduction() {
        // Test that 2^31 - 1 reduces to 0 (since it's the modulus)
        let max = M31::new(M31_PRIME);
        assert_eq!(max, M31::ZERO);
        
        // Test that 2^31 reduces to 1
        let overflow = M31::new(1u32 << 31);
        assert_eq!(overflow, M31::ONE);
    }
    
    #[test]
    fn test_inverse() {
        let a = M31::new(7);
        let a_inv = a.inverse().unwrap();
        
        // a * a^(-1) should equal 1
        assert_eq!(a * a_inv, M31::ONE);
    }
    
    #[test]
    fn test_negation() {
        let a = M31::new(5);
        let neg_a = -a;
        
        assert_eq!(a + neg_a, M31::ZERO);
    }
    
    #[test]
    fn test_power() {
        let a = M31::new(2);
        let a_squared = a.pow(2);
        let a_cubed = a.pow(3);
        
        assert_eq!(a_squared, M31::new(4));
        assert_eq!(a_cubed, M31::new(8));
    }
    
    #[test]
    fn test_is_positive() {
        assert!(M31::new(100).is_positive());
        assert!(!M31::new(M31_PRIME - 100).is_positive());  // Negative number
        assert!(!M31::ZERO.is_positive());
    }
}

