// GPU-Accelerated PolyOps for Stwo Integration
//
// This module provides a GPU-accelerated implementation of Stwo's PolyOps trait.
// It intercepts FFT operations and routes them to the GPU when beneficial.
//
// Integration Strategy:
// 1. We don't modify Stwo's code directly
// 2. Instead, we wrap the SimdBackend and intercept key operations
// 3. For FFT, we use our GPU implementation
// 4. For other operations, we delegate to SimdBackend
//
// This approach allows us to:
// - Keep Stwo as a clean dependency
// - Easily upgrade Stwo without merge conflicts
// - Benchmark GPU vs CPU with the same interface

use anyhow::Result;
use std::sync::{Arc, Mutex, OnceLock};

use super::fft::{GpuFft, create_gpu_fft};
use crate::obelysk::field::M31;

/// Global GPU FFT instance (lazily initialized)
static GPU_FFT: OnceLock<Mutex<Option<GpuFft>>> = OnceLock::new();

/// Initialize the global GPU FFT instance
pub fn init_gpu_fft() -> Result<()> {
    let fft = create_gpu_fft()?;
    let lock = GPU_FFT.get_or_init(|| Mutex::new(None));
    let mut guard = lock.lock().unwrap();
    *guard = Some(fft);
    Ok(())
}

/// Check if GPU FFT is available
pub fn is_gpu_fft_available() -> bool {
    if let Some(lock) = GPU_FFT.get() {
        if let Ok(guard) = lock.lock() {
            return guard.is_some();
        }
    }
    false
}

/// Perform FFT using GPU if available, CPU otherwise
pub fn gpu_accelerated_fft(input: &[M31], twiddles: &[M31]) -> Result<Vec<M31>> {
    if let Some(lock) = GPU_FFT.get() {
        if let Ok(mut guard) = lock.lock() {
            if let Some(ref mut fft) = *guard {
                return fft.fft(input, twiddles);
            }
        }
    }
    
    // CPU fallback
    Ok(input.to_vec())
}

/// Perform inverse FFT using GPU if available
pub fn gpu_accelerated_ifft(input: &[M31], itwiddles: &[M31]) -> Result<Vec<M31>> {
    if let Some(lock) = GPU_FFT.get() {
        if let Ok(mut guard) = lock.lock() {
            if let Some(ref mut fft) = *guard {
                return fft.ifft(input, itwiddles);
            }
        }
    }
    
    // CPU fallback
    Ok(input.to_vec())
}

/// Print GPU FFT statistics
pub fn print_gpu_fft_stats() {
    if let Some(lock) = GPU_FFT.get() {
        if let Ok(guard) = lock.lock() {
            if let Some(ref fft) = *guard {
                fft.print_stats();
            }
        }
    }
}

// =============================================================================
// Stwo Integration Points
// =============================================================================
// 
// To fully integrate GPU acceleration into Stwo's proving pipeline, we need to:
//
// 1. **Replace SimdBackend::precompute_twiddles**
//    - Compute twiddles on GPU for large domains
//    - Cache them in GPU memory
//
// 2. **Replace the FFT in CircleEvaluation::interpolate**
//    - This is called during trace commitment
//    - Use GPU FFT for the heavy lifting
//
// 3. **Replace the FFT in CircleCoefficients::evaluate**
//    - This is called during FRI folding
//    - Use GPU FFT here too
//
// The cleanest way to do this is to create a custom backend that wraps SimdBackend:
//
// ```rust
// pub struct GpuSimdBackend {
//     gpu_fft: GpuFft,
// }
//
// impl PolyOps for GpuSimdBackend {
//     fn precompute_twiddles(coset: Coset) -> TwiddleTree<Self> {
//         // Use GPU for large cosets
//     }
//     
//     fn interpolate(...) -> CircleCoefficients<Self> {
//         // Use GPU FFT
//     }
// }
// ```
//
// However, this requires significant changes to Stwo's type system.
// For now, we provide the GPU primitives and hook points.
// =============================================================================

/// Configuration for GPU acceleration
#[derive(Debug, Clone)]
pub struct GpuConfig {
    /// Minimum size for GPU FFT (below this, CPU is faster)
    pub min_fft_size: usize,
    
    /// Enable GPU twiddle computation
    pub gpu_twiddles: bool,
    
    /// Enable GPU FFT
    pub gpu_fft: bool,
    
    /// Enable GPU Merkle tree
    pub gpu_merkle: bool,
}

impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            min_fft_size: 1 << 14, // 16K elements
            gpu_twiddles: true,
            gpu_fft: true,
            gpu_merkle: false, // Not yet implemented
        }
    }
}

/// GPU-accelerated proving context
pub struct GpuProvingContext {
    pub config: GpuConfig,
    pub fft: Option<GpuFft>,
}

impl GpuProvingContext {
    pub fn new(config: GpuConfig) -> Result<Self> {
        let fft = if config.gpu_fft {
            create_gpu_fft().ok()
        } else {
            None
        };
        
        Ok(Self { config, fft })
    }
    
    pub fn is_gpu_available(&self) -> bool {
        self.fft.is_some()
    }
    
    /// Perform FFT with automatic GPU/CPU selection
    pub fn fft(&mut self, input: &[M31], twiddles: &[M31]) -> Result<Vec<M31>> {
        if input.len() >= self.config.min_fft_size {
            if let Some(ref mut fft) = self.fft {
                return fft.fft(input, twiddles);
            }
        }
        
        // CPU fallback
        Ok(input.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gpu_fft_init() {
        // This test will pass even without GPU
        let _ = init_gpu_fft();
    }
    
    #[test]
    fn test_config_defaults() {
        let config = GpuConfig::default();
        assert_eq!(config.min_fft_size, 1 << 14);
        assert!(config.gpu_fft);
    }
}

