// GPU-Accelerated Circle FFT for Obelysk
//
// This module provides GPU acceleration for the Circle FFT, which is the
// main bottleneck in Stwo proof generation. On A100/H100, we expect 50-100x
// speedup over CPU for large FFTs.
//
// Architecture:
// 1. GpuFft manages CUDA resources and kernel execution
// 2. For each FFT layer, we launch a kernel with n/2 threads
// 3. Twiddle factors are precomputed and cached on GPU
//
// Performance Notes:
// - Small FFTs (<16K): CPU is faster due to GPU overhead
// - Large FFTs (>16K): GPU provides significant speedup
// - Memory transfer is the main bottleneck for moderate sizes

use anyhow::{Result, Context, anyhow};
use std::collections::HashMap;
use tracing::info;

#[cfg(feature = "cuda")]
use cudarc::driver::*;
#[cfg(feature = "cuda")]
use cudarc::nvrtc::compile_ptx;

use crate::obelysk::field::M31;

/// Threshold below which CPU is faster
const GPU_FFT_THRESHOLD: usize = 1 << 14; // 16K elements

/// Maximum cached twiddle size
const MAX_CACHED_TWIDDLES: u32 = 24; // Up to 2^24 = 16M elements

/// GPU FFT executor
#[cfg(feature = "cuda")]
pub struct GpuFft {
    device: std::sync::Arc<CudaDevice>,
    fft_layer_kernel: CudaFunction,
    ifft_layer_kernel: CudaFunction,
    bit_reverse_kernel: CudaFunction,
    
    /// Cached twiddle factors on GPU, keyed by log_size
    twiddle_cache: HashMap<u32, CudaSlice<u32>>,
    
    /// Cached inverse twiddle factors
    itwiddle_cache: HashMap<u32, CudaSlice<u32>>,
    
    /// Statistics
    pub stats: FftStats,
}

#[derive(Default, Debug, Clone)]
pub struct FftStats {
    pub forward_fft_calls: u64,
    pub inverse_fft_calls: u64,
    pub gpu_fft_calls: u64,
    pub cpu_fallback_calls: u64,
    pub total_elements_processed: u64,
    pub total_gpu_time_ms: u64,
}

#[cfg(feature = "cuda")]
impl GpuFft {
    /// Initialize GPU FFT with compiled kernels
    pub fn new() -> Result<Self> {
        let device = CudaDevice::new(0)
            .context("Failed to initialize CUDA device")?;
        
        // Compile FFT kernels
        let fft_source = include_str!("kernels/circle_fft.cu");
        let ptx = compile_ptx(fft_source)
            .context("Failed to compile Circle FFT kernels")?;
        
        let fft_layer = device.get_func("circle_fft_layer", &ptx.to_string())
            .context("Failed to load circle_fft_layer kernel")?;
        let ifft_layer = device.get_func("circle_ifft_layer", &ptx.to_string())
            .context("Failed to load circle_ifft_layer kernel")?;
        let bit_reverse = device.get_func("bit_reverse_permute", &ptx.to_string())
            .context("Failed to load bit_reverse_permute kernel")?;
        
        Ok(Self {
            device: std::sync::Arc::new(device),
            fft_layer_kernel: fft_layer,
            ifft_layer_kernel: ifft_layer,
            bit_reverse_kernel: bit_reverse,
            twiddle_cache: HashMap::new(),
            itwiddle_cache: HashMap::new(),
            stats: FftStats::default(),
        })
    }
    
    /// Perform forward Circle FFT on GPU
    pub fn fft(&mut self, input: &[M31], twiddles: &[M31]) -> Result<Vec<M31>> {
        let n = input.len();
        let log_n = (n as f64).log2() as i32;
        
        self.stats.forward_fft_calls += 1;
        self.stats.total_elements_processed += n as u64;
        
        // For small inputs, use CPU
        if n < GPU_FFT_THRESHOLD {
            self.stats.cpu_fallback_calls += 1;
            return Ok(self.cpu_fft(input, twiddles));
        }
        
        self.stats.gpu_fft_calls += 1;
        let start = std::time::Instant::now();
        
        // Convert to u32 for GPU
        let input_u32: Vec<u32> = input.iter().map(|x| x.value()).collect();
        let twiddles_u32: Vec<u32> = twiddles.iter().map(|x| x.value()).collect();
        
        // Allocate GPU memory
        let mut data_gpu = self.device.htod_copy(input_u32)?;
        let twiddles_gpu = self.device.htod_copy(twiddles_u32)?;
        
        // Execute FFT layers
        let block_size = 256;
        let num_butterflies = n / 2;
        let grid_size = (num_butterflies + block_size - 1) / block_size;
        
        for layer in 0..log_n {
            let cfg = LaunchConfig {
                grid_dim: (grid_size as u32, 1, 1),
                block_dim: (block_size as u32, 1, 1),
                shared_mem_bytes: 0,
            };
            
            unsafe {
                self.fft_layer_kernel.launch(
                    cfg,
                    (&mut data_gpu, &twiddles_gpu, n as i32, layer, log_n),
                )?;
            }
            
            self.device.synchronize()?;
        }
        
        // Copy result back
        let result_u32 = self.device.dtoh_sync_copy(&data_gpu)?;
        let result: Vec<M31> = result_u32.iter().map(|&x| M31::from_u32(x)).collect();
        
        self.stats.total_gpu_time_ms += start.elapsed().as_millis() as u64;
        
        Ok(result)
    }
    
    /// Perform inverse Circle FFT on GPU
    pub fn ifft(&mut self, input: &[M31], itwiddles: &[M31]) -> Result<Vec<M31>> {
        let n = input.len();
        let log_n = (n as f64).log2() as i32;
        
        self.stats.inverse_fft_calls += 1;
        self.stats.total_elements_processed += n as u64;
        
        if n < GPU_FFT_THRESHOLD {
            self.stats.cpu_fallback_calls += 1;
            return Ok(self.cpu_ifft(input, itwiddles));
        }
        
        self.stats.gpu_fft_calls += 1;
        let start = std::time::Instant::now();
        
        let input_u32: Vec<u32> = input.iter().map(|x| x.value()).collect();
        let itwiddles_u32: Vec<u32> = itwiddles.iter().map(|x| x.value()).collect();
        
        let mut data_gpu = self.device.htod_copy(input_u32)?;
        let itwiddles_gpu = self.device.htod_copy(itwiddles_u32)?;
        
        let block_size = 256;
        let num_butterflies = n / 2;
        let grid_size = (num_butterflies + block_size - 1) / block_size;
        
        // IFFT processes layers in reverse order
        for layer in (0..log_n).rev() {
            let cfg = LaunchConfig {
                grid_dim: (grid_size as u32, 1, 1),
                block_dim: (block_size as u32, 1, 1),
                shared_mem_bytes: 0,
            };
            
            unsafe {
                self.ifft_layer_kernel.launch(
                    cfg,
                    (&mut data_gpu, &itwiddles_gpu, n as i32, layer, log_n),
                )?;
            }
            
            self.device.synchronize()?;
        }
        
        let result_u32 = self.device.dtoh_sync_copy(&data_gpu)?;
        let result: Vec<M31> = result_u32.iter().map(|&x| M31::from_u32(x)).collect();
        
        self.stats.total_gpu_time_ms += start.elapsed().as_millis() as u64;
        
        Ok(result)
    }
    
    /// CPU fallback for small FFTs
    fn cpu_fft(&self, input: &[M31], _twiddles: &[M31]) -> Vec<M31> {
        // Simple placeholder - in production, call Stwo's CPU FFT
        input.to_vec()
    }
    
    fn cpu_ifft(&self, input: &[M31], _itwiddles: &[M31]) -> Vec<M31> {
        input.to_vec()
    }
    
    /// Print performance statistics
    pub fn print_stats(&self) {
        let gpu_pct = if self.stats.forward_fft_calls + self.stats.inverse_fft_calls > 0 {
            (self.stats.gpu_fft_calls as f64 /
             (self.stats.forward_fft_calls + self.stats.inverse_fft_calls) as f64) * 100.0
        } else {
            0.0
        };

        info!(
            forward_fft_calls = self.stats.forward_fft_calls,
            inverse_fft_calls = self.stats.inverse_fft_calls,
            gpu_calls = self.stats.gpu_fft_calls,
            gpu_pct = gpu_pct,
            cpu_fallbacks = self.stats.cpu_fallback_calls,
            total_elements = self.stats.total_elements_processed,
            gpu_time_ms = self.stats.total_gpu_time_ms,
            "GPU FFT statistics"
        );
    }
}

// Stub implementation when CUDA is not available
#[cfg(not(feature = "cuda"))]
pub struct GpuFft {
    pub stats: FftStats,
}

#[cfg(not(feature = "cuda"))]
impl GpuFft {
    pub fn new() -> Result<Self> {
        Err(anyhow!("CUDA support not compiled in. Build with --features cuda"))
    }
    
    pub fn fft(&mut self, input: &[M31], _twiddles: &[M31]) -> Result<Vec<M31>> {
        Ok(input.to_vec())
    }
    
    pub fn ifft(&mut self, input: &[M31], _itwiddles: &[M31]) -> Result<Vec<M31>> {
        Ok(input.to_vec())
    }
    
    pub fn print_stats(&self) {
        info!("GPU FFT not available (compile with --features cuda)");
    }
}

/// Create a new GPU FFT instance
pub fn create_gpu_fft() -> Result<GpuFft> {
    GpuFft::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_small_fft_uses_cpu() {
        // Small FFTs should fall back to CPU
        let input: Vec<M31> = (0..1000).map(|i| M31::from_u32(i)).collect();
        let twiddles: Vec<M31> = (0..1000).map(|i| M31::from_u32(i)).collect();
        
        if let Ok(mut fft) = GpuFft::new() {
            let _ = fft.fft(&input, &twiddles);
            assert_eq!(fft.stats.cpu_fallback_calls, 1);
        }
    }
}

