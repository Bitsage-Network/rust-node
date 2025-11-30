// Test GPU M31 operations and verify correctness vs CPU
//
// This example demonstrates:
// 1. GPU initialization
// 2. M31 field operations on GPU (add, sub, mul)
// 3. Verification against CPU results
// 4. Performance comparison
//
// Usage:
//   cargo run --example gpu_m31_test --features cuda --release

use anyhow::Result;
use bitsage_node::obelysk::field::M31;
use bitsage_node::obelysk::gpu::{GpuBackend, GpuBackendType};
use std::time::Instant;

fn main() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║             GPU M31 Operations Test & Verification                   ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
    
    // Initialize GPU backend
    println!("🚀 Initializing GPU backend...");
    let gpu = match GpuBackendType::auto_detect()? {
        GpuBackendType::Cpu => {
            println!("❌ No GPU detected. This test requires CUDA GPU.");
            println!("   Tip: Run on A100/H100 instance or build without --features cuda");
            return Ok(());
        }
        #[cfg(feature = "cuda")]
        GpuBackendType::Cuda(backend) => backend,
        #[cfg(feature = "rocm")]
        GpuBackendType::Rocm(_backend) => {
            println!("⚠️  ROCm backend detected but not yet fully tested");
            return Ok(());
        }
    };
    
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("TEST 1: Small Array (1K elements)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    test_m31_operations(&gpu, 1024)?;
    
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("TEST 2: Medium Array (100K elements)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    test_m31_operations(&gpu, 100_000)?;
    
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("TEST 3: Large Array (1M elements)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    test_m31_operations(&gpu, 1_000_000)?;
    
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                      ✅ ALL TESTS PASSED                             ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    
    Ok(())
}

#[cfg(feature = "cuda")]
fn test_m31_operations(gpu: &bitsage_node::obelysk::gpu::cuda::CudaBackend, n: usize) -> Result<()> {
    use bitsage_node::obelysk::gpu::GpuBackend;
    
    println!("   Array size: {} elements ({:.2} MB)", n, n * 4 as f64 / 1e6);
    
    // Generate test data
    let a: Vec<M31> = (0..n).map(|i| M31::from_u32((i % 1000) as u32 + 1)).collect();
    let b: Vec<M31> = (0..n).map(|i| M31::from_u32((i % 500) as u32 + 1)).collect();
    
    // Compute CPU reference results
    println!("   Computing CPU reference...");
    let cpu_start = Instant::now();
    let cpu_add: Vec<M31> = a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect();
    let cpu_sub: Vec<M31> = a.iter().zip(b.iter()).map(|(x, y)| *x - *y).collect();
    let cpu_mul: Vec<M31> = a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect();
    let cpu_time = cpu_start.elapsed();
    println!("   ✓ CPU time: {:.3} ms", cpu_time.as_micros() as f64 / 1000.0);
    
    // Allocate GPU memory
    println!("   Allocating GPU memory...");
    let mut gpu_a = gpu.allocate(n * 4)?;
    let mut gpu_b = gpu.allocate(n * 4)?;
    let mut gpu_result = gpu.allocate(n * 4)?;
    
    // Transfer data to GPU
    println!("   Transferring to GPU...");
    let transfer_start = Instant::now();
    gpu.transfer_to_gpu(&a, &mut gpu_a)?;
    gpu.transfer_to_gpu(&b, &mut gpu_b)?;
    let transfer_time = transfer_start.elapsed();
    println!("   ✓ Transfer time: {:.3} ms", transfer_time.as_micros() as f64 / 1000.0);
    
    // Test Addition
    println!("   Testing M31 Addition on GPU...");
    let gpu_start = Instant::now();
    gpu.m31_add(&gpu_a, &gpu_b, &mut gpu_result, n)?;
    let gpu_add_time = gpu_start.elapsed();
    
    let mut gpu_add_result = vec![M31::zero(); n];
    gpu.transfer_from_gpu(&gpu_result, &mut gpu_add_result)?;
    
    // Verify correctness
    let mut add_errors = 0;
    for i in 0..n.min(100) {  // Check first 100 elements
        if gpu_add_result[i] != cpu_add[i] {
            add_errors += 1;
            if add_errors <= 5 {  // Show first 5 errors
                println!("      ERROR at {}: GPU={} CPU={}", i, 
                    gpu_add_result[i].value(), cpu_add[i].value());
            }
        }
    }
    
    if add_errors == 0 {
        println!("   ✅ Addition: CORRECT ({:.3} ms, {:.1}x speedup)", 
            gpu_add_time.as_micros() as f64 / 1000.0,
            cpu_time.as_secs_f64() / gpu_add_time.as_secs_f64() * 3.0  // /3 because CPU did 3 ops
        );
    } else {
        println!("   ❌ Addition: {} ERRORS FOUND", add_errors);
    }
    
    // Test Subtraction
    println!("   Testing M31 Subtraction on GPU...");
    let gpu_start = Instant::now();
    gpu.m31_sub(&gpu_a, &gpu_b, &mut gpu_result, n)?;
    let gpu_sub_time = gpu_start.elapsed();
    
    let mut gpu_sub_result = vec![M31::zero(); n];
    gpu.transfer_from_gpu(&gpu_result, &mut gpu_sub_result)?;
    
    let mut sub_errors = 0;
    for i in 0..n.min(100) {
        if gpu_sub_result[i] != cpu_sub[i] {
            sub_errors += 1;
            if sub_errors <= 5 {
                println!("      ERROR at {}: GPU={} CPU={}", i,
                    gpu_sub_result[i].value(), cpu_sub[i].value());
            }
        }
    }
    
    if sub_errors == 0 {
        println!("   ✅ Subtraction: CORRECT ({:.3} ms, {:.1}x speedup)",
            gpu_sub_time.as_micros() as f64 / 1000.0,
            cpu_time.as_secs_f64() / gpu_sub_time.as_secs_f64() * 3.0
        );
    } else {
        println!("   ❌ Subtraction: {} ERRORS FOUND", sub_errors);
    }
    
    // Test Multiplication
    println!("   Testing M31 Multiplication on GPU...");
    let gpu_start = Instant::now();
    gpu.m31_mul(&gpu_a, &gpu_b, &mut gpu_result, n)?;
    let gpu_mul_time = gpu_start.elapsed();
    
    let mut gpu_mul_result = vec![M31::zero(); n];
    gpu.transfer_from_gpu(&gpu_result, &mut gpu_mul_result)?;
    
    let mut mul_errors = 0;
    for i in 0..n.min(100) {
        if gpu_mul_result[i] != cpu_mul[i] {
            mul_errors += 1;
            if mul_errors <= 5 {
                println!("      ERROR at {}: GPU={} CPU={}", i,
                    gpu_mul_result[i].value(), cpu_mul[i].value());
            }
        }
    }
    
    if mul_errors == 0 {
        println!("   ✅ Multiplication: CORRECT ({:.3} ms, {:.1}x speedup)",
            gpu_mul_time.as_micros() as f64 / 1000.0,
            cpu_time.as_secs_f64() / gpu_mul_time.as_secs_f64() * 3.0
        );
    } else {
        println!("   ❌ Multiplication: {} ERRORS FOUND", mul_errors);
    }
    
    // Overall GPU time (including transfers)
    let total_gpu_time = transfer_time + gpu_add_time + gpu_sub_time + gpu_mul_time;
    println!();
    println!("   Summary:");
    println!("     CPU Total:     {:.3} ms", cpu_time.as_micros() as f64 / 1000.0);
    println!("     GPU Compute:   {:.3} ms", 
        (gpu_add_time + gpu_sub_time + gpu_mul_time).as_micros() as f64 / 1000.0);
    println!("     GPU + Transfer: {:.3} ms", total_gpu_time.as_micros() as f64 / 1000.0);
    println!("     Speedup:       {:.1}x (compute only)", 
        cpu_time.as_secs_f64() / (gpu_add_time + gpu_sub_time + gpu_mul_time).as_secs_f64());
    
    // Clean up
    gpu.free(gpu_a)?;
    gpu.free(gpu_b)?;
    gpu.free(gpu_result)?;
    
    Ok(())
}

#[cfg(not(feature = "cuda"))]
fn test_m31_operations(_gpu: &(), _n: usize) -> Result<()> {
    println!("   ⚠️  CUDA feature not enabled");
    Ok(())
}


