// Circle FFT CUDA Kernels for Obelysk
//
// This implements the Circle Fast Fourier Transform over the Mersenne-31 field
// for GPU acceleration. The Circle FFT is the core operation in Circle STARKs
// and is the main bottleneck in proof generation.
//
// Mathematical Background:
// - Circle STARKs operate on the unit circle x² + y² = 1 over M31
// - The FFT uses the "butterfly" operation with twiddle factors
// - Twiddle factors are precomputed x-coordinates of circle points
//
// Performance Target: 50-100x speedup over CPU on A100/H100

#include <cuda_runtime.h>
#include <stdint.h>

// Mersenne-31 prime: 2^31 - 1
#define M31_P 2147483647U
#define M31_P2 (M31_P * 2U)

// =============================================================================
// M31 Field Arithmetic (GPU-optimized)
// =============================================================================

// Reduce a value to M31 range [0, P)
__device__ __forceinline__ uint32_t m31_reduce(uint64_t x) {
    // Fast reduction for M31: x mod (2^31 - 1)
    // = (x & P) + (x >> 31)
    uint32_t lo = (uint32_t)(x & M31_P);
    uint32_t hi = (uint32_t)(x >> 31);
    uint32_t sum = lo + hi;
    // Handle overflow
    return sum >= M31_P ? sum - M31_P : sum;
}

// M31 addition
__device__ __forceinline__ uint32_t m31_add(uint32_t a, uint32_t b) {
    uint32_t sum = a + b;
    return sum >= M31_P ? sum - M31_P : sum;
}

// M31 subtraction
__device__ __forceinline__ uint32_t m31_sub(uint32_t a, uint32_t b) {
    return a >= b ? a - b : a + M31_P - b;
}

// M31 multiplication
__device__ __forceinline__ uint32_t m31_mul(uint32_t a, uint32_t b) {
    uint64_t prod = (uint64_t)a * (uint64_t)b;
    return m31_reduce(prod);
}

// M31 negation
__device__ __forceinline__ uint32_t m31_neg(uint32_t a) {
    return a == 0 ? 0 : M31_P - a;
}

// =============================================================================
// Butterfly Operations
// =============================================================================

// Forward butterfly: (v0, v1) -> (v0 + v1*twiddle, v0 - v1*twiddle)
__device__ __forceinline__ void butterfly(uint32_t* v0, uint32_t* v1, uint32_t twiddle) {
    uint32_t tmp = m31_mul(*v1, twiddle);
    uint32_t new_v1 = m31_sub(*v0, tmp);
    *v0 = m31_add(*v0, tmp);
    *v1 = new_v1;
}

// Inverse butterfly: (v0, v1) -> ((v0+v1)/2, (v0-v1)/2 * itwiddle)
__device__ __forceinline__ void ibutterfly(uint32_t* v0, uint32_t* v1, uint32_t itwiddle) {
    uint32_t tmp = *v0;
    *v0 = m31_add(tmp, *v1);
    *v1 = m31_mul(m31_sub(tmp, *v1), itwiddle);
}

// =============================================================================
// Circle FFT Kernels
// =============================================================================

// Kernel for a single FFT layer
// Each thread handles one butterfly operation
__global__ void circle_fft_layer(
    uint32_t* __restrict__ data,
    const uint32_t* __restrict__ twiddles,
    int n,
    int layer,
    int log_n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Each layer halves the stride
    int stride = 1 << (log_n - layer - 1);
    int num_butterflies = n / 2;
    
    if (idx >= num_butterflies) return;
    
    // Calculate which butterfly group and position within group
    int group = idx / stride;
    int pos = idx % stride;
    
    // Indices of the two elements to combine
    int i0 = group * (2 * stride) + pos;
    int i1 = i0 + stride;
    
    // Get twiddle factor (bit-reversed indexing)
    int twiddle_idx = group;
    uint32_t twiddle = twiddles[twiddle_idx];
    
    // Perform butterfly
    uint32_t v0 = data[i0];
    uint32_t v1 = data[i1];
    butterfly(&v0, &v1, twiddle);
    data[i0] = v0;
    data[i1] = v1;
}

// Kernel for inverse FFT layer
__global__ void circle_ifft_layer(
    uint32_t* __restrict__ data,
    const uint32_t* __restrict__ itwiddles,
    int n,
    int layer,
    int log_n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    int stride = 1 << layer;
    int num_butterflies = n / 2;
    
    if (idx >= num_butterflies) return;
    
    int group = idx / stride;
    int pos = idx % stride;
    
    int i0 = group * (2 * stride) + pos;
    int i1 = i0 + stride;
    
    int twiddle_idx = group;
    uint32_t itwiddle = itwiddles[twiddle_idx];
    
    uint32_t v0 = data[i0];
    uint32_t v1 = data[i1];
    ibutterfly(&v0, &v1, itwiddle);
    data[i0] = v0;
    data[i1] = v1;
}

// =============================================================================
// Optimized Kernels (Shared Memory)
// =============================================================================

// Block-level FFT using shared memory for better performance
// Handles multiple layers within a single kernel launch
#define BLOCK_SIZE 256
#define SHARED_SIZE 512  // 2 * BLOCK_SIZE for double buffering

__global__ void circle_fft_block(
    uint32_t* __restrict__ data,
    const uint32_t* __restrict__ twiddles,
    int n,
    int log_n,
    int start_layer,
    int num_layers
) {
    __shared__ uint32_t shared[SHARED_SIZE];
    
    int block_start = blockIdx.x * SHARED_SIZE;
    int tid = threadIdx.x;
    
    // Load data into shared memory
    if (block_start + tid < n) {
        shared[tid] = data[block_start + tid];
    }
    if (block_start + BLOCK_SIZE + tid < n) {
        shared[BLOCK_SIZE + tid] = data[block_start + BLOCK_SIZE + tid];
    }
    __syncthreads();
    
    // Process layers
    for (int layer = start_layer; layer < start_layer + num_layers && layer < log_n; layer++) {
        int stride = 1 << (log_n - layer - 1);
        int local_stride = stride;
        
        // Only process if stride fits in our block
        if (local_stride <= BLOCK_SIZE) {
            int group = tid / local_stride;
            int pos = tid % local_stride;
            
            int i0 = group * (2 * local_stride) + pos;
            int i1 = i0 + local_stride;
            
            if (i1 < SHARED_SIZE) {
                // Get twiddle (need to calculate global twiddle index)
                int global_group = (block_start / (2 * stride)) + group;
                uint32_t twiddle = twiddles[global_group];
                
                uint32_t v0 = shared[i0];
                uint32_t v1 = shared[i1];
                butterfly(&v0, &v1, twiddle);
                shared[i0] = v0;
                shared[i1] = v1;
            }
        }
        __syncthreads();
    }
    
    // Write back to global memory
    if (block_start + tid < n) {
        data[block_start + tid] = shared[tid];
    }
    if (block_start + BLOCK_SIZE + tid < n) {
        data[block_start + BLOCK_SIZE + tid] = shared[BLOCK_SIZE + tid];
    }
}

// =============================================================================
// Bit Reversal Kernel
// =============================================================================

// Bit reverse permutation (required before/after FFT)
__global__ void bit_reverse_permute(
    uint32_t* __restrict__ data,
    int n,
    int log_n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    
    // Compute bit-reversed index
    int rev = 0;
    int temp = idx;
    for (int i = 0; i < log_n; i++) {
        rev = (rev << 1) | (temp & 1);
        temp >>= 1;
    }
    
    // Only swap if idx < rev to avoid double swapping
    if (idx < rev) {
        uint32_t tmp = data[idx];
        data[idx] = data[rev];
        data[rev] = tmp;
    }
}

// =============================================================================
// High-Level FFT Functions (called from Rust)
// =============================================================================

// Complete forward Circle FFT
// This is the main entry point called from Rust
extern "C" __global__ void circle_fft_complete(
    uint32_t* __restrict__ data,
    const uint32_t* __restrict__ twiddles,
    int n,
    int log_n
) {
    // For small FFTs, use the simple layer-by-layer approach
    // For large FFTs, the host should orchestrate multiple kernel launches
    
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // This kernel handles one layer at a time
    // The host code should call this multiple times for each layer
    // with appropriate synchronization
    
    int stride = n / 2;
    int num_butterflies = n / 2;
    
    if (idx >= num_butterflies) return;
    
    int group = idx / stride;
    int pos = idx % stride;
    
    int i0 = group * (2 * stride) + pos;
    int i1 = i0 + stride;
    
    uint32_t twiddle = twiddles[group];
    
    uint32_t v0 = data[i0];
    uint32_t v1 = data[i1];
    butterfly(&v0, &v1, twiddle);
    data[i0] = v0;
    data[i1] = v1;
}

// Complete inverse Circle FFT
extern "C" __global__ void circle_ifft_complete(
    uint32_t* __restrict__ data,
    const uint32_t* __restrict__ itwiddles,
    int n,
    int log_n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    int stride = 1;
    int num_butterflies = n / 2;
    
    if (idx >= num_butterflies) return;
    
    int group = idx / stride;
    int pos = idx % stride;
    
    int i0 = group * (2 * stride) + pos;
    int i1 = i0 + stride;
    
    uint32_t itwiddle = itwiddles[group];
    
    uint32_t v0 = data[i0];
    uint32_t v1 = data[i1];
    ibutterfly(&v0, &v1, itwiddle);
    data[i0] = v0;
    data[i1] = v1;
}

// =============================================================================
// Twiddle Factor Computation (GPU-accelerated)
// =============================================================================

// Compute twiddle factors on GPU
// This is faster than CPU for large domains
extern "C" __global__ void compute_twiddles(
    uint32_t* __restrict__ twiddles,
    uint32_t initial_x,
    uint32_t initial_y,
    int n,
    int log_n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    
    // Compute the twiddle for index idx
    // Using the circle doubling map: (x, y) -> (2x² - 1, 2xy)
    
    uint32_t x = initial_x;
    uint32_t y = initial_y;
    
    // Apply the appropriate number of doublings based on idx
    // This is a simplified version - full implementation needs
    // proper bit-reversed indexing
    
    for (int i = 0; i < log_n; i++) {
        if ((idx >> i) & 1) {
            // Apply circle point multiplication
            uint32_t new_x = m31_sub(m31_mul(x, x), m31_mul(y, y));
            uint32_t new_y = m31_mul(2, m31_mul(x, y));
            x = new_x;
            y = new_y;
        }
    }
    
    twiddles[idx] = x;  // x-coordinate is the twiddle
}
