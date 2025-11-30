/**
 * M31 Field Operations for GPU
 * 
 * Mersenne-31 field: p = 2^31 - 1
 * 
 * Why M31 is perfect for GPUs:
 * - Fits in 32-bit registers (native GPU operations)
 * - Single-cycle arithmetic
 * - No BigInt libraries needed
 * - SIMD-friendly within GPU warps
 * 
 * Performance: ~10-100x faster than 254-bit fields
 */

#define M31_MOD 2147483647  // 2^31 - 1

/**
 * M31 Addition: (a + b) mod (2^31 - 1)
 * 
 * Optimization: Use 64-bit intermediate to avoid overflow,
 * then reduce with conditional subtraction (branchless if possible)
 */
__device__ inline uint32_t m31_add(uint32_t a, uint32_t b) {
    uint64_t sum = (uint64_t)a + (uint64_t)b;
    uint32_t result = (uint32_t)sum;
    
    // Reduce modulo 2^31 - 1
    // If result >= M31_MOD, subtract M31_MOD
    if (result >= M31_MOD) {
        result -= M31_MOD;
    }
    
    return result;
}

/**
 * M31 Subtraction: (a - b) mod (2^31 - 1)
 */
__device__ inline uint32_t m31_sub(uint32_t a, uint32_t b) {
    if (a >= b) {
        return a - b;
    } else {
        // Need to wrap: a - b = M31_MOD - (b - a)
        return M31_MOD - (b - a);
    }
}

/**
 * M31 Multiplication: (a * b) mod (2^31 - 1)
 * 
 * Optimization: Montgomery-like reduction for M31
 * Since M31_MOD = 2^31 - 1, we can use:
 *   a * b = low_31_bits + high_bits
 * Then reduce with one conditional subtraction
 */
__device__ inline uint32_t m31_mul(uint32_t a, uint32_t b) {
    uint64_t prod = (uint64_t)a * (uint64_t)b;
    
    // Split into 31-bit chunks
    uint32_t low = (uint32_t)(prod & 0x7FFFFFFF);   // Lower 31 bits
    uint32_t high = (uint32_t)(prod >> 31);          // Upper bits
    
    // Reduce: low + high (mod 2^31 - 1)
    uint32_t result = low + high;
    if (result >= M31_MOD) {
        result -= M31_MOD;
    }
    
    return result;
}

/**
 * M31 Negation: (-a) mod (2^31 - 1)
 */
__device__ inline uint32_t m31_neg(uint32_t a) {
    if (a == 0) return 0;
    return M31_MOD - a;
}

/**
 * Batched M31 Addition: c[i] = a[i] + b[i] for all i
 * 
 * Each thread processes one element (or multiple with striding)
 */
extern "C" __global__ void m31_add_batch(
    const uint32_t* __restrict__ a,
    const uint32_t* __restrict__ b,
    uint32_t* __restrict__ c,
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    
    // Grid-stride loop for better occupancy
    for (int i = idx; i < n; i += stride) {
        c[i] = m31_add(a[i], b[i]);
    }
}

/**
 * Batched M31 Subtraction
 */
extern "C" __global__ void m31_sub_batch(
    const uint32_t* __restrict__ a,
    const uint32_t* __restrict__ b,
    uint32_t* __restrict__ c,
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    
    for (int i = idx; i < n; i += stride) {
        c[i] = m31_sub(a[i], b[i]);
    }
}

/**
 * Batched M31 Multiplication
 */
extern "C" __global__ void m31_mul_batch(
    const uint32_t* __restrict__ a,
    const uint32_t* __restrict__ b,
    uint32_t* __restrict__ c,
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    
    for (int i = idx; i < n; i += stride) {
        c[i] = m31_mul(a[i], b[i]);
    }
}

/**
 * M31 Scalar Multiplication: c[i] = scalar * a[i]
 */
extern "C" __global__ void m31_scalar_mul(
    const uint32_t* __restrict__ a,
    uint32_t scalar,
    uint32_t* __restrict__ c,
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    
    for (int i = idx; i < n; i += stride) {
        c[i] = m31_mul(scalar, a[i]);
    }
}

/**
 * M31 Dot Product: result = sum(a[i] * b[i])
 * 
 * Uses parallel reduction within blocks
 */
extern "C" __global__ void m31_dot_product(
    const uint32_t* __restrict__ a,
    const uint32_t* __restrict__ b,
    uint32_t* __restrict__ result,
    int n
) {
    __shared__ uint32_t shared_sums[256];
    
    int tid = threadIdx.x;
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    
    // Each thread computes partial sum
    uint32_t sum = 0;
    for (int i = idx; i < n; i += stride) {
        sum = m31_add(sum, m31_mul(a[i], b[i]));
    }
    
    // Store partial sum in shared memory
    shared_sums[tid] = sum;
    __syncthreads();
    
    // Parallel reduction in shared memory
    for (int s = blockDim.x / 2; s > 0; s >>= 1) {
        if (tid < s) {
            shared_sums[tid] = m31_add(shared_sums[tid], shared_sums[tid + s]);
        }
        __syncthreads();
    }
    
    // First thread in block writes result
    if (tid == 0) {
        atomicAdd(result, shared_sums[0]);  // Note: might need custom M31 atomic
    }
}


