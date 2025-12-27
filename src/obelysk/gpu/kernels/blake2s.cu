/**
 * Blake2s Hash Function for GPU
 *
 * Blake2s is a cryptographic hash function optimized for 32-bit platforms.
 * Perfect for GPU acceleration because:
 * - Uses only 32-bit operations (native GPU operations)
 * - Parallelizable across multiple independent hash computations
 * - Constant-time mixing function prevents timing attacks
 *
 * This implementation supports:
 * - Batch hashing (multiple independent hashes in parallel)
 * - Variable input sizes up to 64 bytes per hash
 * - 32-byte (256-bit) output digest
 *
 * Used for Merkle tree construction in STARK proofs.
 */

#include <stdint.h>

// Blake2s constants
#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_DIGEST_SIZE 32
#define BLAKE2S_KEY_SIZE 32

// Blake2s IV (Initialization Vector) - first 32 bits of fractional parts of sqrt(2..9)
__constant__ uint32_t BLAKE2S_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Blake2s Sigma schedule for 10 rounds
__constant__ uint8_t BLAKE2S_SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

/**
 * Right rotation for 32-bit integers
 */
__device__ inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/**
 * Blake2s G mixing function
 *
 * Mixes four state words with two message words.
 * Uses rotations of 16, 12, 8, and 7 bits.
 */
__device__ inline void blake2s_g(
    uint32_t* v,
    int a, int b, int c, int d,
    uint32_t x, uint32_t y
) {
    v[a] = v[a] + v[b] + x;
    v[d] = rotr32(v[d] ^ v[a], 16);

    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);

    v[a] = v[a] + v[b] + y;
    v[d] = rotr32(v[d] ^ v[a], 8);

    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

/**
 * Blake2s compression function
 *
 * Compresses a 64-byte message block into the state.
 * Performs 10 rounds of mixing.
 */
__device__ void blake2s_compress(
    uint32_t state[8],
    const uint32_t block[16],
    uint64_t t,          // Total bytes compressed so far
    bool last_block      // True if this is the final block
) {
    uint32_t v[16];

    // Initialize working vector
    // First half is the current state
    for (int i = 0; i < 8; i++) {
        v[i] = state[i];
    }

    // Second half is IV XORed with counter and flags
    v[8]  = BLAKE2S_IV[0];
    v[9]  = BLAKE2S_IV[1];
    v[10] = BLAKE2S_IV[2];
    v[11] = BLAKE2S_IV[3];
    v[12] = BLAKE2S_IV[4] ^ (uint32_t)t;
    v[13] = BLAKE2S_IV[5] ^ (uint32_t)(t >> 32);
    v[14] = last_block ? ~BLAKE2S_IV[6] : BLAKE2S_IV[6];
    v[15] = BLAKE2S_IV[7];

    // 10 rounds of mixing
    for (int round = 0; round < 10; round++) {
        const uint8_t* sigma = BLAKE2S_SIGMA[round];

        // Column step
        blake2s_g(v, 0, 4,  8, 12, block[sigma[0]],  block[sigma[1]]);
        blake2s_g(v, 1, 5,  9, 13, block[sigma[2]],  block[sigma[3]]);
        blake2s_g(v, 2, 6, 10, 14, block[sigma[4]],  block[sigma[5]]);
        blake2s_g(v, 3, 7, 11, 15, block[sigma[6]],  block[sigma[7]]);

        // Diagonal step
        blake2s_g(v, 0, 5, 10, 15, block[sigma[8]],  block[sigma[9]]);
        blake2s_g(v, 1, 6, 11, 12, block[sigma[10]], block[sigma[11]]);
        blake2s_g(v, 2, 7,  8, 13, block[sigma[12]], block[sigma[13]]);
        blake2s_g(v, 3, 4,  9, 14, block[sigma[14]], block[sigma[15]]);
    }

    // Finalize: XOR state with both halves of working vector
    for (int i = 0; i < 8; i++) {
        state[i] ^= v[i] ^ v[i + 8];
    }
}

/**
 * Batched Blake2s hash computation
 *
 * Each thread computes one hash independently.
 * Inputs are packed contiguously: [input_0][input_1][input_2]...
 * Outputs are 32 bytes per hash: [digest_0][digest_1][digest_2]...
 *
 * @param inputs      Pointer to input data (all inputs concatenated)
 * @param outputs     Pointer to output digests (32 bytes each)
 * @param num_hashes  Number of independent hashes to compute
 * @param input_size  Size of each input in bytes (must be <= 64 for single block)
 */
extern "C" __global__ void blake2s_batch(
    const uint8_t* __restrict__ inputs,
    uint8_t* __restrict__ outputs,
    int num_hashes,
    int input_size
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;

    for (int hash_idx = idx; hash_idx < num_hashes; hash_idx += stride) {
        // Calculate input/output pointers for this hash
        const uint8_t* input = inputs + hash_idx * input_size;
        uint8_t* output = outputs + hash_idx * BLAKE2S_DIGEST_SIZE;

        // Initialize state with IV
        uint32_t state[8];
        for (int i = 0; i < 8; i++) {
            state[i] = BLAKE2S_IV[i];
        }

        // XOR in parameter block (digest length = 32, no key, fanout = 1, depth = 1)
        state[0] ^= 0x01010000 ^ BLAKE2S_DIGEST_SIZE;

        // Prepare message block (pad with zeros if needed)
        uint32_t block[16] = {0};
        for (int i = 0; i < input_size && i < BLAKE2S_BLOCK_SIZE; i++) {
            int word_idx = i / 4;
            int byte_idx = i % 4;
            block[word_idx] |= ((uint32_t)input[i]) << (8 * byte_idx);
        }

        // Compress (single block, always the last block for <= 64 byte inputs)
        blake2s_compress(state, block, input_size, true);

        // Write output digest (little-endian)
        for (int i = 0; i < 8; i++) {
            output[i * 4 + 0] = (uint8_t)(state[i] >> 0);
            output[i * 4 + 1] = (uint8_t)(state[i] >> 8);
            output[i * 4 + 2] = (uint8_t)(state[i] >> 16);
            output[i * 4 + 3] = (uint8_t)(state[i] >> 24);
        }
    }
}

/**
 * Blake2s Merkle tree layer computation
 *
 * Computes one layer of a Merkle tree by hashing pairs of 32-byte nodes.
 * Output[i] = Blake2s(Input[2*i] || Input[2*i + 1])
 *
 * @param inputs      Pointer to input nodes (num_nodes * 32 bytes)
 * @param outputs     Pointer to output nodes (num_nodes/2 * 32 bytes)
 * @param num_nodes   Number of input nodes (must be even)
 */
extern "C" __global__ void blake2s_merkle_layer(
    const uint8_t* __restrict__ inputs,
    uint8_t* __restrict__ outputs,
    int num_nodes
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    int num_pairs = num_nodes / 2;

    for (int pair_idx = idx; pair_idx < num_pairs; pair_idx += stride) {
        // Get input pair (two 32-byte nodes concatenated = 64 bytes)
        const uint8_t* left = inputs + (pair_idx * 2) * BLAKE2S_DIGEST_SIZE;
        const uint8_t* right = inputs + (pair_idx * 2 + 1) * BLAKE2S_DIGEST_SIZE;
        uint8_t* output = outputs + pair_idx * BLAKE2S_DIGEST_SIZE;

        // Initialize state
        uint32_t state[8];
        for (int i = 0; i < 8; i++) {
            state[i] = BLAKE2S_IV[i];
        }
        state[0] ^= 0x01010000 ^ BLAKE2S_DIGEST_SIZE;

        // Prepare block (64 bytes = left || right)
        uint32_t block[16];
        for (int i = 0; i < 8; i++) {
            block[i] =
                ((uint32_t)left[i * 4 + 0]) |
                ((uint32_t)left[i * 4 + 1] << 8) |
                ((uint32_t)left[i * 4 + 2] << 16) |
                ((uint32_t)left[i * 4 + 3] << 24);
        }
        for (int i = 0; i < 8; i++) {
            block[i + 8] =
                ((uint32_t)right[i * 4 + 0]) |
                ((uint32_t)right[i * 4 + 1] << 8) |
                ((uint32_t)right[i * 4 + 2] << 16) |
                ((uint32_t)right[i * 4 + 3] << 24);
        }

        // Compress single 64-byte block (always the last block for Merkle)
        blake2s_compress(state, block, 64, true);

        // Write output
        for (int i = 0; i < 8; i++) {
            output[i * 4 + 0] = (uint8_t)(state[i] >> 0);
            output[i * 4 + 1] = (uint8_t)(state[i] >> 8);
            output[i * 4 + 2] = (uint8_t)(state[i] >> 16);
            output[i * 4 + 3] = (uint8_t)(state[i] >> 24);
        }
    }
}

/**
 * Blake2s with keyed mode (MAC)
 *
 * Computes keyed Blake2s hashes for message authentication.
 *
 * @param inputs      Pointer to input messages
 * @param key         32-byte key (same for all hashes)
 * @param outputs     Pointer to output MACs (32 bytes each)
 * @param num_hashes  Number of independent MACs to compute
 * @param input_size  Size of each input in bytes (must be <= 64)
 */
extern "C" __global__ void blake2s_mac_batch(
    const uint8_t* __restrict__ inputs,
    const uint8_t* __restrict__ key,
    uint8_t* __restrict__ outputs,
    int num_hashes,
    int input_size
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;

    // Load key into registers (shared across all threads)
    __shared__ uint32_t shared_key[8];
    if (threadIdx.x < 8) {
        shared_key[threadIdx.x] =
            ((uint32_t)key[threadIdx.x * 4 + 0]) |
            ((uint32_t)key[threadIdx.x * 4 + 1] << 8) |
            ((uint32_t)key[threadIdx.x * 4 + 2] << 16) |
            ((uint32_t)key[threadIdx.x * 4 + 3] << 24);
    }
    __syncthreads();

    for (int hash_idx = idx; hash_idx < num_hashes; hash_idx += stride) {
        const uint8_t* input = inputs + hash_idx * input_size;
        uint8_t* output = outputs + hash_idx * BLAKE2S_DIGEST_SIZE;

        // Initialize state with IV
        uint32_t state[8];
        for (int i = 0; i < 8; i++) {
            state[i] = BLAKE2S_IV[i];
        }

        // XOR in parameter block for keyed mode
        // kk = 32 (key length), nn = 32 (digest length)
        state[0] ^= 0x01010000 ^ (BLAKE2S_KEY_SIZE << 8) ^ BLAKE2S_DIGEST_SIZE;

        // First block is the key padded to 64 bytes
        uint32_t key_block[16] = {0};
        for (int i = 0; i < 8; i++) {
            key_block[i] = shared_key[i];
        }
        blake2s_compress(state, key_block, BLAKE2S_BLOCK_SIZE, false);

        // Second block is the message (padded)
        uint32_t msg_block[16] = {0};
        for (int i = 0; i < input_size && i < BLAKE2S_BLOCK_SIZE; i++) {
            int word_idx = i / 4;
            int byte_idx = i % 4;
            msg_block[word_idx] |= ((uint32_t)input[i]) << (8 * byte_idx);
        }
        blake2s_compress(state, msg_block, BLAKE2S_BLOCK_SIZE + input_size, true);

        // Write output
        for (int i = 0; i < 8; i++) {
            output[i * 4 + 0] = (uint8_t)(state[i] >> 0);
            output[i * 4 + 1] = (uint8_t)(state[i] >> 8);
            output[i * 4 + 2] = (uint8_t)(state[i] >> 16);
            output[i * 4 + 3] = (uint8_t)(state[i] >> 24);
        }
    }
}
