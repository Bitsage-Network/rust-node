# GPU FHE E2E Testing - Deployment Guide

This guide explains how to deploy and run the BitSage FHE + STWO proof E2E tests on GPU-enabled infrastructure.

## Prerequisites

### Hardware Requirements
| GPU | VRAM | Expected Performance |
|-----|------|---------------------|
| NVIDIA H100 | 80GB | Optimal - 20-50x speedup |
| NVIDIA A100 | 80GB | Excellent - 15-30x speedup |
| NVIDIA A100 | 40GB | Good - 15-30x speedup |
| NVIDIA V100 | 32GB | Acceptable - 5-10x speedup |

### Software Requirements
- CUDA 12.x
- cuDNN 8.x+
- Rust nightly toolchain
- 16GB+ system RAM

## Quick Start

### Option 1: Local GPU Machine

```bash
# Clone the repository
git clone https://github.com/bitsage/bitsage-network.git
cd bitsage-network/rust-node

# Run the GPU test suite
./scripts/run_gpu_tests.sh

# Or run specific tests
./scripts/run_gpu_tests.sh --quick    # Smoke test
./scripts/run_gpu_tests.sh --benchmark # Full benchmarks
```

### Option 2: AWS p4d/p5 Instance

```bash
# Launch a p5.48xlarge (8x H100) or p4d.24xlarge (8x A100)
# Use Deep Learning AMI (Ubuntu 22.04)

# SSH into instance
ssh -i your-key.pem ubuntu@<instance-ip>

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup default nightly

# Clone and run
git clone https://github.com/bitsage/bitsage-network.git
cd bitsage-network/rust-node
./scripts/run_gpu_tests.sh
```

### Option 3: Lambda Labs / RunPod

```bash
# SSH into GPU instance
ssh ubuntu@<instance-ip>

# Install dependencies
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev

# Install Rust nightly
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup default nightly

# Clone and run
git clone https://github.com/bitsage/bitsage-network.git
cd bitsage-network/rust-node
./scripts/run_gpu_tests.sh
```

## Test Suite Overview

### Available Tests

| Test | Description | Est. Time (CPU) | Est. Time (H100) |
|------|-------------|-----------------|------------------|
| `test_gpu_detection` | Verify GPU availability | <1s | <1s |
| `test_e2e_simple_addition` | FHE addition + proof | 30s | 2s |
| `test_e2e_multiplication` | FHE multiply + proof | 33s | 3s |
| `test_e2e_batched_operations` | 100 FHE ops + proof | 52s | 5s |
| `test_e2e_neural_network_layer` | 128×64 NN layer | 142s | 8s |
| `test_e2e_full_mnist_inference` | Full MNIST model | ~10min | ~30s |
| `benchmark_suite` | Complete benchmarks | 30min+ | 2-3min |

### Running Individual Tests

```bash
# Quick smoke test
cargo test --release --package bitsage-node --test gpu_fhe_e2e_test test_gpu_detection -- --nocapture

# FHE pipeline tests
cargo test --release --package bitsage-node --test gpu_fhe_e2e_test test_e2e_simple_addition -- --nocapture

# Neural network tests
cargo test --release --package bitsage-node --test gpu_fhe_e2e_test test_e2e_neural_network_layer -- --nocapture

# Full benchmark suite (longer running)
cargo test --release --package bitsage-node --test gpu_fhe_e2e_test benchmark_suite -- --nocapture --ignored
```

## Enabling Real FHE Operations

The tests use mock FHE by default. To enable real FHE operations:

```bash
# Build with FHE feature
cargo build --release --features fhe,cuda

# Run tests with real FHE
cargo test --release --features fhe,cuda --package bitsage-node --test gpu_fhe_e2e_test -- --nocapture
```

### Real FHE Feature Flags

| Feature | Description |
|---------|-------------|
| `fhe` | Enable real TFHE/CKKS operations |
| `cuda` | Enable CUDA GPU acceleration |
| `ckks` | Use CKKS scheme (recommended for ML) |
| `tee` | Enable TEE attestation |

## Performance Tuning

### Environment Variables

```bash
# GPU selection
export CUDA_VISIBLE_DEVICES=0  # Use first GPU

# Memory tuning
export RUST_BACKTRACE=1        # Enable stack traces
export CUDA_CACHE_PATH=/tmp    # CUDA kernel cache

# FHE tuning (when using real FHE)
export FHE_POLY_DEGREE=16384   # Polynomial modulus degree
export FHE_SECURITY_BITS=128   # Security level
```

### Optimal Settings by GPU

**H100 80GB:**
```bash
export FHE_BATCH_SIZE=8192     # Max SIMD slots
export FHE_LEVELS=30           # Deep circuits without bootstrapping
```

**A100 40GB:**
```bash
export FHE_BATCH_SIZE=4096     # Reduced batch size
export FHE_LEVELS=20           # Medium depth circuits
```

## Expected Output

Successful test output looks like:

```
╔═══════════════════════════════════════════════════════════════╗
║  E2E Test: Simple Addition (a + b)                            ║
╠═══════════════════════════════════════════════════════════════╣
║  Status:      ✅ PASSED                                       ║
║  GPU Used:    Yes (NVIDIA H100 80GB)                          ║
╠═══════════════════════════════════════════════════════════════╣
║  TIMING BREAKDOWN:                                            ║
║  ├─ Encryption:         0.5ms                                 ║
║  ├─ FHE Compute:        0.1ms                                 ║
║  ├─ Proof Gen:          1.5s                                  ║
║  ├─ Verification:       5.0ms                                 ║
║  └─ Decryption:         0.2ms                                 ║
║  ─────────────────────────────────────────────────────────────║
║  TOTAL:                 1.52s                                 ║
║  Memory:                50 MB                                 ║
╚═══════════════════════════════════════════════════════════════╝
```

## Troubleshooting

### CUDA Not Found
```bash
# Check CUDA installation
nvidia-smi
nvcc --version

# Add CUDA to PATH
export PATH=/usr/local/cuda/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH
```

### Out of GPU Memory
```bash
# Reduce batch size
export FHE_BATCH_SIZE=1024

# Use gradient checkpointing
export ENABLE_CHECKPOINTING=1
```

### Rust Nightly Required
```bash
# Install nightly
rustup install nightly

# Set as default
rustup default nightly

# Or use per-project override
rustup override set nightly
```

## Production Deployment

For production deployments with real jobs:

1. **Enable TEE attestation** for hardware-binding
2. **Configure FHE keys** securely (see `docs/KEY_MANAGEMENT.md`)
3. **Set up proof verification** on Starknet
4. **Configure payment escrow** for proof-gated releases

See `docs/PRODUCTION_SETUP.md` for full production deployment guide.

## Next Steps

- Run benchmarks on your specific GPU
- Compare CPU vs GPU performance
- Integrate with your worker node configuration
- Set up proof aggregation for batch verification
