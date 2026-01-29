# BitSage GPU Worker - Quick Start Guide

This guide covers deploying the BitSage GPU worker for production-level STWO proof generation on Starknet.

## Prerequisites

- NVIDIA GPU (H100, A100, RTX 4090, or similar)
- CUDA Toolkit 12.x
- Ubuntu 22.04+ or similar Linux distribution
- Starknet testnet/mainnet tokens (STRK for gas)

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/Bitsage-Network/bitsage-network.git
cd bitsage-network
```

### 2. Run the Setup Script

```bash
./rust-node/scripts/gpu_worker_setup.sh
```

This script will:
- Detect GPU hardware
- Install CUDA toolkit if needed
- Build STWO with GPU acceleration
- Build the worker binary
- Run GPU proof generation tests

### 3. Start the Worker

```bash
cd rust-node
./target/release/sage-worker setup --network sepolia
./target/release/sage-worker start
```

## Manual Setup

### Environment Variables

Create a `.env` file:

```bash
cd rust-node
cp .env.example .env
```

Set the required variables:

```bash
# Starknet RPC
export STARKNET_RPC_URL="https://rpc.starknet-testnet.lava.build"

# Contract Addresses (Sepolia)
export STWO_VERIFIER_ADDRESS="0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d"
export PROOF_VERIFIER_ADDRESS="0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b"
export SAGE_TOKEN_ADDRESS="0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850"
```

### Build with GPU Support

```bash
# Build STWO with GPU features
cd libs/stwo
cargo build --release --package stwo --features "prover,std,gpu,cuda-runtime"

# Build worker with CUDA
cd ../../rust-node
cargo build --release --features cuda --bin sage-worker
```

### Run GPU Tests

```bash
# Run STWO GPU unit tests
cd libs/stwo
cargo test --release --package stwo --features "prover,std,gpu,cuda-runtime" gpu_

# Run GPU benchmark
cd rust-node
cargo run --release --features cuda --example gpu_benchmark
```

## Sepolia Contract Addresses

| Contract | Address |
|----------|---------|
| SAGE Token | `0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850` |
| STWO Verifier | `0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d` |
| Proof Verifier | `0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b` |
| Prover Staking | `0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b` |
| Job Manager | `0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3` |
| Faucet | `0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3` |

## GPU Feature Overview

The STWO GPU backend provides:

- **GPU FFT**: CUDA-accelerated NTT/iNTT operations
- **GPU FRI Folding**: Parallel FRI layer computation
- **GPU Merkle Trees**: Fast Merkle tree construction
- **Pinned Memory Pool**: Optimized CPU-GPU transfers
- **Multi-GPU Support**: Work stealing across multiple GPUs
- **CUDA Graphs**: Kernel launch overhead reduction

### Performance Expectations

| GPU | Trace Size 2^20 | Trace Size 2^22 | Trace Size 2^24 |
|-----|-----------------|-----------------|-----------------|
| H100 | ~2s | ~8s | ~35s |
| A100 | ~4s | ~15s | ~60s |
| RTX 4090 | ~6s | ~25s | ~100s |

## One-Click Deploy with SDK

Install the SDK:

```bash
npm install @bitsage/sdk
```

Deploy a GPU worker:

```typescript
import { BitSageClient, GpuProver } from '@bitsage/sdk';

const client = new BitSageClient({
  network: 'sepolia',
  rpcUrl: 'https://rpc.starknet-testnet.lava.build'
});

// Initialize GPU prover
const prover = new GpuProver({
  gpuEnabled: true,
  securityBits: 128
});

// Generate and submit proof
const proof = await prover.generateProof(traceData);
const txHash = await client.submitProof(proof);
```

## Gasless Proof Submission (V3 Paymaster)

Workers can submit proofs without holding STRK for gas by using a paymaster contract that sponsors transaction fees.

### Setup

Add the paymaster address to your environment:

```bash
export PAYMASTER_ADDRESS=0x<funded_paymaster_contract>
```

Or add it to your `.env` file. The worker will automatically use INVOKE_V3 transactions with `paymaster_data` when this is set. If unset, standard V1 transactions are used (requires STRK for gas).

### How It Works

- V3 transactions use **STRK resource bounds** instead of `max_fee`
- The `paymaster_data` field tells the sequencer which contract pays gas
- Transaction hashes use **Poseidon** (not Pedersen) for V3
- Falls back to V1 automatically if no paymaster is configured

## Troubleshooting

### CUDA Not Found

```bash
# Check CUDA installation
nvidia-smi
nvcc --version

# Install CUDA toolkit (Ubuntu)
sudo apt-get update
sudo apt-get install -y cuda-toolkit-12-0
```

### Build Errors

```bash
# Ensure nightly Rust
rustup default nightly

# Clean and rebuild
cargo clean
cargo build --release --features cuda
```

### Worker Connection Issues

```bash
# Check coordinator connectivity
curl -s http://coordinator.bitsage.network/health

# Check worker status
./target/release/sage-worker status
```

## Monitoring

View worker metrics:

```bash
# Check worker status
./target/release/sage-worker status

# View worker info
./target/release/sage-worker info

# Follow logs
./target/release/sage-worker logs -f
```

## Support

- Dashboard: https://dashboard.bitsage.network
- Documentation: https://docs.bitsage.network
- Discord: https://discord.gg/bitsage
