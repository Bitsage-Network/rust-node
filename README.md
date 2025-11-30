# BitSage Network - Rust Node

High-performance Rust node for the BitSage Network, featuring **Obelysk Protocol** integration with GPU-accelerated zero-knowledge proofs.

## 🚀 Key Features

### Obelysk Protocol
- **Verifiable Computation** - Prove that GPU computations ran correctly
- **TEE Integration** - Data encrypted in Trusted Execution Environment
- **GPU-Accelerated Proving** - 60-230x faster than CPU SIMD
- **Multi-GPU Support** - Scale across multiple GPUs
- **Minimal Proof Output** - Only 32-byte attestation returned

## 🔥 Performance

### Single GPU (Verified on A100 80GB)

| Proof Size | GPU Time | Speedup | Throughput |
|------------|----------|---------|------------|
| 2^18 (8MB) | 2.17ms | **60.7x** | 460K/hour |
| 2^20 (32MB) | 6.53ms | **85.7x** | 127/sec |
| 2^22 (64MB) | 19.02ms | **116.7x** | 146K/hour |

### GPU Scaling Projections

| GPU | Est. Speedup | Proofs/sec | Cost/Proof |
|-----|--------------|------------|------------|
| RTX 4090 | ~50-80x | ~100 | $0.0000011 |
| A100 80GB | **60-117x** ✓ | **127** ✓ | $0.0000033 |
| H100 80GB | ~120-200x | ~250 | $0.0000033 |
| H200 141GB | ~150-230x | ~300 | $0.0000040 |
| B100/B200 | ~200-400x | ~500 | TBD |

### Multi-GPU Scaling

| Configuration | Throughput | Single Proof |
|---------------|------------|--------------|
| 2x A100 | 254/sec | ~1.8x faster |
| 4x A100 | 508/sec | ~3.5x faster |
| 8x A100 (DGX) | 1,016/sec | ~6.5x faster |
| 8x H100 (DGX H100) | ~2,000/sec | ~12x faster |

## 📦 Architecture

```
rust-node/
├── src/
│   ├── obelysk/              # Obelysk Protocol
│   │   ├── prover.rs         # ZK proof generation
│   │   ├── vm.rs             # Obelysk Virtual Machine
│   │   └── stwo_adapter.rs   # Stwo GPU integration
│   ├── coordinator/          # Job coordination
│   ├── network/              # P2P networking
│   ├── blockchain/           # Starknet integration
│   └── compute/              # Job execution
└── libs/stwo/                # GPU-accelerated Stwo fork
```

## 🛠️ Quick Start

### Prerequisites
- Rust nightly
- CUDA Toolkit 12.x (for GPU acceleration)
- NVIDIA GPU (A100/H100 recommended)

### Build

```bash
# Standard build (CPU only)
cargo build --release

# Single GPU
cargo build --release --features cuda

# Multi-GPU
cargo build --release --features cuda,multi-gpu
```

### Run GPU Benchmark

```bash
cd libs/stwo
cargo run --example obelysk_production_benchmark --features cuda-runtime --release
```

## 📊 How Obelysk Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    Obelysk Proof Pipeline                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Client submits encrypted workload                          │
│                    │                                            │
│                    ▼                                            │
│  2. Data uploaded to GPU (stays in TEE)                        │
│                    │                                            │
│                    ▼                                            │
│  3. GPU computes: FFT → FRI → Merkle                           │
│     (Data NEVER leaves GPU)                                     │
│                    │                                            │
│                    ▼                                            │
│  4. 32-byte proof/attestation returned                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-GPU Architecture

```
THROUGHPUT MODE (Independent Proofs)
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│  GPU 0  │  │  GPU 1  │  │  GPU 2  │  │  GPU 3  │
│ Proof A │  │ Proof B │  │ Proof C │  │ Proof D │  → 4x throughput
└─────────┘  └─────────┘  └─────────┘  └─────────┘

DISTRIBUTED MODE (Single Large Proof)
┌─────────────────────────────────────────────────────────────┐
│                    Coordinator (CPU)                         │
└─────────────────────────────────────────────────────────────┘
       │              │              │              │
       ▼              ▼              ▼              ▼
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│  GPU 0  │◄──►│  GPU 1  │◄──►│  GPU 2  │◄──►│  GPU 3  │
│Polys 0-3│    │Polys 4-7│    │Polys 8-11│   │Polys12-15│
└─────────┘    └─────────┘    └─────────┘    └─────────┘
       │              │              │              │
       └──────────────┴──────────────┴──────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Combined Proof │
                    │    (32 bytes)   │
                    └─────────────────┘
```

### Why 60-117x Speedup?

| Traditional Approach | Obelysk Approach |
|---------------------|------------------|
| Download all results | Download only 32-byte proof |
| 40-60% transfer overhead | ~0% transfer overhead |
| 10-18x speedup | **60-117x speedup** |

## 🔧 Configuration

### Environment Variables

```bash
# Blockchain
STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io
STARKNET_PRIVATE_KEY=0x...

# GPU
CUDA_VISIBLE_DEVICES=0,1,2,3  # For multi-GPU
```

### Config File (`config/coordinator.toml`)

```toml
[server]
port = 8080
host = "0.0.0.0"

[gpu]
enabled = true
device_ids = [0, 1, 2, 3]  # Multi-GPU
mode = "throughput"  # or "distributed"
```

## 🧪 Testing

```bash
# All tests
cargo test

# GPU integration tests
cargo test --features cuda gpu_backend

# Multi-GPU tests
cargo test --features cuda,multi-gpu multi_gpu
```

## 📝 API Endpoints

### Health
- `GET /health` - Node health status
- `GET /gpu/status` - GPU availability and stats

### Jobs
- `POST /jobs` - Submit new job
- `GET /jobs/:id` - Get job status
- `GET /jobs/:id/proof` - Get 32-byte proof

### Workers
- `POST /workers/register` - Register GPU worker
- `GET /workers` - List workers with GPU info

## 🔗 Related Repositories

- [stwo-gpu](https://github.com/Bitsage-Network/stwo-gpu) - GPU-accelerated Stwo prover
- [BitSage-Cairo-Smart-Contracts](https://github.com/Bitsage-Network/BitSage-Cairo-Smart-Contracts) - Cairo contracts
- [BitSage-WebApp](https://github.com/Bitsage-Network/BitSage-WebApp) - Web frontend

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built by [BitSage Network](https://github.com/Bitsage-Network)**

*Powering verifiable computation with GPU-accelerated ZK proofs*

</div>
