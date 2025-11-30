# BitSage Network - Rust Node

High-performance Rust node for the BitSage Network, featuring **Obelysk Protocol** integration with GPU-accelerated zero-knowledge proofs.

## 🚀 Key Features

### Obelysk Protocol
- **Verifiable Computation** - Prove that GPU computations ran correctly
- **TEE Integration** - Data encrypted in Trusted Execution Environment
- **GPU-Accelerated Proving** - 60-117x faster than CPU SIMD
- **Minimal Proof Output** - Only 32-byte attestation returned

### Performance (Verified on A100)

| Proof Size | GPU Time | Speedup | Throughput |
|------------|----------|---------|------------|
| 2^18 (8MB) | 2.17ms | **60.7x** | 460K/hour |
| 2^20 (32MB) | 6.53ms | **85.7x** | 127/sec |
| 2^22 (64MB) | 19.02ms | **116.7x** | 146K/hour |

**Cost: $0.000003 per proof** (A100 cloud pricing)

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

# With GPU acceleration
cargo build --release --features cuda
```

### Run GPU Benchmark

```bash
# Navigate to Stwo library
cd libs/stwo

# Run Obelysk production benchmark
cargo run --example obelysk_production_benchmark --features cuda-runtime --release
```

### Run Coordinator

```bash
cargo run --bin simple_coordinator
```

## 🔧 Configuration

### Environment Variables

```bash
# Blockchain
STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io
STARKNET_PRIVATE_KEY=0x...

# Database
DATABASE_URL=sqlite://./coordinator.db

# GPU
CUDA_VISIBLE_DEVICES=0
```

### Config File (`config/coordinator.toml`)

```toml
[server]
port = 8080
host = "0.0.0.0"

[blockchain]
rpc_url = "https://starknet-sepolia.public.blastapi.io"
chain_id = "SN_SEPOLIA"

[gpu]
enabled = true
device_id = 0
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

### Why 60-117x Speedup?

| Traditional Approach | Obelysk Approach |
|---------------------|------------------|
| Download all results | Download only 32-byte proof |
| 40-60% transfer overhead | ~0% transfer overhead |
| 10-18x speedup | **60-117x speedup** |

## 🧪 Testing

```bash
# All tests
cargo test

# GPU integration tests (requires GPU)
cargo test --features cuda gpu_backend

# Obelysk protocol tests
cargo test obelysk
```

## 📝 API Endpoints

### Health
- `GET /health` - Node health status
- `GET /status` - Detailed component status

### Jobs
- `POST /jobs` - Submit new job
- `GET /jobs/:id` - Get job status
- `GET /jobs/:id/proof` - Get job proof (32 bytes)

### Workers
- `POST /workers/register` - Register worker
- `GET /workers` - List workers
- `GET /workers/:id/stats` - Worker statistics

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
