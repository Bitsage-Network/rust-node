# BitSage Network - Rust Node

High-performance Rust node for the BitSage Network, featuring **Obelysk Protocol** integration with GPU-accelerated zero-knowledge proofs.

## 🚀 Features

### ✅ Core Components
- **Obelysk Protocol** - Verifiable computation with ZK proofs
- **GPU-Accelerated Proving** - CUDA-based Circle FFT (50-100x speedup)
- **Stwo Prover Integration** - StarkWare's next-gen Circle STARK prover
- **TEE Support** - Trusted Execution Environment attestation
- **Coordinator System** - Job distribution and worker management
- **Starknet Integration** - On-chain proof verification

### 🔥 GPU Acceleration
- **Circle FFT CUDA Kernels** - Optimized for A100/H100 GPUs
- **M31 Field Operations** - Mersenne-31 arithmetic on GPU
- **Automatic Fallback** - Falls back to SIMD when GPU unavailable
- **Twiddle Caching** - Precomputed twiddle factors for FFT

## 📦 Architecture

```
rust-node/
├── src/
│   ├── obelysk/              # Obelysk Protocol
│   │   ├── mod.rs            # Protocol entry point
│   │   ├── prover.rs         # ZK proof generation
│   │   ├── vm.rs             # Obelysk Virtual Machine
│   │   ├── stwo_adapter.rs   # Stwo prover integration
│   │   └── gpu/              # GPU acceleration
│   │       ├── cuda.rs       # CUDA runtime wrapper
│   │       ├── fft.rs        # GPU FFT operations
│   │       └── kernels/      # CUDA kernel source
│   ├── coordinator/          # Job coordination
│   ├── network/              # P2P networking
│   ├── blockchain/           # Starknet integration
│   └── compute/              # Job execution
├── examples/
│   ├── gpu_benchmark.rs      # GPU performance tests
│   ├── obelysk_*.rs          # Obelysk protocol demos
│   └── gpu_m31_test.rs       # M31 field GPU tests
└── tests/
    └── gpu_backend_integration.rs
```

## 🛠️ Quick Start

### Prerequisites
- Rust nightly
- CUDA Toolkit 12.x (for GPU acceleration)
- SQLite

### Build

```bash
# Standard build (CPU only)
cargo build --release

# With GPU acceleration
cargo build --release --features cuda
```

### Run Coordinator

```bash
# Simple coordinator
cargo run --bin simple_coordinator

# Production coordinator
cargo run --bin prod_coordinator
```

### Run GPU Tests (requires NVIDIA GPU)

```bash
# GPU benchmark
cargo run --example gpu_benchmark --features cuda --release

# M31 field operations test
cargo run --example gpu_m31_test --features cuda --release
```

## 🔧 Configuration

### Environment Variables

```bash
# Blockchain
STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io
STARKNET_PRIVATE_KEY=0x...

# Database
DATABASE_URL=sqlite://./coordinator.db

# GPU (optional)
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

[database]
url = "sqlite://./coordinator.db"

[gpu]
enabled = true
device_id = 0
```

## 🧪 Testing

```bash
# All tests
cargo test

# GPU integration tests (requires GPU)
cargo test --features cuda gpu_backend

# Obelysk protocol tests
cargo test obelysk
```

## 📊 Benchmarks

### Expected GPU Speedup (A100)

| FFT Size | SIMD (CPU) | GPU | Speedup |
|----------|------------|-----|---------|
| 2^14 (16K) | 2ms | 0.5ms | 4x |
| 2^16 (64K) | 10ms | 0.8ms | 12x |
| 2^18 (256K) | 45ms | 1.5ms | 30x |
| 2^20 (1M) | 200ms | 3ms | 67x |

## 🔗 Dependencies

- **[stwo-gpu](https://github.com/Bitsage-Network/stwo-gpu)** - GPU-accelerated Stwo prover fork
- **cudarc** - CUDA runtime bindings (optional)
- **starknet-rs** - Starknet client

## 📝 API Endpoints

### Health
- `GET /health` - Node health status
- `GET /status` - Detailed component status

### Jobs
- `POST /jobs` - Submit new job
- `GET /jobs/:id` - Get job status
- `GET /jobs/:id/proof` - Get job proof

### Workers
- `POST /workers/register` - Register worker
- `GET /workers` - List workers
- `GET /workers/:id/stats` - Worker statistics

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Related Repositories

- [stwo-gpu](https://github.com/Bitsage-Network/stwo-gpu) - GPU-accelerated Stwo prover
- [BitSage-Cairo-Smart-Contracts](https://github.com/Bitsage-Network/BitSage-Cairo-Smart-Contracts) - Cairo contracts
- [BitSage-WebApp](https://github.com/Bitsage-Network/BitSage-WebApp) - Web frontend
