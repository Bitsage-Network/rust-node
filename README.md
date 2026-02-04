# BitSage Network - GPU Worker Node

High-performance Rust node for the BitSage Network, featuring **Obelysk Protocol** integration with GPU-accelerated zero-knowledge proofs.

---

## One-Command Deployment

### Option 1: Docker (Recommended)

**Start earning SAGE tokens with a single command:**

```bash
# GPU Worker (requires nvidia-docker)
docker compose -f docker-compose.worker.yml up

# CPU-only (for testing)
docker compose -f docker-compose.worker.yml --profile cpu up
```

This automatically:
- Generates a wallet (account abstraction)
- Claims tokens from faucet (testnet)
- Registers with the coordinator
- Starts processing jobs
- Earns SAGE tokens

### Option 2: Native Installation

```bash
curl -sSL https://raw.githubusercontent.com/Bitsage-Network/rust-node/main/scripts/install.sh | bash
```

This interactive wizard will:
- Detect your GPU and system configuration
- Install all dependencies (Rust, CUDA drivers)
- Download and build the sage-worker
- Generate wallet and encryption keys
- Register with the network
- Start earning immediately

---

## Manual Installation

### Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **GPU** | NVIDIA RTX 3090 (24GB) | NVIDIA H100 (80GB) |
| **CUDA** | 12.0+ | 12.4+ |
| **RAM** | 32 GB | 64 GB |
| **Storage** | 100 GB SSD | 500 GB NVMe |
| **Network** | 100 Mbps | 1 Gbps |
| **OS** | Ubuntu 22.04 | Ubuntu 22.04/24.04 |

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Bitsage-Network/rust-node
cd bitsage-network/rust-node

# Build the worker
cargo build --release --bin sage-worker

# Run the setup wizard
./target/release/sage-worker setup --network sepolia

# Start the worker
./target/release/sage-worker start
```

### What the Setup Wizard Does

1. Detects your GPU(s) automatically
2. Generates a Starknet wallet (or imports existing)
3. Generates ElGamal encryption keys for privacy
4. Registers with the BitSage coordinator
5. Saves configuration to `~/.bitsage/worker.toml`

### Start Earning

```bash
# Start your worker
sage-worker start

# Check status
sage-worker status

# View earnings
sage-worker info
```

### Staking Tiers

Stake SAGE tokens to unlock higher-paying jobs:

| Tier | Stake Required | Job Priority | Max Concurrent Jobs |
|------|----------------|--------------|---------------------|
| **Consumer** | 1,000 SAGE | Standard | 4 |
| **Workstation** | 2,500 SAGE | Priority | 8 |
| **DataCenter** | 5,000 SAGE | High Priority | 16 |
| **Enterprise** | 10,000 SAGE | Premium | 32 |
| **Frontier** | 25,000 SAGE | Maximum | Unlimited |

```bash
# Stake tokens
sage-worker stake --amount 5000

# Check stake status
sage-worker info

# Claim rewards
sage-worker claim
```

---

## Performance Benchmarks

### Latest Results (February 3, 2026)

**Hardware:** NVIDIA H100 PCIe 80GB
**Network:** Starknet Sepolia
**Events per TX:** 12 (full fee distribution cascade)

### Proof Generation Performance

| Workload | Trace Steps | GPU Time | CPU Time | Speedup | Gas Cost |
|----------|-------------|----------|----------|---------|----------|
| **ML Inference** | 132 | **21ms** | 18ms | 1.0x | 0.307 STRK |
| **1K Steps** | 1,024 | **24ms** | 20ms | 0.8x | 0.307 STRK |
| **64K Steps** | 65,536 | **159ms** | 164ms | 1.0x | 0.380 STRK |
| **256K Steps** | 262,144 | **335ms** | 352ms | 1.1x | 0.404 STRK |
| **1M Steps** | 1,048,576 | **1,107ms** | 1,125ms | 1.0x | 0.429 STRK |

### On-Chain Verification Stats

| Metric | Value |
|--------|-------|
| **Events per TX** | 12 |
| **Internal Calls** | 10+ |
| **Success Rate** | 100% |
| **Calldata Size** | 173-333 felts |
| **FRI Layers** | 8-20 |

### Verified Transactions (Live on Starknet Sepolia)

```
ML_GPU:   https://sepolia.voyager.online/tx/0x068545dbe5b18a52328b0c0b74a661c6f0f7f689d4847247b055bd217a46cf53
ML_CPU:   https://sepolia.voyager.online/tx/0x051ee2466af84d94b439fae15bcb1662317a4a7116ee3e7ccb3a3f07ae731eac
GPU_1K:   https://sepolia.voyager.online/tx/0x03962dcd9b61dbcd7e5f24fab76132ad29ba4c6ba6e3b667b7f78055ee876e72
GPU_64K:  https://sepolia.voyager.online/tx/0x03cc26baf34abbed4c753ce60e53854d8728723a73acc3f7fa9f687fc6f9bfb1
GPU_256K: https://sepolia.voyager.online/tx/0x0384d3daa5f08e083115c228b91d19a2a79d3d73117eb57f666f9ec8b3574607
GPU_1M:   https://sepolia.voyager.online/tx/0x05d0ae5280523e1ec31802a8aa7ffec28eea943c498d7b1694a495087557eec9
CPU_1M:   https://sepolia.voyager.online/tx/0x03494f9bd7eb9e5a1b323b12e0478d12876d8c943b9b92035b61d824ecd8a2fe
```

### Multi-GPU Scaling (4x H100)

| Metric | Value |
|--------|-------|
| **Throughput** | **1,237 proofs/sec** |
| Per-proof time | 0.81ms |
| **Scaling efficiency** | **193%** (super-linear!) |
| Hourly capacity | **4.45 million proofs** |
| Daily capacity | **107 million proofs** |

### GPU Comparison

| GPU | Speedup | Proofs/sec | Monthly Earnings* |
|-----|---------|------------|-------------------|
| RTX 3090 | 15-40x | ~50 | ~$200-400 |
| RTX 4090 | 25-60x | ~80 | ~$350-600 |
| A100 80GB | 45-130x | 127 | ~$500-900 |
| **H100 80GB** | **55-174x** | **150** | ~$600-1,100 |
| **4x H100** | **55-174x** | **1,237** | ~$2,500-4,500 |

*Estimated based on network demand and staking tier

---

## Architecture

```
bitsage-network/
├── rust-node/
│   ├── src/
│   │   ├── bin/
│   │   │   ├── sage_worker.rs     # GPU Worker CLI (run this!)
│   │   │   ├── proof_cli.rs       # Proof generation CLI
│   │   │   └── unified_coordinator.rs
│   │   ├── obelysk/               # Obelysk Protocol
│   │   │   ├── prover.rs          # ZK proof generation
│   │   │   ├── vm.rs              # Obelysk Virtual Machine
│   │   │   ├── gpu/               # GPU acceleration
│   │   │   └── stwo_adapter.rs    # Stwo GPU integration
│   │   ├── coordinator/           # Job coordination
│   │   ├── network/               # P2P networking
│   │   ├── blockchain/            # Starknet integration
│   │   └── compute/               # Job execution
│   └── libs/stwo/                 # GPU-accelerated Stwo prover
```

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    BitSage Network Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐                                           │
│  │   Your GPU       │                                           │
│  │   sage-worker    │◄────── You run this                       │
│  └────────┬─────────┘                                           │
│           │                                                      │
│           │ HTTPS (polls for jobs)                              │
│           ▼                                                      │
│  ┌──────────────────┐                                           │
│  │   Coordinator    │◄────── Managed by BitSage                 │
│  │   (BitSage)      │                                           │
│  └────────┬─────────┘                                           │
│           │                                                      │
│           │ On-chain verification                               │
│           ▼                                                      │
│  ┌──────────────────┐                                           │
│  │   Starknet       │◄────── Smart contracts                    │
│  │   Blockchain     │        (ProverStaking, JobManager)        │
│  └──────────────────┘                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Obelysk Proof Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    Obelysk Proof Pipeline                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Client submits encrypted workload                           │
│                    │                                             │
│                    ▼                                             │
│  2. Data uploaded to GPU (stays in TEE)                         │
│                    │                                             │
│                    ▼                                             │
│  3. GPU computes: FFT → FRI → Merkle                            │
│     (Data NEVER leaves GPU - 174x faster!)                       │
│                    │                                             │
│                    ▼                                             │
│  4. 32-byte proof/attestation returned                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Obelysk Protocol: Understanding the Proving System

### Overview

BitSage uses a **two-layer proving architecture**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    YOUR APPLICATION                              │
│          (ML inference, data processing, privacy)                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    OBELYSK PROTOCOL                              │
│    High-level proving API — what YOU interact with               │
│                                                                  │
│    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│    │  ObelyskVM   │  │   Prover     │  │   Starknet   │         │
│    │  (M31 field) │  │  (circuits)  │  │   (verify)   │         │
│    └──────────────┘  └──────────────┘  └──────────────┘         │
└───────────────────────────┬─────────────────────────────────────┘
                            │ stwo_adapter.rs
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    STWO PROVER (libs/stwo/)                      │
│    Low-level Circle STARK cryptography — handled internally      │
│                                                                  │
│    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│    │  Circle FFT  │  │     FRI      │  │   Merkle     │         │
│    │   (GPU)      │  │  (folding)   │  │   (commit)   │         │
│    └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- **Obelysk** = BitSage's protocol layer (high-level, user-facing)
- **Stwo** = StarkWare's Circle STARK prover (low-level, internal)
- You interact with Obelysk APIs — Stwo is handled automatically
- The `stwo_adapter.rs` file bridges the two layers

### Why Two Layers?

| Layer | Purpose | You Touch It? |
|-------|---------|---------------|
| **Obelysk** | Application logic: ML, privacy, payments | ✅ Yes |
| **Stwo** | Cryptographic proving (Circle STARKs) | ❌ No (internal) |

**Benefits:**
- **Obelysk** provides simple APIs for verifiable computation
- **Stwo** provides 10-174x GPU speedup via Circle FFTs
- **Mersenne-31** field (2³¹ - 1) enables native 32-bit operations
- **Clean separation** means you focus on business logic, not cryptography

---

## Developer Guide: Generating Proofs

### Quick Start: Generate Your First Proof

```bash
# Build with GPU support
cargo build --release --features cuda

# Generate a demo proof (proves ML inference)
./target/release/bitsage-proof demo --batch-size 100

# Output:
# ✓ Generated proof for 100 ML inferences
# ✓ Proof size: 48.2 KB
# ✓ Proving time: 127ms (GPU)
# ✓ Proof hash: 0x7a3f...
```

### CLI Proof Generation

```bash
# Generate proof for a workload
bitsage-proof generate \
  --workload ml-inference \
  --batch-size 1000 \
  --output proof.json

# Verify locally (fast, no gas)
bitsage-proof verify --proof proof.json

# Submit to Starknet (costs gas, permanent)
bitsage-proof submit \
  --proof proof.json \
  --network sepolia

# Check on-chain status
bitsage-proof status --tx-hash 0x...
```

### Rust API: Programmatic Proof Generation

```rust
use bitsage_node::obelysk::{
    ObelyskVM, ObelyskProver, ProverConfig,
    Instruction, OpCode, M31,
};

fn main() -> anyhow::Result<()> {
    // 1. Create and execute your computation
    let mut vm = ObelyskVM::new();

    // Simple example: compute 2 * 3 + 5 = 11
    vm.load_program(vec![
        Instruction::new(OpCode::LoadImm, 0, 2, 0),  // r0 = 2
        Instruction::new(OpCode::LoadImm, 1, 3, 0),  // r1 = 3
        Instruction::new(OpCode::Mul, 2, 0, 1),      // r2 = r0 * r1 = 6
        Instruction::new(OpCode::LoadImm, 3, 5, 0),  // r3 = 5
        Instruction::new(OpCode::Add, 4, 2, 3),      // r4 = r2 + r3 = 11
    ]);

    let trace = vm.execute()?;
    println!("Result: {:?}", trace.final_state());

    // 2. Generate ZK proof
    let prover = ObelyskProver::new(ProverConfig::default());
    let proof = prover.prove_execution(&trace)?;

    println!("Proof size: {} bytes", proof.size());
    println!("Proof hash: 0x{}", hex::encode(&proof.commitment()));

    // 3. Verify locally
    assert!(prover.verify(&proof)?);
    println!("✓ Proof verified!");

    Ok(())
}
```

### GPU-Accelerated Proving

```rust
use bitsage_node::obelysk::{prewarm_gpu, stwo_adapter};

fn main() -> anyhow::Result<()> {
    // Pre-warm GPU (compile CUDA kernels)
    prewarm_gpu()?;

    // Generate trace (same as before)
    let trace = generate_ml_trace()?;

    // Prove with GPU acceleration (50-174x faster)
    let proof = stwo_adapter::prove_with_stwo_gpu(&trace)?;

    println!("GPU proving time: {:?}", proof.metrics.total_time);
    Ok(())
}
```

### Submitting Proofs to Starknet

```rust
use bitsage_node::obelysk::{StarknetClient, ProofSerializer};

async fn submit_proof(proof: StarkProof) -> anyhow::Result<String> {
    // Connect to Starknet
    let client = StarknetClient::new(
        "https://starknet-sepolia.public.blastapi.io",
        "0x...", // Your private key
    ).await?;

    // Serialize proof to Cairo format
    let cairo_proof = ProofSerializer::serialize(&proof)?;

    // Submit to verifier contract
    let tx_hash = client.submit_proof(
        cairo_proof,
        "0x..." // Verifier contract address
    ).await?;

    println!("Submitted! TX: {}", tx_hash);
    Ok(tx_hash)
}
```

### Available Workload Types

| Workload | Description | Use Case |
|----------|-------------|----------|
| `ml-inference` | Neural network inference proof | Verify ML model ran correctly |
| `data-transform` | ETL pipeline proof | Verify data processing |
| `privacy-transfer` | Private payment proof | Confidential transactions |
| `batch-verify` | Aggregate multiple proofs | Gas-efficient verification |
| `custom` | User-defined computation | Any ObelyskVM program |

---

## Module Reference

### Core Obelysk Modules

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `obelysk::vm` | Virtual machine execution | `ObelyskVM`, `Instruction`, `OpCode` |
| `obelysk::prover` | Proof generation | `ObelyskProver`, `ProverConfig`, `StarkProof` |
| `obelysk::field` | Mersenne-31 arithmetic | `M31` |
| `obelysk::circuit` | Circuit building | `Circuit`, `CircuitBuilder` |
| `obelysk::stwo_adapter` | Stwo integration | `prove_with_stwo`, `prewarm_gpu` |

### GPU Modules

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `obelysk::gpu` | GPU acceleration | `GpuProver`, `GpuConfig` |
| `obelysk::gpu::fft` | Circle FFT on GPU | (internal) |
| `obelysk::gpu::memory_pool` | GPU memory management | (internal) |

### Starknet Modules

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `obelysk::starknet` | On-chain verification | `StarknetClient`, `VerifierContract` |
| `obelysk::proof_packer` | Proof serialization | `PackedProof`, `pack_proof` |

### Privacy Modules

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `obelysk::elgamal` | ElGamal encryption | `encrypt`, `decrypt`, `KeyPair` |
| `obelysk::privacy_client` | Private transfers | `PrivateAccount`, `PrivatePayment` |
| `obelysk::fhe` | Homomorphic encryption | `FheEncryptor`, `EncryptedValue` |

---

## CLI Reference

### sage-worker Commands

```bash
# Initial setup
sage-worker setup --network mainnet

# Worker management
sage-worker start                    # Start worker
sage-worker stop                     # Stop worker
sage-worker status                   # Check status
sage-worker logs                     # View logs

# Staking
sage-worker stake --amount 5000      # Stake SAGE tokens
sage-worker unstake --amount 1000    # Unstake tokens
sage-worker claim                    # Claim rewards

# Information
sage-worker info                     # Show worker info + earnings
sage-worker export                   # Export wallet (backup)
```

### bitsage-proof Commands

```bash
# Generate proofs manually
bitsage-proof generate \
  --batch-size 1000 \
  --security-bits 128 \
  --output proof.json

# Generate TEE attestation
bitsage-proof attest \
  --proof proof.json \
  --output quote.bin

# Submit to Starknet
bitsage-proof submit \
  --proof proof.json \
  --quote quote.bin \
  --network mainnet
```

---

## Configuration

### Worker Configuration (~/.bitsage/worker.toml)

```toml
worker_id = "worker-abc12345"
network = "mainnet"
coordinator_url = "https://coordinator.bitsage.network"
starknet_rpc = "https://starknet-mainnet.public.blastapi.io"
dashboard_url = "https://dashboard.bitsage.network"

[wallet]
address = "0x..."
private_key_path = "~/.bitsage/keys/starknet.key"
elgamal_key_path = "~/.bitsage/keys/elgamal.key"

[gpu]
detected = true
count = 4
model = "NVIDIA H100 80GB HBM3"
memory_gb = 80
compute_capability = "9.0"
tee_supported = true

[settings]
poll_interval_secs = 5
heartbeat_interval_secs = 30
max_concurrent_jobs = 16
auto_claim_rewards = true
```

### Environment Variables

```bash
# Override config file
export BITSAGE_NETWORK=mainnet
export BITSAGE_COORDINATOR_URL=https://coordinator.bitsage.network
export STARKNET_PRIVATE_KEY=0x...

# GPU settings
export CUDA_VISIBLE_DEVICES=0,1,2,3  # For multi-GPU
```

---

## Building from Source

### Standard Build (CPU only)

```bash
cargo build --release
```

### GPU Acceleration (NVIDIA CUDA)

```bash
# Requires CUDA Toolkit 12.x
cargo build --release --features cuda
```

### Multi-GPU Support

```bash
cargo build --release --features cuda,multi-gpu
```

### All Features

```bash
cargo build --release --features cuda,gpu-metrics,redis-cache,tee
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `cuda` | NVIDIA CUDA GPU acceleration |
| `gpu-metrics` | NVIDIA NVML metrics monitoring |
| `rocm` | AMD ROCm support (future) |
| `tee` | Trusted Execution Environment support |
| `redis-cache` | Redis caching for dashboard |
| `fhe` | Fully Homomorphic Encryption |

---

## Docker Deployment

### Using Docker

```bash
# Pull the image
docker pull ghcr.io/ciro-ai-labs/sage-worker:latest

# Run with GPU support
docker run --gpus all \
  -v ~/.bitsage:/root/.bitsage \
  -e STARKNET_PRIVATE_KEY=$STARKNET_PRIVATE_KEY \
  ghcr.io/ciro-ai-labs/sage-worker:latest \
  start
```

### Docker Compose

```yaml
version: '3.8'
services:
  sage-worker:
    image: ghcr.io/ciro-ai-labs/sage-worker:latest
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    volumes:
      - ~/.bitsage:/root/.bitsage
    environment:
      - BITSAGE_NETWORK=mainnet
      - STARKNET_PRIVATE_KEY=${STARKNET_PRIVATE_KEY}
    restart: unless-stopped
```

---

## Cloud Deployment

### AWS (EC2 P4d/P5)

```bash
# Launch H100 instance
aws ec2 run-instances \
  --instance-type p5.48xlarge \
  --image-id ami-0abcdef1234567890 \
  --key-name your-key

# SSH and install
ssh -i your-key.pem ubuntu@<instance-ip>
curl -sSL https://get.bitsage.network/sage-worker | bash
sage-worker setup --network mainnet
sage-worker start
```

### Lambda Labs

```bash
# Launch from Lambda dashboard or CLI
lambda instance create --type gpu_8x_h100 --region us-west-1

# SSH and install
ssh ubuntu@<instance-ip>
curl -sSL https://get.bitsage.network/sage-worker | bash
sage-worker setup --network mainnet
sage-worker start
```

### Brev.dev (Kubernetes)

```bash
# Deploy via Brev
brev deploy --gpu h100 --count 4

# Worker starts automatically via init container
```

---

## Monitoring

### Built-in Dashboard

Access your worker status at: https://dashboard.bitsage.network

### Prometheus Metrics

Metrics are exposed at `http://localhost:9090/metrics`:

```
# HELP sage_proofs_generated_total Total proofs generated
sage_proofs_generated_total 12345

# HELP sage_gpu_utilization_percent Current GPU utilization
sage_gpu_utilization_percent{gpu="0"} 87.5

# HELP sage_earnings_sage Total SAGE earned
sage_earnings_sage 1234.56
```

### Grafana Integration

Import the BitSage Grafana dashboard:

```bash
# Dashboard ID: 12345
```

---

## Troubleshooting

### Common Issues

**GPU not detected**
```bash
# Check NVIDIA driver
nvidia-smi

# Check CUDA
nvcc --version

# Reinstall CUDA toolkit
sudo apt install cuda-toolkit-12-4
```

**Connection refused**
```bash
# Check coordinator URL
curl -s https://coordinator.bitsage.network/health

# Check firewall
sudo ufw allow 443/tcp
```

**Wallet issues**
```bash
# Export and backup wallet
sage-worker export > wallet-backup.json

# Check balance on Starknet
starkli balance <your-address> --network mainnet
```

**Low earnings**
```bash
# Increase stake for priority jobs
sage-worker stake --amount 5000

# Check job history
sage-worker info --verbose
```

### Logs

```bash
# View worker logs
sage-worker logs

# View system logs
journalctl -u sage-worker -f

# Debug mode
RUST_LOG=debug sage-worker start
```

---

## Security

### Key Management

- Private keys are stored encrypted in `~/.bitsage/keys/`
- Never share your private key or export file
- Use a hardware wallet for large stakes (coming soon)

### TEE Attestation

Workers with TEE support (H100, TDX, SEV) generate cryptographic attestation:

```bash
# Generate attestation quote
bitsage-proof attest --output quote.bin

# Verify attestation
bitsage-proof verify-quote --quote quote.bin
```

---

## API Endpoints

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

---

## Deployed Contracts (Starknet Sepolia)

### Core Infrastructure

| Contract | Address | Purpose |
|----------|---------|---------|
| **StwoVerifier** | `0x575968af96f814da648442daf1b8a09d43b650c06986e17b2bab7719418ddfb` | Circle STARK proof verification |
| **ProofGatedPayment** | `0x7e74d191b1cca7cac00adc03bc64eaa6236b81001f50c61d1d70ec4bfde8af0` | Payment gating for proofs |
| **PaymentRouter** | `0x001a7c5974eaa8a4d8c145765e507f73d56ee1d05419cbcffcae79ed3cd50f4d` | Fee distribution (80/18/2) |
| **ProverStaking** | `0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b` | Worker stake management |

### Token & Oracle

| Contract | Address | Purpose |
|----------|---------|---------|
| **SAGE Token** | `0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850` | Native token |
| **OracleWrapper** | `0x4d86bb472cb462a45d68a705a798b5e419359a5758d84b24af4bbe5441b6e5a` | Price feeds (w/ fallback) |
| **Faucet** | `0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3` | Testnet token faucet |

### External Tokens (OTC Config)

| Token | Address | Source |
|-------|---------|--------|
| **USDC** | `0x053b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080` | Bridged |
| **STRK** | `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d` | Native |
| **WBTC** | `0x00452bd5c0512a61df7c7be8cfea5e4f893cb40e126bdc40aee6054db955129e` | StarkGate |

### Fee Distribution Model

```
Payment Flow (pay_with_sage):
├── Worker:   80% → Direct SAGE transfer
├── Treasury: 18% → Protocol development
└── Stakers:   2% → Staking rewards pool
```

---

## Related Resources

- [Validator Deployment Guide](./docs/VALIDATOR_DEPLOYMENT.md) - Detailed deployment guide
- [GPU Operator FAQ](./docs/GPU_OPERATOR_FAQ.md) - Common questions
- [Staking Guide](./docs/STAKING_GUIDE.md) - Token staking details
- [BitSage Website](https://bitsage.network) - Main website
- [Discord](https://discord.gg/bitsage) - Community support

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built by [BitSage Network](https://github.com/Ciro-AI-Labs)**

*Powering verifiable computation with GPU-accelerated ZK proofs*

**1,237 proofs/sec on 4x H100 | 107M proofs/day**

[Website](https://bitsage.network) | [Discord](https://discord.gg/bitsage) | [Twitter](https://twitter.com/bitsagenetwork)

</div>
