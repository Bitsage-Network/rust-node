# BitSage Network - GPU Worker Node

High-performance Rust node for the BitSage Network, featuring **Obelysk Protocol** integration with GPU-accelerated zero-knowledge proofs.

---

## One-Click Installation

**Run a single command to install and start earning SAGE tokens:**

```bash
curl -sSL https://raw.githubusercontent.com/Ciro-AI-Labs/bitsage-network/main/rust-node/scripts/install.sh | bash
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
git clone https://github.com/Ciro-AI-Labs/bitsage-network
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

### Single GPU (H100 80GB)

| Proof Size | GPU Time | CPU Time | **Speedup** |
|------------|----------|----------|-------------|
| 2^18 (8MB) | 2.42ms | 132ms | **54.6x** |
| 2^20 (32MB) | 5.71ms | 560ms | **98.2x** |
| 2^22 (64MB) | 17.73ms | 2.22s | **125.2x** |
| 2^23 (64MB) | 25.83ms | 4.5s | **174.2x** |

### Multi-GPU (4x H100)

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
