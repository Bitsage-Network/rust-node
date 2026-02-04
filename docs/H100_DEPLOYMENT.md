# BitSage H100 Production Deployment Guide

Real deployment steps tested on Shadeform H100 PCIe (via Brev).

## Hardware

| Spec | Value |
|------|-------|
| GPU | NVIDIA H100 PCIe, 80GB HBM3 |
| CPU | AMD EPYC 9554 64-Core (28 cores allocated) |
| RAM | 177GB |
| Storage | 97GB root + 700GB ephemeral |
| CUDA | 12.8 (Driver 570.195.03) |
| Compute | 9.0 (TEE supported) |
| OS | Ubuntu 22.04.5 LTS |

## Access

```bash
brev shell bitsage-worker1
# SSH: shadeform@62.169.159.30
```

## Step 1: Install Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Build dependencies
sudo apt-get update -qq
sudo apt-get install -y build-essential pkg-config libssl-dev libpq-dev \
  protobuf-compiler cmake clang
```

## Step 2: Deploy Source Code

From your local machine (the repo is private):

```bash
# Only need rust-node and vendored stwo prover
rsync -avz --exclude='target/' \
  /path/to/bitsage-network/rust-node/ \
  bitsage-worker1:/ephemeral/bitsage-network/rust-node/

rsync -avz --exclude='target/' --exclude='.git/' \
  /path/to/bitsage-network/libs/stwo/ \
  bitsage-worker1:/ephemeral/bitsage-network/libs/stwo/

scp /path/to/bitsage-network/docker-compose.prod.yml \
  bitsage-worker1:/ephemeral/bitsage-network/
```

## Step 3: Build Binaries

```bash
cd /ephemeral/bitsage-network/rust-node
export CUDA_PATH=/usr/local/cuda
export PATH=$CUDA_PATH/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_PATH/lib64:$LD_LIBRARY_PATH

# Full build with all features (~70s on H100 instance)
cargo build --release --features cuda,fhe,gpu-metrics,redis-cache
```

Produces 3 binaries:
- `target/release/sage-coordinator` (37MB) - Job orchestration, REST API, WebSocket
- `target/release/sage-worker` (30MB) - GPU worker, job execution, heartbeats
- `target/release/bitsage-proof` (23MB) - Standalone proof CLI

## Step 4: Start Databases

```bash
# PostgreSQL 15
docker run -d --name bitsage-postgres \
  -e POSTGRES_USER=bitsage \
  -e POSTGRES_PASSWORD=<YOUR_DB_PASSWORD> \
  -e POSTGRES_DB=sage \
  -p 5432:5432 \
  -v /ephemeral/pgdata:/var/lib/postgresql/data \
  postgres:15

# Redis 7
docker run -d --name bitsage-redis \
  -p 6379:6379 \
  redis:7-alpine

# Verify
docker ps
```

## Step 5: Configure Environment

```bash
cat > /ephemeral/bitsage-network/.env << 'EOF'
DATABASE_URL=postgresql://bitsage:<YOUR_DB_PASSWORD>@localhost:5432/sage
STARKNET_NETWORK=sepolia
STARKNET_RPC_URL=https://rpc.starknet-testnet.lava.build
DEPLOYER_ADDRESS=<YOUR_STARKNET_ADDRESS>
DEPLOYER_PRIVATE_KEY=<YOUR_PRIVATE_KEY>
CUDA_PATH=/usr/local/cuda
GPU_ENABLED=true
HOST=0.0.0.0
PORT=8080
REDIS_URL=redis://localhost:6379
RUST_LOG=info,bitsage=debug
RUST_BACKTRACE=1
EOF
```

## Step 6: Start Coordinator

```bash
cd /ephemeral/bitsage-network

nohup ./rust-node/target/release/sage-coordinator \
  --port 8080 \
  --database-url "postgresql://bitsage:<YOUR_DB_PASSWORD>@localhost:5432/sage" \
  --network sepolia \
  --rpc-url "https://rpc.starknet-testnet.lava.build" \
  > /ephemeral/coordinator.log 2>&1 &

# Verify
curl http://localhost:8080/api/health
# {"status":"healthy","timestamp":...}
```

## Step 7: Configure Worker

```bash
mkdir -p /ephemeral/.bitsage

cat > /ephemeral/.bitsage/worker.toml << 'TOML'
worker_id = "h100-worker-prod-01"
network = "sepolia"
coordinator_url = "http://localhost:8080"
starknet_rpc = "https://rpc.starknet-testnet.lava.build"
dashboard_url = "https://dashboard-sepolia.bitsage.network"

[wallet]
address = "<YOUR_STARKNET_ADDRESS>"
private_key_path = "/ephemeral/.bitsage/wallet.key"
elgamal_key_path = "/ephemeral/.bitsage/elgamal.key"

[gpu]
detected = true
count = 1
model = "NVIDIA H100 PCIe"
memory_gb = 79
compute_capability = "9.0"
tee_supported = true
cuda_version = "12.8"

[settings]
poll_interval_secs = 5
heartbeat_interval_secs = 30
max_concurrent_jobs = 4
auto_claim_rewards = true

[session_key]
registered = false
allowed_contracts = []
TOML

# Write your actual Starknet private key
echo "<YOUR_PRIVATE_KEY>" > /ephemeral/.bitsage/wallet.key
chmod 600 /ephemeral/.bitsage/wallet.key
```

## Step 8: Start Worker

```bash
cd /ephemeral/bitsage-network
export CUDA_PATH=/usr/local/cuda
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH

nohup ./rust-node/target/release/sage-worker \
  -c /ephemeral/.bitsage start --foreground \
  > /ephemeral/worker.log 2>&1 &

# Verify registration
tail -5 /ephemeral/coordinator.log
# Should show: "Worker h100-worker-prod-01 registered"
```

## Step 9: Test STWO GPU Proof Generation

```bash
cd /ephemeral/bitsage-network/rust-node

# Small batch (fast verification)
./target/release/bitsage-proof generate --batch-size 100

# Large batch (GPU FFT kicks in at >16K elements)
./target/release/bitsage-proof generate --batch-size 10000

# Full demo (proof + TEE attestation + on-chain submission)
./target/release/bitsage-proof demo
```

### Expected Output

```
GPU acceleration: CUDA backend initialized
  device=CUDA Device 0 (H100/A100)
  memory_total_gb=85.9
  compute_capability=(9, 0)

  Batch size:      10000 transactions
  FFT size:        2^15 = 32768
  FFT calls:       1 (GPU: 1, CPU: 0)
  Proof size:      4140 bytes
  Total time:      ~150ms
```

## Step 10: Deploy LLM Runtime (vLLM)

```bash
# Install vLLM for GPU-accelerated LLM serving
pip3 install vllm

# Start Qwen 2.5 (7B fits in ~16GB, leaves room for proofs)
python3 -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-7B-Instruct \
  --host 0.0.0.0 \
  --port 8000 \
  --gpu-memory-utilization 0.5 \
  --max-model-len 8192 \
  --dtype auto \
  > /ephemeral/vllm.log 2>&1 &

# Verify
curl http://localhost:8000/v1/models

# Test inference
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen2.5-7B-Instruct",
    "messages": [{"role": "user", "content": "What is BitSage?"}],
    "max_tokens": 100
  }'
```

## Monitoring

```bash
# GPU utilization
nvidia-smi -l 1

# Coordinator logs
tail -f /ephemeral/coordinator.log

# Worker logs
tail -f /ephemeral/worker.log

# vLLM logs
tail -f /ephemeral/vllm.log

# System info
./rust-node/target/release/sage-worker info
```

## Ports

| Port | Service |
|------|---------|
| 8080 | Coordinator REST API + WebSocket |
| 8000 | vLLM OpenAI-compatible API |
| 5432 | PostgreSQL |
| 6379 | Redis |

## Firewall

The instance runs UFW. For external access:

```bash
sudo ufw allow 8080/tcp  # Coordinator API
sudo ufw allow 8000/tcp  # LLM API (only if needed externally)
```

## Known Issues

1. **Privacy client error**: "Invalid private key: invalid character" — Occurs when wallet.key contains a placeholder instead of a real Starknet private key. Fix: write your actual key.
2. **GPU FFT threshold**: FFT operations only use GPU when input size > 16K elements (batch size > ~5500). Smaller batches use CPU FFT which is fast enough.
3. **`--cpu-only` flag**: Currently not fully respected in proof CLI. The GPU backend initializes regardless.
