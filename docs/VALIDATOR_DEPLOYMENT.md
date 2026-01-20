# BitSage GPU Validator Deployment Guide

Complete guide for deploying a GPU validator (worker) on the BitSage Network.

---

## Quick Start (One Command)

**The fastest way to get started:**

```bash
curl -sSL https://raw.githubusercontent.com/Bitsage-Network/rust-node/main/rust-node/scripts/install.sh | bash
```

This wizard handles everything automatically. For manual installation or more control, continue reading.

---

## Table of Contents

1. [Overview](#overview)
2. [Hardware Requirements](#hardware-requirements)
3. [Pre-Installation](#pre-installation)
4. [Installation Methods](#installation-methods)
5. [Configuration](#configuration)
6. [Staking](#staking)
7. [Running the Worker](#running-the-worker)
8. [Monitoring](#monitoring)
9. [Security Best Practices](#security-best-practices)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)

---

## Overview

### What is a BitSage Validator?

A BitSage validator (also called "GPU worker" or "prover") is a machine that:

1. **Receives compute jobs** from the BitSage coordinator
2. **Generates STWO zero-knowledge proofs** using GPU acceleration
3. **Submits proofs on-chain** to Starknet for verification
4. **Earns SAGE tokens** for completed jobs

### Network Architecture

```
                    ┌─────────────────────────────────────┐
                    │         BitSage Network             │
                    └─────────────────────────────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
            ▼                        ▼                        ▼
    ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
    │  GPU Worker 1 │       │  GPU Worker 2 │       │  GPU Worker N │
    │  (Your Node)  │       │               │       │               │
    │               │       │               │       │               │
    │  ┌─────────┐  │       │  ┌─────────┐  │       │  ┌─────────┐  │
    │  │ H100 x4 │  │       │  │ A100 x8 │  │       │  │ RTX 4090│  │
    │  └─────────┘  │       │  └─────────┘  │       │  └─────────┘  │
    └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
            │                       │                       │
            └───────────────────────┼───────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      BitSage Coordinator      │
                    │   (Managed by BitSage Team)   │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │         Starknet              │
                    │  (ProverStaking, JobManager)  │
                    └───────────────────────────────┘
```

### What You Deploy vs. What BitSage Manages

| Component | Who Manages | Notes |
|-----------|-------------|-------|
| **GPU Worker (sage-worker)** | You | Your machine with GPUs |
| Coordinator | BitSage | Job distribution |
| PostgreSQL Database | BitSage | Job queue storage |
| Dashboard API | BitSage | Monitoring interface |
| Smart Contracts | BitSage | On-chain logic |
| Starknet RPC | Public/BitSage | Blockchain access |

**You only need to deploy the sage-worker binary.**

---

## Hardware Requirements

### Minimum Requirements

| Component | Minimum | Notes |
|-----------|---------|-------|
| **GPU** | NVIDIA RTX 3090 (24GB) | Pascal or newer |
| **CUDA** | 12.0+ | Required for GPU acceleration |
| **CPU** | 8 cores | For job management |
| **RAM** | 32 GB | For proof buffers |
| **Storage** | 100 GB SSD | For temporary proof data |
| **Network** | 100 Mbps | Stable connection required |
| **OS** | Ubuntu 22.04 LTS | Debian-based preferred |

### Recommended Configurations

#### Tier 1: Consumer (Hobby)
- **GPU**: RTX 3090 or RTX 4090
- **Expected Earnings**: $200-600/month
- **Best For**: Testing, low-volume workloads

#### Tier 2: Workstation (Semi-Pro)
- **GPU**: A100 40GB or A100 80GB
- **Expected Earnings**: $500-900/month
- **Best For**: Dedicated operators

#### Tier 3: Data Center (Professional)
- **GPU**: 4x H100 80GB
- **Expected Earnings**: $2,500-4,500/month
- **Best For**: Professional operators, maximum throughput

#### Tier 4: Enterprise (Fleet)
- **GPU**: 8x H100 or B200
- **Expected Earnings**: $5,000-10,000+/month
- **Best For**: Large-scale operations

### GPU Performance Comparison

| GPU | VRAM | Proofs/sec | Speedup vs CPU | Monthly Est. |
|-----|------|------------|----------------|--------------|
| RTX 3090 | 24 GB | ~50 | 15-40x | $200-400 |
| RTX 4090 | 24 GB | ~80 | 25-60x | $350-600 |
| A100 40GB | 40 GB | ~100 | 35-100x | $400-700 |
| A100 80GB | 80 GB | ~127 | 45-130x | $500-900 |
| **H100 80GB** | **80 GB** | **~150** | **55-174x** | **$600-1,100** |
| **4x H100** | **320 GB** | **~1,237** | **55-174x** | **$2,500-4,500** |

---

## Pre-Installation

### 1. Install NVIDIA Drivers

```bash
# Ubuntu 22.04/24.04
sudo apt update
sudo apt install -y nvidia-driver-550

# Reboot
sudo reboot

# Verify
nvidia-smi
```

Expected output:
```
+-----------------------------------------------------------------------------+
| NVIDIA-SMI 550.54.14    Driver Version: 550.54.14    CUDA Version: 12.4     |
|-------------------------------+----------------------+----------------------+
| GPU  Name        Persistence-M| Bus-Id        Disp.A | Volatile Uncorr. ECC |
| Fan  Temp  Perf  Pwr:Usage/Cap|         Memory-Usage | GPU-Util  Compute M. |
|===============================+======================+======================|
|   0  NVIDIA H100 80GB    On   | 00000000:00:04.0 Off |                    0 |
| N/A   32C    P0    70W / 700W |      0MiB / 81559MiB |      0%      Default |
+-------------------------------+----------------------+----------------------+
```

### 2. Install CUDA Toolkit

```bash
# Download CUDA 12.4
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt update
sudo apt install -y cuda-toolkit-12-4

# Add to PATH
echo 'export PATH=/usr/local/cuda-12.4/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda-12.4/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# Verify
nvcc --version
```

### 3. Install Rust (if building from source)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify
rustc --version
```

---

## Installation Methods

### Method 1: One-Line Install (Recommended)

```bash
curl -sSL https://get.bitsage.network/sage-worker | bash
```

This script:
1. Downloads the latest `sage-worker` binary
2. Installs to `/usr/local/bin/`
3. Creates systemd service
4. Runs initial setup

### Method 2: Build from Source

```bash
# Clone repository
git clone https://github.com/Bitsage-Network/rust-node
cd bitsage-network/rust-node

# Build with GPU support
cargo build --release --features cuda

# Install binary
sudo cp target/release/sage-worker /usr/local/bin/
```

### Method 3: Docker

```bash
# Pull image
docker pull ghcr.io/ciro-ai-labs/sage-worker:latest

# Run setup
docker run -it --gpus all \
  -v ~/.bitsage:/root/.bitsage \
  ghcr.io/ciro-ai-labs/sage-worker:latest \
  setup --network mainnet
```

---

## Configuration

### Initial Setup

Run the setup wizard:

```bash
sage-worker setup --network mainnet
```

The wizard will:

1. **Detect GPUs**
   ```
   Detecting GPUs...
     GPU 0: NVIDIA H100 80GB HBM3
       Memory: 80 GB
       Compute Capability: 9.0
       TEE Support: Yes (H100 CC)
   ```

2. **Generate Starknet Wallet**
   ```
   Generating Starknet wallet...
     Address: 0x04a7b8c...
     Saved to: ~/.bitsage/keys/starknet.key
   ```

3. **Generate ElGamal Keys** (for encrypted payments)
   ```
   Generating ElGamal keypair...
     Public Key: 0x05c3d2e...
     Saved to: ~/.bitsage/keys/elgamal.key
   ```

4. **Register with Coordinator**
   ```
   Registering with coordinator...
     Worker ID: worker-a1b2c3d4
     Status: REGISTERED
   ```

5. **Save Configuration**
   ```
   Configuration saved to: ~/.bitsage/worker.toml
   ```

### Configuration File

Location: `~/.bitsage/worker.toml`

```toml
# Worker identity
worker_id = "worker-a1b2c3d4"
network = "mainnet"

# Network endpoints
coordinator_url = "https://coordinator.bitsage.network"
starknet_rpc = "https://starknet-mainnet.public.blastapi.io"
dashboard_url = "https://dashboard.bitsage.network"

[wallet]
address = "0x04a7b8c..."
private_key_path = "/home/user/.bitsage/keys/starknet.key"
elgamal_key_path = "/home/user/.bitsage/keys/elgamal.key"

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

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `poll_interval_secs` | 5 | How often to check for new jobs |
| `heartbeat_interval_secs` | 30 | How often to send heartbeat |
| `max_concurrent_jobs` | 4 | Max parallel jobs (based on GPU memory) |
| `auto_claim_rewards` | true | Auto-claim rewards to wallet |

### Environment Variables

Override config file settings:

```bash
export BITSAGE_NETWORK=mainnet
export BITSAGE_COORDINATOR_URL=https://coordinator.bitsage.network
export STARKNET_PRIVATE_KEY=0x...  # Use with caution!
export CUDA_VISIBLE_DEVICES=0,1,2,3
```

---

## Staking

### Why Stake?

Staking SAGE tokens:
- **Unlocks higher-paying jobs**
- **Increases job priority**
- **Demonstrates commitment** to the network

### Staking Tiers

| Tier | Stake | Job Priority | Max Jobs | Benefits |
|------|-------|--------------|----------|----------|
| **Unstaked** | 0 | Lowest | 2 | Basic access |
| **Consumer** | 1,000 SAGE | Standard | 4 | Standard jobs |
| **Workstation** | 2,500 SAGE | Priority | 8 | Priority queue |
| **DataCenter** | 5,000 SAGE | High | 16 | Enterprise jobs |
| **Enterprise** | 10,000 SAGE | Premium | 32 | Premium jobs |
| **Frontier** | 25,000 SAGE | Maximum | Unlimited | All jobs + bonuses |

### How to Stake

**Option 1: CLI**
```bash
# Stake 5,000 SAGE tokens
sage-worker stake --amount 5000

# Check stake status
sage-worker info
```

**Option 2: Dashboard**
1. Go to https://dashboard.bitsage.network
2. Connect your wallet
3. Navigate to "Staking"
4. Enter amount and confirm

**Option 3: Direct Contract**
```bash
# Using starkli
starkli invoke \
  0x<PROVER_STAKING_CONTRACT> \
  stake \
  5000000000000000000000 \
  --account ~/.starknet_accounts/account.json
```

### Unstaking

```bash
# Request unstake (7-day unbonding period)
sage-worker unstake --amount 1000

# Check unbonding status
sage-worker info
```

---

## Running the Worker

### Start Worker

```bash
# Foreground (for testing)
sage-worker start

# Background (production)
sage-worker start --daemon
```

### Systemd Service (Recommended for Production)

Create `/etc/systemd/system/sage-worker.service`:

```ini
[Unit]
Description=BitSage GPU Worker
After=network.target

[Service]
Type=simple
User=bitsage
ExecStart=/usr/local/bin/sage-worker start
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sage-worker
sudo systemctl start sage-worker

# Check status
sudo systemctl status sage-worker

# View logs
sudo journalctl -u sage-worker -f
```

### Worker Commands

```bash
sage-worker start              # Start worker
sage-worker stop               # Stop worker
sage-worker status             # Check status
sage-worker info               # Show info + earnings
sage-worker logs               # View logs
sage-worker claim              # Claim pending rewards
sage-worker export             # Export wallet backup
```

---

## Monitoring

### Dashboard

Access the web dashboard at: **https://dashboard.bitsage.network**

Features:
- Real-time job status
- Earnings history
- GPU utilization graphs
- Network statistics

### CLI Monitoring

```bash
# Worker status
sage-worker status

# Example output:
# Worker Status: ACTIVE
# Jobs Completed: 1,234
# Jobs In Progress: 4
# Total Earnings: 5,678.90 SAGE
# Pending Rewards: 123.45 SAGE
# GPU Utilization: 87%
# Uptime: 14d 6h 32m
```

### Prometheus Metrics

Metrics endpoint: `http://localhost:9090/metrics`

```prometheus
# HELP sage_jobs_completed_total Total jobs completed
sage_jobs_completed_total 1234

# HELP sage_proofs_generated_total Total proofs generated
sage_proofs_generated_total 56789

# HELP sage_gpu_utilization GPU utilization percentage
sage_gpu_utilization{gpu="0"} 87.5
sage_gpu_utilization{gpu="1"} 92.3

# HELP sage_earnings_total Total SAGE earned
sage_earnings_total 5678.90
```

### Grafana Dashboard

Import the BitSage dashboard:
1. Open Grafana
2. Import dashboard ID: `12345`
3. Select Prometheus data source

### Alerts

Set up alerts for:
- Worker offline
- GPU utilization < 50%
- Failed jobs > 5%
- Low disk space

---

## Security Best Practices

### 1. Key Management

```bash
# Backup your keys
sage-worker export > wallet-backup-$(date +%Y%m%d).json

# Store backup securely (encrypted, offline)
gpg -c wallet-backup-*.json

# Never share these files:
# - ~/.bitsage/keys/starknet.key
# - ~/.bitsage/keys/elgamal.key
```

### 2. Firewall Configuration

```bash
# Only allow outbound HTTPS
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
```

### 3. System Hardening

```bash
# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Use SSH keys only
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart sshd
```

### 4. Dedicated User

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash bitsage
sudo usermod -aG docker bitsage

# Run worker as dedicated user
sudo -u bitsage sage-worker start
```

### 5. Regular Updates

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Update sage-worker
curl -sSL https://get.bitsage.network/sage-worker | bash
```

---

## Troubleshooting

### GPU Not Detected

```bash
# Check NVIDIA driver
nvidia-smi

# If not found, reinstall driver
sudo apt install -y nvidia-driver-550
sudo reboot

# Check CUDA
nvcc --version

# If not found, install CUDA toolkit
sudo apt install -y cuda-toolkit-12-4
```

### Connection Refused

```bash
# Test coordinator
curl -s https://coordinator.bitsage.network/health

# If fails, check:
# 1. Internet connection
ping google.com

# 2. DNS resolution
nslookup coordinator.bitsage.network

# 3. Firewall
sudo ufw status
```

### Wallet Issues

```bash
# Check wallet address
sage-worker info

# Check balance
starkli balance <your-address> --network mainnet

# Re-generate keys (WARNING: creates new wallet)
rm -rf ~/.bitsage/keys
sage-worker setup --network mainnet
```

### Low Earnings

1. **Check stake tier**
   ```bash
   sage-worker info
   # Ensure you're staked at appropriate tier
   ```

2. **Check GPU utilization**
   ```bash
   nvidia-smi
   # Should be >80% when jobs are running
   ```

3. **Check job completion rate**
   ```bash
   sage-worker status
   # Failed jobs reduce priority
   ```

4. **Upgrade hardware**
   - More VRAM = larger jobs
   - Faster GPU = more jobs/hour

### Worker Crashes

```bash
# Check logs
sudo journalctl -u sage-worker -n 100

# Common causes:
# - Out of memory: Reduce max_concurrent_jobs
# - GPU timeout: Update NVIDIA drivers
# - Network issues: Check connection

# Restart worker
sudo systemctl restart sage-worker
```

### Debug Mode

```bash
# Run with verbose logging
RUST_LOG=debug sage-worker start

# Or set in systemd service:
# Environment=RUST_LOG=debug
```

---

## FAQ

### Q: How much can I earn?

Earnings depend on:
- GPU model (faster = more jobs)
- Stake tier (higher = priority jobs)
- Network demand (varies)

Estimates:
- RTX 4090: $350-600/month
- A100 80GB: $500-900/month
- H100 80GB: $600-1,100/month
- 4x H100: $2,500-4,500/month

### Q: Do I need to run 24/7?

Yes, for maximum earnings. Intermittent availability reduces job priority and total earnings.

### Q: Can I run multiple workers?

Yes, each machine needs its own:
- `worker_id`
- Wallet (or shared with caution)
- Stake (per worker or shared pool)

### Q: What if my GPU is already mining?

BitSage jobs are intermittent. You can:
1. Run both (reduced performance)
2. Switch fully to BitSage (recommended)

### Q: Is my data safe?

Yes:
- All compute runs in TEE (H100/TDX/SEV)
- Data is encrypted end-to-end
- Results are verified on-chain

### Q: How do I get SAGE tokens to stake?

1. **Buy on DEX**: Uniswap, JediSwap
2. **Earn first**: Start unstaked, earn, then stake
3. **Faucet**: Testnet only

### Q: What's the unbonding period?

7 days from unstake request. Tokens are locked during this period.

### Q: Can I run on cloud GPUs?

Yes! Supported providers:
- AWS (P4d, P5 instances)
- Lambda Labs
- CoreWeave
- Brev.dev
- RunPod

---

## Support

- **Discord**: https://discord.gg/bitsage
- **Twitter**: [@bitsagenetwork](https://twitter.com/bitsagenetwork)
- **Email**: support@bitsage.network
- **GitHub Issues**: https://github.com/Bitsage-Network/rust-node/issues

---

## Changelog

### v1.0.0 (2025-01)
- Initial release
- One-click setup wizard
- CUDA GPU support
- Staking integration
- Dashboard integration

---

<div align="center">

**Built by [BitSage Network](https://bitsage.network)**

*Start earning with your GPU today*

</div>
