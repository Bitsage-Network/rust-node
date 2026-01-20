# BitSage GPU Quick Start

Get your GPU earning SAGE tokens in under 5 minutes.

---

## Requirements

- **GPU**: NVIDIA RTX 3090+ (24GB+ VRAM)
- **CUDA**: 12.0+
- **OS**: Ubuntu 22.04 LTS
- **RAM**: 32GB+
- **Network**: 100 Mbps+

---

## Step 1: Install

### Option A: One-Line Install (Recommended)

```bash
# Interactive wizard - handles everything automatically
curl -sSL https://raw.githubusercontent.com/Ciro-AI-Labs/bitsage-network/main/rust-node/scripts/install.sh | bash
```

The wizard will:
- Detect your GPU and system specs
- Install all dependencies
- Build or download the worker
- Run the setup wizard
- Start earning immediately

### Option B: Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/Ciro-AI-Labs/bitsage-network
cd bitsage-network/rust-node
cargo build --release --features cuda

# Make available globally
sudo cp target/release/sage-worker /usr/local/bin/
```

---

## Step 2: Setup

```bash
sage-worker setup --network mainnet
```

This will:
1. Detect your GPU(s)
2. Generate a Starknet wallet
3. Generate encryption keys
4. Register with the network
5. Save config to `~/.bitsage/worker.toml`

**Save the wallet address!** You'll need it to receive SAGE tokens.

---

## Step 3: Start Earning

```bash
sage-worker start
```

That's it! Your GPU is now part of the BitSage Network.

---

## Check Status

```bash
# Worker status
sage-worker status

# View earnings
sage-worker info

# View logs
sage-worker logs
```

---

## Stake for Higher Earnings

Staking SAGE tokens unlocks higher-paying jobs:

| Tier | Stake | Benefit |
|------|-------|---------|
| Consumer | 1,000 SAGE | Standard jobs |
| Workstation | 2,500 SAGE | Priority queue |
| DataCenter | 5,000 SAGE | Enterprise jobs |
| Enterprise | 10,000 SAGE | Premium jobs |
| Frontier | 25,000 SAGE | Maximum priority |

```bash
# Stake 5,000 SAGE
sage-worker stake --amount 5000

# Claim rewards
sage-worker claim
```

---

## Run as Service (Production)

```bash
# Create systemd service
sudo tee /etc/systemd/system/sage-worker.service << 'EOF'
[Unit]
Description=BitSage GPU Worker
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sage-worker start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable sage-worker
sudo systemctl start sage-worker

# Check status
sudo systemctl status sage-worker
```

---

## Troubleshooting

### GPU not detected

```bash
# Check NVIDIA driver
nvidia-smi

# Install if missing
sudo apt install nvidia-driver-550
sudo reboot
```

### Connection issues

```bash
# Test coordinator
curl -s https://coordinator.bitsage.network/health

# Should return: {"status":"healthy"}
```

### View debug logs

```bash
RUST_LOG=debug sage-worker start
```

---

## Expected Earnings

| GPU | Proofs/sec | Monthly Est. |
|-----|------------|--------------|
| RTX 4090 | ~80 | $350-600 |
| A100 80GB | ~127 | $500-900 |
| H100 80GB | ~150 | $600-1,100 |
| 4x H100 | ~1,237 | $2,500-4,500 |

---

## Need Help?

- **Discord**: https://discord.gg/bitsage
- **Docs**: [Full Validator Guide](./VALIDATOR_DEPLOYMENT.md)
- **GitHub**: https://github.com/Ciro-AI-Labs/bitsage-network/issues

---

**Happy earning!**
