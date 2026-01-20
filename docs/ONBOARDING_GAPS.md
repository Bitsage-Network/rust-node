# BitSage Onboarding Analysis: Current vs. Ideal

## Executive Summary

Current state: Requires custom scripts, manual configuration, deep technical knowledge
Target state: One command deployment like Cocoon/Gonka

---

## User Journeys Compared

### Journey 1: GPU Worker Operator

| Step | Ideal (Cocoon-style) | Current BitSage | Gap |
|------|---------------------|-----------------|-----|
| 1. Discovery | Visit bitsage.network, see "Start Earning" | No clear landing page | Need onboarding page |
| 2. Install | `npm i -g @bitsage/cli` | Clone repo, build from source | Need published CLI |
| 3. Setup | `bitsage init worker` | Manual config editing | Need init wizard |
| 4. Get Tokens | `bitsage faucet claim` | Manual contract interaction | Need CLI faucet |
| 5. Stake | `bitsage stake 1000` | Use webapp or scripts | Need CLI staking |
| 6. Register | `bitsage worker register` | Manual API calls | Need auto-registration |
| 7. Start | `bitsage worker start` | `cargo run --bin worker` | Need pre-built binary |
| 8. Monitor | `bitsage status` + Dashboard | Check logs manually | Need health commands |
| 9. Earnings | `bitsage earnings` | Check blockchain manually | Need earnings view |

### Journey 2: Job Submitter (Developer)

| Step | Ideal | Current | Gap |
|------|-------|---------|-----|
| 1. Install SDK | `npm i @bitsage/sdk` | Works ✅ | Published? |
| 2. Get API Key | Dashboard → API Keys | ? | Need API key system |
| 3. Submit Job | SDK call | Works ✅ | |
| 4. Get Result | SDK call | Works ✅ | |
| 5. Verify Proof | SDK call | Works ✅ | |

### Journey 3: Staker (Token Holder)

| Step | Ideal | Current | Gap |
|------|-------|---------|-----|
| 1. Get SAGE | Faucet or DEX | Faucet contract exists | Need easy claim |
| 2. Stake | `bitsage stake` or webapp | Webapp exists? | Verify webapp works |
| 3. Delegate | Choose validator | ? | Need delegation UI |
| 4. Claim Rewards | `bitsage claim` | ? | Need rewards claim |

---

## Component Gap Analysis

### 1. CLI Tool (@bitsage/cli) - MISSING ❌

**Required Commands:**
```bash
# Installation
npm install -g @bitsage/cli
# or
cargo install bitsage-cli

# Initialization
bitsage init                    # Interactive setup wizard
bitsage init worker             # Worker-specific setup
bitsage init validator          # Validator setup

# Wallet Management
bitsage wallet create           # Create new wallet
bitsage wallet import           # Import existing
bitsage wallet balance          # Check balance

# Faucet (Testnet)
bitsage faucet claim            # Claim testnet tokens
bitsage faucet status           # Check cooldown

# Staking
bitsage stake <amount>          # Stake SAGE tokens
bitsage unstake <amount>        # Begin unstaking
bitsage stake status            # View stake info
bitsage delegate <validator>    # Delegate to validator

# Worker Operations
bitsage worker register         # Register as worker
bitsage worker start            # Start worker node
bitsage worker stop             # Stop worker
bitsage worker status           # Check status
bitsage worker logs             # View logs

# Monitoring
bitsage status                  # Overall status
bitsage earnings                # View earnings
bitsage jobs                    # List recent jobs
bitsage health                  # Health check

# Network
bitsage network status          # Network overview
bitsage network workers         # List workers
bitsage network validators      # List validators
```

### 2. Docker Images - PARTIAL ⚠️

**Current:**
- Dockerfile.coordinator ✅
- Dockerfile.worker ✅
- docker-compose.yml (dev only) ✅

**Missing:**
- Published to Docker Hub ❌
- GPU-enabled worker image ❌
- One-command docker run ❌

**Target:**
```bash
# Start worker with GPU
docker run -d --gpus all \
  -e WALLET_ADDRESS=0x... \
  -e COORDINATOR_URL=https://coordinator.bitsage.network \
  bitsage/worker:latest

# Start validator
docker run -d \
  -e STARKNET_PRIVATE_KEY=0x... \
  bitsage/validator:latest
```

### 3. Pre-built Binaries - MISSING ❌

**Need:**
- GitHub Releases with binaries for:
  - Linux x86_64 (primary)
  - Linux ARM64
  - macOS x86_64
  - macOS ARM64 (Apple Silicon)
- Auto-update mechanism

### 4. Coordinator Discovery - MISSING ❌

**Current:** User must know coordinator URL
**Target:** Auto-discovery via:
- DNS seed nodes
- Hardcoded bootstrap nodes
- Network DHT lookup

### 5. Health/Stats Endpoints - PARTIAL ⚠️

**Current:** Various endpoints exist but not standardized
**Target (Cocoon-style):**
```
GET /health          # Simple alive check
GET /stats           # Human-readable stats
GET /metrics         # Prometheus metrics
GET /status          # JSON status
```

### 6. Dashboard Integration - UNKNOWN ❓

**Questions:**
- Does worker auto-register with dashboard?
- Can operators see their worker in dashboard?
- Real-time status updates?

### 7. Faucet Flow - PARTIAL ⚠️

**Current:** Contract deployed, no easy claim
**Target:**
```bash
bitsage faucet claim
# → Claims 100 SAGE to your wallet
# → Shows transaction hash
# → Waits for confirmation
```

---

## Priority Roadmap

### Phase 1: Basic CLI (1 week)
1. Create `@bitsage/cli` npm package
2. Implement core commands: init, wallet, status
3. Publish to npm

### Phase 2: Worker Onboarding (1 week)
1. `bitsage worker start` command
2. Auto-registration with coordinator
3. Pre-built binaries in GitHub releases

### Phase 3: Staking & Faucet (1 week)
1. `bitsage faucet claim` command
2. `bitsage stake` command
3. Dashboard integration

### Phase 4: Production Ready (1 week)
1. Docker Hub images
2. Coordinator auto-discovery
3. Health monitoring
4. Documentation site

---

## Technical Requirements

### CLI Architecture
```
@bitsage/cli/
├── src/
│   ├── commands/
│   │   ├── init.ts
│   │   ├── wallet.ts
│   │   ├── worker.ts
│   │   ├── stake.ts
│   │   ├── faucet.ts
│   │   └── status.ts
│   ├── lib/
│   │   ├── starknet.ts      # Starknet interactions
│   │   ├── coordinator.ts   # Coordinator API
│   │   └── config.ts        # Config management
│   └── index.ts
├── package.json
└── README.md
```

### Config File (~/.bitsage/config.toml)
```toml
[network]
name = "mainnet"  # or "sepolia"
coordinator_url = "https://coordinator.bitsage.network"
starknet_rpc = "https://starknet-mainnet.public.blastapi.io"

[wallet]
address = "0x..."
keystore_path = "~/.bitsage/keystore.json"

[worker]
id = "worker-abc123"
gpu_enabled = true
```

---

## Questions to Answer

1. Is the TypeScript SDK published to npm?
2. Is there a public coordinator running?
3. What's the faucet contract address on Sepolia?
4. Does the dashboard exist and work?
5. Are there any bootstrap/seed nodes?

---

## Learning from Cocoon & Gonka

### Cocoon (Telegram)
- `cocoon-launch` single entry point
- Auto-builds on first run
- Health client for monitoring
- Reproducible builds

### Gonka
- Docker-first deployment
- `launch_chain.sh` script
- config.env for configuration
- Seed nodes in Docker image

### BitSage Target
- `bitsage` CLI as primary interface
- Docker for deployment
- Auto-discovery of network
- Dashboard for monitoring
