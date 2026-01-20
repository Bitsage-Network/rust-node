#!/bin/bash
# =============================================================================
# BitSage GPU Worker - One-Click Deployment for NVIDIA Brev
# =============================================================================
# Usage: curl -sSL https://raw.githubusercontent.com/bitsage-network/rust-node/main/scripts/brev_deploy.sh | bash
# Or: ./brev_deploy.sh
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  🚀 BitSage GPU Worker - One-Click Deployment"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# -----------------------------------------------------------------------------
# Step 1: Detect GPU
# -----------------------------------------------------------------------------
log_info "Detecting GPU..."

if ! command -v nvidia-smi &> /dev/null; then
    log_error "nvidia-smi not found. Is this a GPU instance?"
    exit 1
fi

GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n1 | xargs)
GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -n1 | xargs)
GPU_COUNT=$(nvidia-smi -L | wc -l)
GPU_DRIVER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1 | xargs)

log_success "Detected: $GPU_NAME ($GPU_MEMORY MiB) x $GPU_COUNT"
log_info "Driver version: $GPU_DRIVER"

# Determine GPU tier for staking requirements
GPU_TIER="Consumer"
MIN_STAKE="1000"
case "$GPU_NAME" in
    *"B300"*|*"B200"*|*"H200"*|*"H100"*)
        GPU_TIER="Enterprise"
        MIN_STAKE="10000"
        ;;
    *"A100"*)
        GPU_TIER="DataCenter"
        MIN_STAKE="5000"
        ;;
    *"A6000"*|*"L40"*|*"L4"*)
        GPU_TIER="Workstation"
        MIN_STAKE="2500"
        ;;
    *"4090"*|*"4080"*|*"3090"*|*"3080"*)
        GPU_TIER="Consumer"
        MIN_STAKE="1000"
        ;;
esac

log_info "GPU Tier: $GPU_TIER (min stake: $MIN_STAKE SAGE)"

# -----------------------------------------------------------------------------
# Step 2: Install Dependencies
# -----------------------------------------------------------------------------
log_info "Installing dependencies..."

# Update package list
sudo apt-get update -qq

# Install build essentials
sudo apt-get install -y -qq build-essential pkg-config libssl-dev git curl

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    log_success "Rust installed"
else
    log_success "Rust already installed: $(rustc --version)"
fi

# Ensure cargo is in path
source "$HOME/.cargo/env" 2>/dev/null || true

# -----------------------------------------------------------------------------
# Step 3: Clone/Update Repository
# -----------------------------------------------------------------------------
REPO_DIR="$HOME/bitsage-network"

if [ -d "$REPO_DIR/rust-node" ]; then
    log_info "Updating existing repository..."
    cd "$REPO_DIR/rust-node"
    git fetch origin
    git reset --hard origin/main
    log_success "Repository updated"
else
    log_info "Cloning BitSage Network..."
    mkdir -p "$REPO_DIR"
    cd "$REPO_DIR"
    # Try SSH first, fall back to HTTPS
    git clone git@github.com:bitsage-network/bitsage-network.git . 2>/dev/null || \
    git clone https://github.com/bitsage-network/bitsage-network.git .
    log_success "Repository cloned"
fi

cd "$REPO_DIR/rust-node"

# -----------------------------------------------------------------------------
# Step 4: Build Worker Binary
# -----------------------------------------------------------------------------
log_info "Building BitSage worker (this may take 5-15 minutes)..."
BUILD_START=$(date +%s)

# Build with release optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release --bin worker 2>&1 | tail -20

BUILD_END=$(date +%s)
BUILD_TIME=$((BUILD_END - BUILD_START))

if [ -f "target/release/worker" ]; then
    log_success "Build complete in ${BUILD_TIME}s"
else
    log_error "Build failed! Check the output above."
    exit 1
fi

# -----------------------------------------------------------------------------
# Step 5: Generate Configuration
# -----------------------------------------------------------------------------
log_info "Generating worker configuration..."

mkdir -p config

# Generate unique worker ID
WORKER_ID="bitsage-$(hostname)-$(date +%s | md5sum | head -c 8)"

# Get system info
CPU_CORES=$(nproc)
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
DISK_GB=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
GPU_MEMORY_GB=$((GPU_MEMORY / 1024))

# Detect TEE support
TEE_TYPE="None"
if [[ "$GPU_NAME" == *"H100"* ]] || [[ "$GPU_NAME" == *"H200"* ]]; then
    if dmesg 2>/dev/null | grep -iq "tdx\|sgx"; then
        TEE_TYPE="Full"
        log_success "Intel TDX/SGX TEE detected"
    else
        TEE_TYPE="CpuOnly"
        log_warn "Enterprise GPU but no hardware TEE detected"
    fi
fi

# Create worker config
cat > config/worker.toml <<EOF
# =============================================================================
# BitSage Worker Configuration - PRODUCTION (Sepolia)
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# GPU: $GPU_NAME x $GPU_COUNT
# =============================================================================

[worker]
id = "$WORKER_ID"
# Coordinator URL (set via COORDINATOR_URL env var or edit here)
coordinator_url = "http://localhost:8080"
# Your Starknet wallet address for receiving SAGE rewards
wallet_address = ""

[capabilities]
gpu_count = $GPU_COUNT
gpu_memory_gb = $GPU_MEMORY_GB
gpu_model = "$GPU_NAME"
gpu_tier = "$GPU_TIER"
tee_type = "$TEE_TYPE"
cpu_cores = $CPU_CORES
ram_gb = $RAM_GB
disk_gb = $DISK_GB
max_concurrent_jobs = $((GPU_COUNT * 2))

[network]
listen_address = "0.0.0.0"
listen_port = 8081
enable_p2p = true
p2p_port = 4001

[proof_generation]
# Enable GPU-accelerated proof generation
enable_gpu = true
# Security bits for STARK proofs (128 for production)
security_bits = 128
# Enable multi-GPU for large proofs
multi_gpu = $([ "$GPU_COUNT" -gt 1 ] && echo "true" || echo "false")
# Generate real proofs (not mocks)
live_proofs = true

[security]
enable_tee = $([ "$TEE_TYPE" != "None" ] && echo "true" || echo "false")
verify_attestations = true

[performance]
worker_threads = $CPU_CORES
# Reserve 4GB for system, rest for proofs
max_gpu_memory_mb = $((GPU_MEMORY - 4096))

# =============================================================================
# Starknet Configuration (Sepolia Testnet)
# =============================================================================
[starknet]
network = "sepolia"
rpc_url = "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_7/YOUR_KEY"

# Contract Addresses (Sepolia - Production Deployed)
[starknet.contracts]
sage_token = "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850"
proof_verifier = "0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b"
stwo_verifier = "0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d"
proof_gated_payment = "0x7e74d191b1cca7cac00adc03bc64eaa6236b81001f50c61d1d70ec4bfde8af0"
escrow = "0x7d7b5aa04b8eec7676568c8b55acd5682b8f7cb051f69c1876f0e5a6d8edfd4"
fee_manager = "0x74344374490948307360e6a8376d656190773115a4fca4d049366cea7edde39"
payment_router = "0x6a0639e673febf90b6a6e7d3743c81f96b39a3037b60429d479c62c5d20d41"
prover_staking = "0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b"
reputation_manager = "0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de"

# Settlement configuration
[settlement]
# Set to true for real on-chain transactions
live_mode = false
# Minimum SAGE for worker payment
min_payout_sage = 1
EOF

log_success "Configuration created: config/worker.toml"

# -----------------------------------------------------------------------------
# Step 6: Create Helper Scripts
# -----------------------------------------------------------------------------

# Start script
cat > start.sh <<'SCRIPT'
#!/bin/bash
set -e

cd "$(dirname "$0")"

# Load environment if exists
[ -f .env ] && source .env

echo "🚀 Starting BitSage Worker..."
echo "   Config: config/worker.toml"
echo "   Logs: worker.log"
echo ""

# Check if coordinator URL is set
if grep -q 'coordinator_url = "http://localhost:8080"' config/worker.toml; then
    echo "⚠️  WARNING: Coordinator URL not configured!"
    echo "   Edit config/worker.toml or set COORDINATOR_URL environment variable"
    echo ""
fi

# Update coordinator URL from env if set
if [ -n "$COORDINATOR_URL" ]; then
    sed -i "s|coordinator_url = .*|coordinator_url = \"$COORDINATOR_URL\"|" config/worker.toml
    echo "✓ Using coordinator: $COORDINATOR_URL"
fi

# Update wallet address from env if set
if [ -n "$WALLET_ADDRESS" ]; then
    sed -i "s|wallet_address = .*|wallet_address = \"$WALLET_ADDRESS\"|" config/worker.toml
    echo "✓ Using wallet: $WALLET_ADDRESS"
fi

# Start worker
RUST_LOG=${RUST_LOG:-info} ./target/release/worker \
    --config config/worker.toml \
    2>&1 | tee -a worker.log
SCRIPT
chmod +x start.sh

# Stop script
cat > stop.sh <<'SCRIPT'
#!/bin/bash
echo "🛑 Stopping BitSage Worker..."
pkill -f "target/release/worker" 2>/dev/null || true
echo "✓ Worker stopped"
SCRIPT
chmod +x stop.sh

# Status script
cat > status.sh <<'SCRIPT'
#!/bin/bash
echo "📊 BitSage Worker Status"
echo "========================"
echo ""

# Check if running
if pgrep -f "target/release/worker" > /dev/null; then
    PID=$(pgrep -f "target/release/worker")
    echo "Status: ✅ RUNNING (PID: $PID)"
    echo ""

    # Show resource usage
    echo "Resource Usage:"
    ps -p $PID -o %cpu,%mem,etime --no-headers | awk '{print "  CPU: "$1"%, Memory: "$2"%, Uptime: "$3}'
else
    echo "Status: ❌ NOT RUNNING"
fi

echo ""
echo "GPU Status:"
nvidia-smi --query-gpu=utilization.gpu,utilization.memory,temperature.gpu,power.draw --format=csv,noheader | \
    awk -F', ' '{print "  Utilization: "$1", Memory: "$2", Temp: "$3", Power: "$4}'

echo ""
echo "Recent Logs:"
tail -5 worker.log 2>/dev/null || echo "  No logs yet"
SCRIPT
chmod +x status.sh

# GPU test script
cat > test_gpu.sh <<'SCRIPT'
#!/bin/bash
echo "🧪 Testing GPU Proof Generation..."
echo ""

cd "$(dirname "$0")"

# Run GPU benchmark
RUST_LOG=info cargo run --release --example gpu_benchmark 2>&1 || {
    echo ""
    echo "Running basic GPU test instead..."
    nvidia-smi
    echo ""
    echo "Testing CUDA..."
    python3 -c "import torch; print(f'PyTorch CUDA: {torch.cuda.is_available()}'); print(f'Device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"N/A\"}')" 2>/dev/null || echo "PyTorch not installed (optional)"
}
SCRIPT
chmod +x test_gpu.sh

# Production proof test script
cat > test_proof.sh <<'SCRIPT'
#!/bin/bash
echo "🔐 Testing Production STWO Proof Generation..."
echo ""
echo "This will generate a real STWO proof using your H100 GPU"
echo "and verify the proof-as-invoice pipeline."
echo ""

cd "$(dirname "$0")"
source .env 2>/dev/null || true

# Check GPU
echo "📊 GPU Status:"
nvidia-smi --query-gpu=name,memory.total,memory.free --format=csv
echo ""

# Run the proof generation example
echo "🚀 Generating STWO proof..."
RUST_LOG=info cargo run --release --example obelysk_proof_of_attestation 2>&1

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  If you see proof metrics above, your GPU prover is working!"
echo "═══════════════════════════════════════════════════════════════"
SCRIPT
chmod +x test_proof.sh

# End-to-end test script
cat > test_e2e.sh <<'SCRIPT'
#!/bin/bash
echo "🧪 End-to-End Production Test"
echo "============================="
echo ""
echo "This test will:"
echo "  1. Submit a Ping job"
echo "  2. Generate STWO proof"
echo "  3. Create compute invoice"
echo "  4. Verify proof locally"
echo "  5. (If LIVE_MODE=true) Settle on Sepolia"
echo ""

cd "$(dirname "$0")"
source .env 2>/dev/null || true

# Run e2e test
RUST_LOG=info cargo run --release --example e2e_invoice_test 2>&1

echo ""
echo "Check above for invoice generation and settlement status."
SCRIPT
chmod +x test_e2e.sh

log_success "Helper scripts created: start.sh, stop.sh, status.sh, test_gpu.sh, test_proof.sh, test_e2e.sh"

# -----------------------------------------------------------------------------
# Step 7: Create .env template (Production Sepolia)
# -----------------------------------------------------------------------------
cat > .env.example <<EOF
# =============================================================================
# BitSage Worker - Production Environment (Sepolia)
# =============================================================================
# Copy to .env and fill in your values

# -----------------------------------------------------------------------------
# Required Configuration
# -----------------------------------------------------------------------------

# Coordinator URL (your coordinator endpoint)
COORDINATOR_URL=http://your-coordinator:8080

# Your Starknet wallet address (for receiving SAGE rewards)
WALLET_ADDRESS=0x...

# Your Starknet private key (for signing transactions)
# SECURITY: Keep this secret! Never commit to git!
STARKNET_PRIVATE_KEY=0x...

# -----------------------------------------------------------------------------
# Starknet RPC (Sepolia)
# -----------------------------------------------------------------------------
# Options: Alchemy, Infura, Blast, or public nodes
STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io/rpc/v0_7

# -----------------------------------------------------------------------------
# Contract Addresses (Sepolia - Already Deployed)
# -----------------------------------------------------------------------------
SAGE_TOKEN=0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850
PROOF_VERIFIER=0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b
STWO_VERIFIER=0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d
PROOF_GATED_PAYMENT=0x7e74d191b1cca7cac00adc03bc64eaa6236b81001f50c61d1d70ec4bfde8af0
ESCROW=0x7d7b5aa04b8eec7676568c8b55acd5682b8f7cb051f69c1876f0e5a6d8edfd4
FEE_MANAGER=0x74344374490948307360e6a8376d656190773115a4fca4d049366cea7edde39
PAYMENT_ROUTER=0x6a0639e673febf90b6a6e7d3743c81f96b39a3037b60429d479c62c5d20d41
PROVER_STAKING=0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b
REPUTATION_MANAGER=0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de

# -----------------------------------------------------------------------------
# Settlement Configuration
# -----------------------------------------------------------------------------
# Set to true for real on-chain transactions (false = dry run)
LIVE_MODE=false

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
RUST_LOG=info
EOF

if [ ! -f .env ]; then
    cp .env.example .env
    log_info "Created .env file - please configure it"
fi

# Create a quick-config script
cat > configure.sh <<'SCRIPT'
#!/bin/bash
# Quick configuration script

echo "🔧 BitSage Worker Quick Configuration"
echo "======================================"
echo ""

read -p "Enter your Starknet wallet address (0x...): " wallet
read -p "Enter your coordinator URL (or press Enter for localhost): " coordinator
coordinator=${coordinator:-http://localhost:8080}

# Update .env
sed -i "s|WALLET_ADDRESS=.*|WALLET_ADDRESS=$wallet|" .env
sed -i "s|COORDINATOR_URL=.*|COORDINATOR_URL=$coordinator|" .env

# Update config
sed -i "s|wallet_address = .*|wallet_address = \"$wallet\"|" config/worker.toml
sed -i "s|coordinator_url = .*|coordinator_url = \"$coordinator\"|" config/worker.toml

echo ""
echo "✅ Configuration updated!"
echo "   Wallet: $wallet"
echo "   Coordinator: $coordinator"
echo ""
echo "To enable live on-chain settlement, edit .env and set LIVE_MODE=true"
echo ""
echo "Start the worker with: ./start.sh"
SCRIPT
chmod +x configure.sh

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  ✅ BitSage GPU Worker - Setup Complete!"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "  📊 Worker Details:"
echo "     ID:        $WORKER_ID"
echo "     GPU:       $GPU_NAME x $GPU_COUNT ($GPU_MEMORY_GB GB)"
echo "     GPU Tier:  $GPU_TIER (min stake: $MIN_STAKE SAGE)"
echo "     TEE:       $TEE_TYPE"
echo "     CPU:       $CPU_CORES cores"
echo "     RAM:       $RAM_GB GB"
echo ""
echo "  ⛓️  Network: Starknet Sepolia (Production Testnet)"
echo "     All contract addresses pre-configured in .env"
echo ""
echo "  📁 Files Created:"
echo "     config/worker.toml  - Worker + Starknet configuration"
echo "     .env                - Environment (wallet, keys, contracts)"
echo "     configure.sh        - Quick wallet configuration"
echo "     start.sh            - Start the worker"
echo "     stop.sh             - Stop the worker"
echo "     status.sh           - Check worker status"
echo "     test_gpu.sh         - Test GPU capabilities"
echo "     test_proof.sh       - Test STWO proof generation"
echo "     test_e2e.sh         - Full E2E invoice pipeline test"
echo ""
echo "  🚀 Quick Start (3 steps):"
echo ""
echo "     1. Configure your wallet:"
echo "        ./configure.sh"
echo "        # OR manually: nano .env"
echo ""
echo "     2. Test the proof pipeline:"
echo "        ./test_e2e.sh"
echo ""
echo "     3. Start the worker:"
echo "        ./start.sh"
echo ""
echo "  🧪 Testing Commands:"
echo "     ./test_gpu.sh     - Basic GPU test"
echo "     ./test_proof.sh   - STWO proof generation"
echo "     ./test_e2e.sh     - Full Job → Proof → Invoice → Settlement"
echo ""
echo "  📡 API Endpoints (after starting):"
echo "     Health:  http://localhost:8081/health"
echo "     Metrics: http://localhost:8081/metrics"
echo "     Status:  http://localhost:8081/status"
echo ""
echo "  ⚡ Production Settlement:"
echo "     Set LIVE_MODE=true in .env for real on-chain transactions"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo ""
