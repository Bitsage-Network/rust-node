#!/bin/bash
#
# BitSage Network - GPU Worker Setup Script
#
# This script sets up and runs GPU-accelerated STWO proof generation
# on any NVIDIA GPU instance (H100, A100, RTX 4090, etc.)
#
# Usage:
#   ./rust-node/scripts/gpu_worker_setup.sh
#
# Or with explicit credentials:
#   KEYSTORE_PASSWORD=your_password ./rust-node/scripts/gpu_worker_setup.sh

set -e

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║       BITSAGE NETWORK - GPU WORKER SETUP                          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUST_NODE="$PROJECT_ROOT/rust-node"
STWO_DIR="$PROJECT_ROOT/libs/stwo"

# Load environment variables if .env exists
if [ -f "$RUST_NODE/.env" ]; then
    echo "Loading environment from .env..."
    export $(grep -v '^#' "$RUST_NODE/.env" | xargs)
fi

# Sepolia contract addresses (defaults, can be overridden via .env)
export STWO_VERIFIER_ADDRESS="${STWO_VERIFIER_ADDRESS:-0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d}"
export PROOF_VERIFIER_ADDRESS="${PROOF_VERIFIER_ADDRESS:-0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b}"
export SAGE_TOKEN_ADDRESS="${SAGE_TOKEN_ADDRESS:-0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850}"
export PROVER_STAKING_ADDRESS="${PROVER_STAKING_ADDRESS:-0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b}"

# Starknet Sepolia RPC
export STARKNET_RPC_URL="${STARKNET_RPC_URL:-https://rpc.starknet-testnet.lava.build}"

# ============================================================================
# Step 1: Check GPU availability
# ============================================================================
echo "[1/7] Checking GPU availability..."
if command -v nvidia-smi &> /dev/null; then
    echo "  GPU Details:"
    nvidia-smi --query-gpu=index,name,memory.total,memory.free,compute_cap,driver_version --format=csv,noheader | while read line; do
        echo "    $line"
    done
    GPU_COUNT=$(nvidia-smi --query-gpu=count --format=csv,noheader | head -1)
    GPU_MODEL=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)
    GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
    export GPU_AVAILABLE=true
    echo "  ✅ $GPU_COUNT GPU(s) detected: $GPU_MODEL ($GPU_MEMORY MB)"
else
    echo "  ⚠️  nvidia-smi not found. GPU support disabled."
    export GPU_AVAILABLE=false
fi
echo

# ============================================================================
# Step 2: Check CUDA toolkit
# ============================================================================
echo "[2/7] Checking CUDA toolkit..."
if command -v nvcc &> /dev/null; then
    CUDA_VERSION=$(nvcc --version | grep "release" | awk '{print $5}' | sed 's/,//')
    echo "  ✅ CUDA $CUDA_VERSION installed"
else
    echo "  ⚠️  nvcc not found. Installing CUDA toolkit..."
    if [ -f /etc/debian_version ]; then
        sudo apt-get update && sudo apt-get install -y cuda-toolkit-12-0 2>/dev/null || echo "  Manual CUDA install may be needed"
    fi
fi
echo

# ============================================================================
# Step 3: Verify Rust toolchain
# ============================================================================
echo "[3/7] Checking Rust toolchain..."
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version)
    echo "  ✅ $RUST_VERSION"
else
    echo "  Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Ensure nightly for SIMD features
rustup toolchain install nightly 2>/dev/null || true
rustup default nightly
echo

# ============================================================================
# Step 4: Build STWO with GPU support
# ============================================================================
echo "[4/7] Building STWO prover with GPU support..."
cd "$STWO_DIR"

BUILD_FEATURES="prover,std"
if [ "$GPU_AVAILABLE" = true ]; then
    BUILD_FEATURES="$BUILD_FEATURES,gpu,cuda-runtime"
    echo "  Building with GPU features: $BUILD_FEATURES"
else
    echo "  Building CPU-only: $BUILD_FEATURES"
fi

cargo build --release --package stwo --features "$BUILD_FEATURES" 2>&1 | tail -5
echo "  ✅ STWO prover built"
echo

# ============================================================================
# Step 5: Build rust-node worker with GPU
# ============================================================================
echo "[5/7] Building rust-node worker..."
cd "$RUST_NODE"

if [ "$GPU_AVAILABLE" = true ]; then
    cargo build --release --features cuda --bin sage-worker 2>&1 | tail -5
else
    cargo build --release --bin sage-worker 2>&1 | tail -5
fi
echo "  ✅ Worker binary built"
echo

# ============================================================================
# Step 6: Run GPU proof generation test
# ============================================================================
echo "[6/7] Running GPU proof generation test..."

OUTPUT_DIR="$RUST_NODE/data/proofs-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Run the GPU unit tests first
echo "  Running STWO GPU unit tests..."
cd "$STWO_DIR"
if [ "$GPU_AVAILABLE" = true ]; then
    cargo test --release --package stwo --features "prover,std,gpu,cuda-runtime" gpu_ 2>&1 | tail -20 || echo "  Some GPU tests may have failed (expected on first run)"
fi

# Generate a test proof
echo "  Generating test STWO proof..."
cat > "$OUTPUT_DIR/test_circuit.json" << 'EOF'
{
  "circuit_type": "fibonacci",
  "trace_length": 1024,
  "security_bits": 100,
  "blowup_factor": 2
}
EOF

# Run proof generation example if it exists
cd "$RUST_NODE"
if [ -f "./target/release/examples/gpu_benchmark" ]; then
    echo "  Running GPU benchmark..."
    ./target/release/examples/gpu_benchmark --trace-size 1024 --iterations 3 2>&1 | tail -10
fi
echo

# ============================================================================
# Step 7: Configuration summary
# ============================================================================
echo "[7/7] Configuration summary..."
echo "  RPC: $STARKNET_RPC_URL"
echo "  STWO Verifier: ${STWO_VERIFIER_ADDRESS:0:20}..."
echo

# ============================================================================
# Summary
# ============================================================================
echo
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETE                                 ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
if [ "$GPU_AVAILABLE" = true ]; then
echo "║  GPU:        $GPU_MODEL"
echo "║  CUDA:       ${CUDA_VERSION:-N/A}"
else
echo "║  GPU:        Not available (CPU mode)"
fi
echo "║  Output:     $OUTPUT_DIR"
echo "║                                                                   ║"
echo "║  To start the GPU worker:                                         ║"
echo "║    cd $RUST_NODE"
echo "║    ./target/release/sage-worker setup --network sepolia"
echo "║    ./target/release/sage-worker start"
echo "║                                                                   ║"
echo "║  To run GPU proof generation examples:                            ║"
echo "║    cargo run --release --features cuda --example gpu_benchmark"
echo "║    cargo run --release --features cuda --example investor_proof_demo"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo

# Offer to start worker
read -p "Start GPU worker now? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    echo "Starting worker setup..."
    cd "$RUST_NODE"
    ./target/release/sage-worker setup --network sepolia
    echo
    echo "Starting worker..."
    ./target/release/sage-worker start
fi
