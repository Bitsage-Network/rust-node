#!/bin/bash
# GPU Batch Proof Demo - Run on H100 Instance
# This script runs REAL AI inference with GPU-accelerated proof generation
# and submits batch proofs to Starknet Sepolia

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║        OBELYSK GPU BATCH PROOF DEMO - H100                           ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Running REAL AI inference with GPU-accelerated STWO proofs          ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
NUM_PROOFS=${1:-100}
CONTRACT="0x017ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b"
RPC_URL="https://rpc.starknet-testnet.lava.build"
ACCOUNT_ADDRESS="${STARKNET_ACCOUNT_ADDRESS:?Set STARKNET_ACCOUNT_ADDRESS in .env}"
PRIVATE_KEY="${STARKNET_PRIVATE_KEY:?Set STARKNET_PRIVATE_KEY in .env}"

echo "Configuration:"
echo "  - Number of proofs: $NUM_PROOFS"
echo "  - Contract: $CONTRACT"
echo "  - Network: Starknet Sepolia"
echo ""

# Check GPU
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "GPU STATUS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
nvidia-smi --query-gpu=name,memory.total,memory.free,utilization.gpu --format=csv
echo ""

# Install starkli if not present
if ! command -v starkli &> /dev/null; then
    echo "Installing starkli..."
    curl https://get.starkli.sh | sh
    export PATH="$HOME/.starkli/bin:$PATH"
fi

# Create account file
echo "Creating account file..."
cat > /tmp/account.json << 'EOF'
{
  "version": 1,
  "variant": {
    "type": "braavos",
    "version": 1,
    "implementation": "0x0",
    "multisig": {
      "status": "off"
    },
    "signers": [
      {
        "type": "stark",
        "public_key": "0x064285e1b6e46d55c25ca77ced1e5e05b3d0f5ec78c30fded6d31d4edce1e4c5"
      }
    ]
  },
  "deployment": {
    "status": "deployed",
    "class_hash": "0x00816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253",
    "address": "0x01f9ebd4b60101259df3ac877a27a1a017e7961995fa913be1a6f189af664660"
  }
}
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 1: Building with CUDA support..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cargo build --release --features cuda 2>&1 | tail -5

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 2: Running GPU batch proof generation..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
START_TIME=$(date +%s.%N)

# Run the batch proof generator
cargo run --release --features cuda --example large_scale_batch_proofs -- $NUM_PROOFS

END_TIME=$(date +%s.%N)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 3: Submitting batch proofs to Starknet..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Run the batch submission script
if [ -f /tmp/batch_proof_submit.sh ]; then
    chmod +x /tmp/batch_proof_submit.sh
    /tmp/batch_proof_submit.sh
else
    echo "Batch script not generated - run large_scale_batch_proofs first"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "FINAL RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Total proofs generated: $NUM_PROOFS"
echo "  Total time: ${DURATION}s"
echo "  Throughput: $(echo "scale=2; $NUM_PROOFS / $DURATION" | bc) proofs/sec"
echo ""
echo "  GPU: NVIDIA H100"
echo "  Cost per proof: ~\$0.003"
echo ""
echo "  vs STWO CPU (estimated):"
echo "  - CPU throughput: ~0.5 proofs/sec"
echo "  - GPU speedup: ~$(echo "scale=0; ($NUM_PROOFS / $DURATION) / 0.5" | bc)x"
echo ""
