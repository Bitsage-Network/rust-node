#!/bin/bash
#
# BitSage Network - Mainnet GPU Proof Demo
#
# This script runs the investor demonstration on Starknet mainnet
# with GPU-accelerated STWO proof generation.
#
# Prerequisites:
#   - NVIDIA GPU with CUDA 12.x installed
#   - Starknet mainnet account with STRK for gas
#   - STWO verifier deployed to mainnet
#
# Usage:
#   export STARKNET_PRIVATE_KEY="0x..."
#   export STARKNET_ACCOUNT="0x..."
#   export STWO_VERIFIER_MAINNET="0x..."
#   ./scripts/mainnet_gpu_demo.sh

set -e

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║       BITSAGE NETWORK - MAINNET GPU PROOF DEMONSTRATION          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo

# Check for GPU
echo "[1/6] Checking GPU availability..."
if command -v nvidia-smi &> /dev/null; then
    nvidia-smi --query-gpu=name,memory.total,compute_cap --format=csv,noheader
    GPU_AVAILABLE=true
else
    echo "  WARNING: nvidia-smi not found. Running in CPU mode."
    GPU_AVAILABLE=false
fi
echo

# Check environment variables
echo "[2/6] Checking credentials..."
if [ -z "$STARKNET_PRIVATE_KEY" ]; then
    echo "  ERROR: STARKNET_PRIVATE_KEY not set"
    echo "  Export your mainnet account private key:"
    echo "    export STARKNET_PRIVATE_KEY=\"0x...\""
    exit 1
fi

if [ -z "$STARKNET_ACCOUNT" ]; then
    echo "  ERROR: STARKNET_ACCOUNT not set"
    echo "  Export your mainnet account address:"
    echo "    export STARKNET_ACCOUNT=\"0x...\""
    exit 1
fi

if [ -z "$STWO_VERIFIER_MAINNET" ]; then
    echo "  WARNING: STWO_VERIFIER_MAINNET not set"
    echo "  Using default Sepolia verifier for demo"
fi

echo "  Account: ${STARKNET_ACCOUNT:0:20}..."
echo "  Verifier: ${STWO_VERIFIER_MAINNET:-Not set (Sepolia default)}"
echo

# Build with CUDA if available
echo "[3/6] Building with GPU support..."
cd "$(dirname "$0")/.."

if [ "$GPU_AVAILABLE" = true ]; then
    cargo build --release --features cuda --bin bitsage-proof --example investor_proof_demo 2>&1 | tail -3
else
    cargo build --release --bin bitsage-proof --example investor_proof_demo 2>&1 | tail -3
fi
echo

# Create output directory
OUTPUT_DIR="./mainnet-demo-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo "[4/6] Output directory: $OUTPUT_DIR"
echo

# Run proof generation
echo "[5/6] Generating GPU-accelerated STWO proof..."
./target/release/bitsage-proof generate \
    --batch-size 1000 \
    --security-bits 128 \
    --format json \
    --output "$OUTPUT_DIR/proof.json"
echo

# Generate TEE attestation
echo "[6/6] Generating TEE attestation..."
./target/release/bitsage-proof attest \
    --proof "$OUTPUT_DIR/proof.json" \
    --output "$OUTPUT_DIR/quote.bin"
echo

# Summary
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    PROOF GENERATION COMPLETE                      ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Output directory: $OUTPUT_DIR"
echo "║                                                                   ║"
echo "║  Files generated:                                                 ║"
echo "║    - proof.json      (STWO Circle STARK proof)                   ║"
echo "║    - quote.bin       (TEE attestation quote)                     ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo

# Offer to submit
read -p "Submit proof to Starknet mainnet? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    echo "Submitting to mainnet..."
    ./target/release/bitsage-proof submit \
        --proof "$OUTPUT_DIR/proof.json" \
        --quote "$OUTPUT_DIR/quote.bin" \
        --network mainnet
else
    echo
    echo "To submit later, run:"
    echo "  ./target/release/bitsage-proof submit \\"
    echo "    --proof $OUTPUT_DIR/proof.json \\"
    echo "    --quote $OUTPUT_DIR/quote.bin \\"
    echo "    --network mainnet"
fi

echo
echo "Done!"
