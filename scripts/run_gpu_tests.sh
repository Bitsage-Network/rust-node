#!/bin/bash
# ============================================================================
# BitSage GPU FHE E2E Test Runner
# ============================================================================
#
# This script runs the FHE + STWO E2E tests on a GPU-enabled machine.
#
# Requirements:
# - NVIDIA GPU (H100/A100/V100 recommended)
# - CUDA 12.x installed
# - Rust nightly toolchain
#
# Usage:
#   ./scripts/run_gpu_tests.sh              # Run all tests
#   ./scripts/run_gpu_tests.sh --benchmark  # Run benchmarks
#   ./scripts/run_gpu_tests.sh --quick      # Quick smoke test
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║            BitSage GPU FHE E2E Test Suite                             ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================================
# GPU Detection
# ============================================================================

echo -e "${YELLOW}[1/5] Detecting GPU...${NC}"

if command -v nvidia-smi &> /dev/null; then
    echo -e "${GREEN}✓ nvidia-smi found${NC}"
    nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader

    # Get GPU info
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)
    GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader | head -1)

    echo ""
    echo "  GPU: $GPU_NAME"
    echo "  Memory: $GPU_MEM"

    # Check for H100
    if [[ "$GPU_NAME" == *"H100"* ]]; then
        echo -e "  ${GREEN}✓ H100 detected - optimal for FHE!${NC}"
    elif [[ "$GPU_NAME" == *"A100"* ]]; then
        echo -e "  ${GREEN}✓ A100 detected - great for FHE${NC}"
    else
        echo -e "  ${YELLOW}⚠ Non-optimal GPU - H100/A100 recommended${NC}"
    fi
else
    echo -e "${RED}✗ nvidia-smi not found - GPU tests will run in CPU mode${NC}"
    echo "  Install NVIDIA drivers for GPU acceleration"
fi

# ============================================================================
# CUDA Check
# ============================================================================

echo ""
echo -e "${YELLOW}[2/5] Checking CUDA...${NC}"

if [ -d "/usr/local/cuda" ]; then
    CUDA_VERSION=$(/usr/local/cuda/bin/nvcc --version | grep "release" | awk '{print $5}' | cut -d',' -f1)
    echo -e "${GREEN}✓ CUDA found: $CUDA_VERSION${NC}"
else
    echo -e "${YELLOW}⚠ CUDA not found in /usr/local/cuda${NC}"
    echo "  Some optimizations may be unavailable"
fi

# Check cuDNN
if [ -f "/usr/include/cudnn.h" ] || [ -f "/usr/local/cuda/include/cudnn.h" ]; then
    echo -e "${GREEN}✓ cuDNN headers found${NC}"
fi

# ============================================================================
# Rust Environment
# ============================================================================

echo ""
echo -e "${YELLOW}[3/5] Checking Rust environment...${NC}"

if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version)
    echo -e "${GREEN}✓ Rust: $RUST_VERSION${NC}"
else
    echo -e "${RED}✗ Rust not found - please install rustup${NC}"
    exit 1
fi

# Check for nightly (needed for some FHE features)
if rustup show active-toolchain | grep -q "nightly"; then
    echo -e "${GREEN}✓ Nightly toolchain active${NC}"
else
    echo -e "${YELLOW}⚠ Stable toolchain - some features may be limited${NC}"
    echo "  Run: rustup default nightly"
fi

# ============================================================================
# Build
# ============================================================================

echo ""
echo -e "${YELLOW}[4/5] Building tests...${NC}"

# Parse arguments
BENCHMARK=false
QUICK=false

for arg in "$@"; do
    case $arg in
        --benchmark)
            BENCHMARK=true
            ;;
        --quick)
            QUICK=true
            ;;
    esac
done

# Build with release optimizations and FHE features
echo "  Building with --release..."
cargo build --release --package bitsage-node 2>&1 | tail -5

echo -e "${GREEN}✓ Build complete${NC}"

# ============================================================================
# Run Tests
# ============================================================================

echo ""
echo -e "${YELLOW}[5/5] Running E2E tests...${NC}"
echo ""

# Set environment for GPU
export RUST_BACKTRACE=1
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0}

if [ "$QUICK" = true ]; then
    echo "Running quick smoke tests..."
    cargo test --release --package bitsage-node gpu_fhe_e2e -- \
        test_e2e_simple_addition \
        test_gpu_detection \
        --nocapture

elif [ "$BENCHMARK" = true ]; then
    echo "Running full benchmark suite..."
    cargo test --release --package bitsage-node gpu_fhe_e2e -- \
        --nocapture \
        --ignored \
        benchmark_suite

else
    echo "Running all E2E tests..."
    cargo test --release --package bitsage-node gpu_fhe_e2e -- --nocapture
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                    Test Suite Complete                                 ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo "Next steps:"
echo "  1. Review test output above"
echo "  2. Run benchmarks: ./scripts/run_gpu_tests.sh --benchmark"
echo "  3. Deploy to production GPU: see docs/GPU_DEPLOYMENT.md"
echo ""
