#!/bin/bash
#
# BitSage Network - H100 GPU Worker Deployment Script
#
# This script deploys a sage-worker to an H100 instance.
#
# Usage:
#   SSH to your H100 instance and run:
#   curl -sSL https://raw.githubusercontent.com/Ciro-AI-Labs/bitsage-network/main/rust-node/scripts/deploy_h100.sh | bash
#
# Or locally:
#   ./scripts/deploy_h100.sh
#

set -e

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║       BITSAGE NETWORK - H100 GPU WORKER DEPLOYMENT                ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Check if running as root or with sudo
echo "[1/8] Checking permissions..."
if [ "$EUID" -ne 0 ]; then
    log_warn "Not running as root. Some commands may require sudo."
fi

# 2. Check for NVIDIA GPU
echo
echo "[2/8] Checking GPU..."
if command -v nvidia-smi &> /dev/null; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total,compute_cap --format=csv,noheader 2>/dev/null || echo "Unknown")
    log_info "GPU detected: $GPU_INFO"

    # Check for H100
    if echo "$GPU_INFO" | grep -qi "H100"; then
        log_info "H100 GPU confirmed!"
    else
        log_warn "Not an H100. Script will continue but performance may vary."
    fi
else
    log_error "nvidia-smi not found. Please install NVIDIA drivers first."
    echo "  Run: sudo apt install nvidia-driver-550"
    exit 1
fi

# 3. Check CUDA
echo
echo "[3/8] Checking CUDA..."
if command -v nvcc &> /dev/null; then
    CUDA_VERSION=$(nvcc --version | grep "release" | awk '{print $5}' | cut -d',' -f1)
    log_info "CUDA version: $CUDA_VERSION"
else
    log_warn "nvcc not found. Installing CUDA toolkit..."
    if [ -f /etc/debian_version ]; then
        wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb 2>/dev/null
        sudo dpkg -i cuda-keyring_1.1-1_all.deb
        sudo apt update
        sudo apt install -y cuda-toolkit-12-4
        rm -f cuda-keyring_1.1-1_all.deb

        # Add to PATH
        echo 'export PATH=/usr/local/cuda-12.4/bin:$PATH' >> ~/.bashrc
        echo 'export LD_LIBRARY_PATH=/usr/local/cuda-12.4/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
        export PATH=/usr/local/cuda-12.4/bin:$PATH
        export LD_LIBRARY_PATH=/usr/local/cuda-12.4/lib64:$LD_LIBRARY_PATH
    else
        log_error "Please install CUDA toolkit manually"
        exit 1
    fi
fi

# 4. Install Rust if needed
echo
echo "[4/8] Checking Rust..."
if command -v cargo &> /dev/null; then
    RUST_VERSION=$(rustc --version | awk '{print $2}')
    log_info "Rust version: $RUST_VERSION"
else
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# 5. Install dependencies
echo
echo "[5/8] Installing dependencies..."
if [ -f /etc/debian_version ]; then
    sudo apt update
    sudo apt install -y build-essential pkg-config libssl-dev cmake git
fi

# 6. Clone and build
echo
echo "[6/8] Building sage-worker..."
BITSAGE_DIR="$HOME/bitsage-network"

if [ -d "$BITSAGE_DIR" ]; then
    log_info "Updating existing repository..."
    cd "$BITSAGE_DIR"
    git pull
else
    log_info "Cloning repository..."
    git clone https://github.com/Ciro-AI-Labs/bitsage-network "$BITSAGE_DIR"
    cd "$BITSAGE_DIR"
fi

cd rust-node
log_info "Building with CUDA support (this may take several minutes)..."
cargo build --release --features cuda 2>&1 | tail -5

# 7. Install binary
echo
echo "[7/8] Installing sage-worker..."
sudo cp target/release/sage-worker /usr/local/bin/
log_info "Installed to /usr/local/bin/sage-worker"

# 8. Run setup
echo
echo "[8/8] Running setup..."
echo
sage-worker setup --network mainnet

# Create systemd service
echo
log_info "Creating systemd service..."
sudo tee /etc/systemd/system/sage-worker.service > /dev/null << 'EOF'
[Unit]
Description=BitSage GPU Worker
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sage-worker start
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable sage-worker

echo
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    DEPLOYMENT COMPLETE!                           ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║                                                                   ║"
echo "║  Your H100 GPU worker is ready.                                   ║"
echo "║                                                                   ║"
echo "║  Commands:                                                        ║"
echo "║    sage-worker start    - Start earning                           ║"
echo "║    sage-worker status   - Check status                            ║"
echo "║    sage-worker info     - View earnings                           ║"
echo "║    sage-worker stake    - Stake for better jobs                   ║"
echo "║                                                                   ║"
echo "║  To start as a service:                                           ║"
echo "║    sudo systemctl start sage-worker                               ║"
echo "║                                                                   ║"
echo "║  View logs:                                                       ║"
echo "║    sudo journalctl -u sage-worker -f                              ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo
echo "Start earning now:"
echo "  sage-worker start"
echo
