#!/bin/bash
#
# BitSage GPU Worker - One-Command Installation
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Bitsage-Network/rust-node/main/scripts/install.sh | bash
#
# Or run directly:
#   ./install.sh
#
# This script will:
#   1. Detect your GPU, TEE, and system configuration
#   2. Install all dependencies (Rust, build tools)
#   3. Clone and build the STWO prover and sage-worker
#   4. Run the setup wizard
#   5. Start earning SAGE tokens
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Configuration
VERSION="2.0.0"
INSTALL_DIR="${BITSAGE_HOME:-$HOME/bitsage}"
BIN_DIR="$HOME/.local/bin"
RUST_NODE_REPO="https://github.com/Bitsage-Network/rust-node.git"
STWO_REPO="https://github.com/Bitsage-Network/stwo-gpu.git"

# Coordinator URLs
MAINNET_COORDINATOR="https://coordinator.bitsage.network"
SEPOLIA_COORDINATOR="http://35.163.191.22:8080"

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'

    ██████╗ ██╗████████╗███████╗ █████╗  ██████╗ ███████╗
    ██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝ ██╔════╝
    ██████╔╝██║   ██║   ███████╗███████║██║  ███╗█████╗
    ██╔══██╗██║   ██║   ╚════██║██╔══██║██║   ██║██╔══╝
    ██████╔╝██║   ██║   ███████║██║  ██║╚██████╔╝███████╗
    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

         GPU-Accelerated Compute Network on Starknet
                  ONE-COMMAND INSTALLER v2.0

EOF
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

print_error() {
    echo -e "${RED}  ✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}  ⚠ $1${NC}"
}

print_info() {
    echo -e "${CYAN}  ℹ $1${NC}"
}

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO=$ID
            DISTRO_VERSION=$VERSION_ID
            DISTRO_NAME=$PRETTY_NAME
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
        DISTRO_NAME="macOS $(sw_vers -productVersion 2>/dev/null)"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

detect_system() {
    print_step "Step 1/6: System Detection"

    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC}                    ${BOLD}SYSTEM INFORMATION${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"

    # OS Info
    echo -e "${CYAN}│${NC}  ${BOLD}OS:${NC}          $DISTRO_NAME"
    echo -e "${CYAN}│${NC}  ${BOLD}Kernel:${NC}      $(uname -r)"

    # CPU Info
    if [ "$OS" == "linux" ]; then
        CPU_MODEL=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | xargs)
        CPU_CORES=$(nproc 2>/dev/null || echo "?")
    else
        CPU_MODEL=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
        CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo "?")
    fi
    echo -e "${CYAN}│${NC}  ${BOLD}CPU:${NC}         $CPU_MODEL / ${CPU_CORES} cores"

    # RAM Info
    if [ "$OS" == "linux" ]; then
        RAM_GB=$(free -g 2>/dev/null | awk '/^Mem:/{print $2}')
    else
        RAM_GB=$(($(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 / 1024))
    fi
    echo -e "${CYAN}│${NC}  ${BOLD}RAM:${NC}         ${RAM_GB}GB"

    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC}                      ${BOLD}GPU INFORMATION${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"

    # GPU Detection
    HAS_GPU=false
    GPU_TYPE="none"

    if command -v nvidia-smi &> /dev/null; then
        GPU_COUNT=$(nvidia-smi -L 2>/dev/null | wc -l | xargs)
        if [ "$GPU_COUNT" -gt 0 ]; then
            HAS_GPU=true
            GPU_TYPE="NVIDIA"

            # Get detailed GPU info
            GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | xargs)
            GPU_MEMORY_MB=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 | xargs)
            GPU_MEMORY_GB=$((GPU_MEMORY_MB / 1024))
            GPU_DRIVER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 | xargs)
            GPU_CUDA=$(nvcc --version 2>/dev/null | grep "release" | awk '{print $5}' | sed 's/,//' || echo "N/A")
            GPU_COMPUTE=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | xargs)
            GPU_UTIL=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader 2>/dev/null | head -1 | xargs)
            GPU_TEMP=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader 2>/dev/null | head -1 | xargs)
            GPU_POWER=$(nvidia-smi --query-gpu=power.draw --format=csv,noheader 2>/dev/null | head -1 | xargs)

            echo -e "${CYAN}│${NC}  ${BOLD}GPUs:${NC}         ${GREEN}$GPU_NAME x$GPU_COUNT${NC}"
            echo -e "${CYAN}│${NC}  ${BOLD}VRAM:${NC}         ${GPU_MEMORY_GB}GB per GPU"
            echo -e "${CYAN}│${NC}  ${BOLD}Driver:${NC}       $GPU_DRIVER"
            echo -e "${CYAN}│${NC}  ${BOLD}CUDA:${NC}         $GPU_CUDA"
            echo -e "${CYAN}│${NC}  ${BOLD}Compute:${NC}      $GPU_COMPUTE"
            echo -e "${CYAN}│${NC}  ${BOLD}Status:${NC}       ${GPU_UTIL} util, ${GPU_TEMP}°C, ${GPU_POWER}"

            # Determine GPU tier
            if [[ "$GPU_NAME" =~ H100|H200|B100|B200 ]]; then
                GPU_TIER="Enterprise"
                MIN_STAKE="10000"
            elif [[ "$GPU_NAME" =~ A100|A800 ]]; then
                GPU_TIER="DataCenter"
                MIN_STAKE="5000"
            elif [[ "$GPU_NAME" =~ A6000|L40|L4|A5000 ]]; then
                GPU_TIER="Workstation"
                MIN_STAKE="2500"
            elif [[ "$GPU_NAME" =~ 4090|4080|3090 ]]; then
                GPU_TIER="Consumer"
                MIN_STAKE="1000"
            else
                GPU_TIER="Basic"
                MIN_STAKE="500"
            fi
        fi
    fi

    # AMD GPU detection
    if [ "$HAS_GPU" = false ] && command -v rocm-smi &> /dev/null; then
        AMD_GPU=$(rocm-smi --showproductname 2>/dev/null | grep -i "card" | head -1)
        if [ -n "$AMD_GPU" ]; then
            HAS_GPU=true
            GPU_TYPE="AMD"
            GPU_NAME="$AMD_GPU"
            echo -e "${CYAN}│${NC}  ${BOLD}GPUs:${NC}         ${GREEN}$GPU_NAME${NC}"
            GPU_TIER="Workstation"
            MIN_STAKE="2500"
        fi
    fi

    if [ "$HAS_GPU" = false ]; then
        echo -e "${CYAN}│${NC}  ${BOLD}GPUs:${NC}         ${YELLOW}None detected (CPU-only mode)${NC}"
        GPU_TIER="CPU"
        MIN_STAKE="100"
    fi

    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC}                  ${BOLD}SECURITY & PRIVACY${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"

    # TEE Detection
    TEE_STATUS="${RED}Not Available${NC}"
    HAS_TEE=false

    # Intel TDX
    if [ -f /dev/tdx_guest ] || [ -d /sys/kernel/security/tdx ] || dmesg 2>/dev/null | grep -qi "tdx"; then
        TEE_STATUS="${GREEN}Intel TDX${NC}"
        TEE_TYPE="TDX"
        HAS_TEE=true
    # AMD SEV-SNP
    elif [ -f /dev/sev-guest ] || [ -d /sys/kernel/security/sev ] || dmesg 2>/dev/null | grep -qi "sev"; then
        TEE_STATUS="${GREEN}AMD SEV-SNP${NC}"
        TEE_TYPE="SEV"
        HAS_TEE=true
    # NVIDIA Confidential Computing (H100)
    elif [ "$HAS_GPU" = true ] && [[ "$GPU_NAME" =~ H100|H200 ]]; then
        # Check if CC mode is available
        if nvidia-smi conf-compute -i 0 2>/dev/null | grep -qi "enabled\|on"; then
            TEE_STATUS="${GREEN}NVIDIA CC (Active)${NC}"
            TEE_TYPE="NVIDIA_CC"
            HAS_TEE=true
        else
            TEE_STATUS="${YELLOW}NVIDIA CC (Available)${NC}"
            TEE_TYPE="NVIDIA_CC_AVAILABLE"
        fi
    fi
    echo -e "${CYAN}│${NC}  ${BOLD}TEE:${NC}          $TEE_STATUS"

    # FHE Support (based on CPU/GPU capabilities)
    FHE_STATUS="${YELLOW}Software Mode${NC}"
    if [ "$HAS_GPU" = true ] && [ "$GPU_MEMORY_GB" -ge 40 ]; then
        FHE_STATUS="${GREEN}GPU-Accelerated${NC}"
    fi
    echo -e "${CYAN}│${NC}  ${BOLD}FHE:${NC}          $FHE_STATUS"

    # STWO Proving capability
    if [ "$HAS_GPU" = true ]; then
        STWO_STATUS="${GREEN}GPU-Accelerated${NC}"
    else
        STWO_STATUS="${YELLOW}CPU Mode${NC}"
    fi
    echo -e "${CYAN}│${NC}  ${BOLD}STWO:${NC}         $STWO_STATUS"

    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}Worker Tier:${NC}  ${GREEN}$GPU_TIER${NC} (min stake: ${MIN_STAKE} SAGE)"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo
}

install_dependencies() {
    print_step "Step 2/6: Installing Dependencies"

    # Install Rust if not present
    if ! command -v cargo &> /dev/null; then
        print_info "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        print_success "Rust installed: $(rustc --version)"
    else
        print_success "Rust already installed: $(rustc --version)"
    fi

    # Install build dependencies
    if [ "$OS" == "linux" ]; then
        if [ "$DISTRO" == "ubuntu" ] || [ "$DISTRO" == "debian" ]; then
            print_info "Installing build dependencies..."
            sudo apt-get update -qq
            sudo apt-get install -y -qq build-essential pkg-config libssl-dev libpq-dev clang libclang-dev curl git
            print_success "Build dependencies installed"
        elif [ "$DISTRO" == "fedora" ] || [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
            sudo dnf install -y gcc gcc-c++ openssl-devel postgresql-devel clang clang-devel curl git
            print_success "Build dependencies installed"
        fi
    fi
}

clone_repositories() {
    print_step "Step 3/6: Cloning BitSage Repositories"

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/libs"
    mkdir -p "$BIN_DIR"

    # Clone rust-node
    if [ -d "$INSTALL_DIR/rust-node" ]; then
        print_info "rust-node already exists, pulling latest..."
        cd "$INSTALL_DIR/rust-node"
        git pull --ff-only 2>/dev/null || true
    else
        print_info "Cloning rust-node..."
        git clone --depth 1 "$RUST_NODE_REPO" "$INSTALL_DIR/rust-node" 2>&1 | tail -2
    fi
    print_success "rust-node ready"

    # Clone stwo-gpu
    if [ -d "$INSTALL_DIR/libs/stwo" ]; then
        print_info "stwo-gpu already exists, pulling latest..."
        cd "$INSTALL_DIR/libs/stwo"
        git pull --ff-only 2>/dev/null || true
    else
        print_info "Cloning stwo-gpu (STWO prover with GPU support)..."
        git clone --depth 1 "$STWO_REPO" "$INSTALL_DIR/libs/stwo" 2>&1 | tail -2
    fi
    print_success "stwo-gpu ready"
}

build_worker() {
    print_step "Step 4/6: Building BitSage Worker"

    cd "$INSTALL_DIR/rust-node"
    source "$HOME/.cargo/env" 2>/dev/null || true

    # Determine build features
    BUILD_FEATURES=""
    if [ "$HAS_GPU" = true ] && [ "$GPU_TYPE" = "NVIDIA" ]; then
        BUILD_FEATURES="--features cuda"
        print_info "Building with GPU acceleration (CUDA)..."
    else
        print_info "Building CPU-only version..."
    fi

    # Build the worker
    echo -e "${DIM}"
    cargo build --release --bin sage-worker $BUILD_FEATURES 2>&1 | tail -10
    echo -e "${NC}"

    # Copy to bin directory
    cp "$INSTALL_DIR/rust-node/target/release/sage-worker" "$BIN_DIR/"
    chmod +x "$BIN_DIR/sage-worker"

    # Add to PATH
    if ! grep -q "$BIN_DIR" "$HOME/.bashrc" 2>/dev/null; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
    fi
    if ! grep -q "$BIN_DIR" "$HOME/.zshrc" 2>/dev/null; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.zshrc"
    fi
    export PATH="$BIN_DIR:$PATH"

    print_success "Worker built: $(sage-worker --version 2>/dev/null || echo 'sage-worker')"
}

run_setup_wizard() {
    print_step "Step 5/6: Worker Configuration"

    # Default to sepolia for safety
    NETWORK="sepolia"

    print_info "Running worker setup for Sepolia testnet..."
    echo ""

    # Run the built-in setup wizard
    "$BIN_DIR/sage-worker" setup --network "$NETWORK"
}

print_completion() {
    print_step "Step 6/6: Installation Complete"

    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                  BITSAGE WORKER INSTALLED                         ║"
    echo "╠═══════════════════════════════════════════════════════════════════╣"
    echo "║                                                                   ║"
    echo "║  Installation:  $INSTALL_DIR"
    echo "║  Binary:        $BIN_DIR/sage-worker"
    echo "║                                                                   ║"
    echo "╠═══════════════════════════════════════════════════════════════════╣"
    echo "║  QUICK START:                                                     ║"
    echo "║                                                                   ║"
    echo "║    sage-worker start     # Start earning SAGE                     ║"
    echo "║    sage-worker status    # Check status & earnings                ║"
    echo "║    sage-worker stake     # Stake tokens for priority              ║"
    echo "║                                                                   ║"
    echo "╠═══════════════════════════════════════════════════════════════════╣"
    echo "║  RESOURCES:                                                       ║"
    echo "║                                                                   ║"
    echo "║    Dashboard:     https://dashboard.bitsage.network               ║"
    echo "║    Documentation: https://docs.bitsage.network                    ║"
    echo "║    Discord:       https://discord.gg/bitsage                      ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_summary() {
    echo -e "\n${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    INSTALLATION COMPLETE                          ║"
    echo "╠═══════════════════════════════════════════════════════════════════╣"
    echo "║                                                                   ║"
    echo "║  Worker ID:       $(cat "$INSTALL_DIR/worker.toml" 2>/dev/null | grep worker_id | cut -d'"' -f2 || echo 'See config')"
    echo "║  Network:         $NETWORK"
    echo "║  Staking Tier:    $STAKE_TIER (min ${MIN_STAKE} SAGE)"
    echo "║                                                                   ║"
    echo "║  Configuration:   $INSTALL_DIR/worker.toml"
    echo "║  Wallet Keys:     $INSTALL_DIR/keys/"
    echo "║                                                                   ║"
    echo "╠═══════════════════════════════════════════════════════════════════╣"
    echo "║  NEXT STEPS:                                                      ║"
    echo "║                                                                   ║"
    echo "║  1. Get SAGE tokens:                                              ║"
    if [ "$NETWORK" == "sepolia" ]; then
    echo "║     Visit: https://faucet.bitsage.network                         ║"
    else
    echo "║     Purchase on: https://app.bitsage.network/trade                ║"
    fi
    echo "║                                                                   ║"
    echo "║  2. Stake tokens:                                                 ║"
    echo "║     sage-worker stake ${MIN_STAKE}                                 ║"
    echo "║                                                                   ║"
    echo "║  3. Monitor earnings:                                             ║"
    echo "║     sage-worker status                                            ║"
    echo "║     https://dashboard.bitsage.network                             ║"
    echo "║                                                                   ║"
    echo "╠═══════════════════════════════════════════════════════════════════╣"
    echo "║  USEFUL COMMANDS:                                                 ║"
    echo "║                                                                   ║"
    echo "║    sage-worker start     Start the worker                         ║"
    echo "║    sage-worker stop      Stop the worker                          ║"
    echo "║    sage-worker status    Check status and earnings                ║"
    echo "║    sage-worker stake     Stake SAGE tokens                        ║"
    echo "║    sage-worker claim     Claim pending rewards                    ║"
    echo "║    sage-worker info      Show system info                         ║"
    echo "║    sage-worker logs      View logs                                ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "  ${CYAN}Need help?${NC}"
    echo -e "    Documentation: https://docs.bitsage.network"
    echo -e "    Discord:       https://discord.gg/bitsage"
    echo -e "    GitHub:        https://github.com/Bitsage-Network/rust-node"
    echo ""
}

# Main execution
main() {
    print_banner

    echo -e "  ${BOLD}One-command installer for BitSage GPU Workers${NC}"
    echo -e "  Earn SAGE tokens by providing GPU compute to the network."
    echo ""

    # Auto-detect or prompt
    if [ -t 0 ]; then
        echo -ne "  ${CYAN}Press Enter to begin installation...${NC}"
        read -r
    fi

    detect_os
    detect_system
    install_dependencies
    clone_repositories
    build_worker
    run_setup_wizard
    print_completion

    echo ""
    echo -e "  ${GREEN}Ready to start earning!${NC} Run: ${CYAN}sage-worker start${NC}"
    echo ""
}

main "$@"
