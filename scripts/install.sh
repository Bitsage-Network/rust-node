#!/bin/bash
#
# BitSage GPU Worker - One-Click Installation
#
# Usage:
#   curl -sSL https://get.bitsage.network | bash
#   or
#   ./install.sh
#
# This wizard will:
#   1. Detect your GPU and system configuration
#   2. Install all dependencies (Rust, CUDA drivers)
#   3. Download and build the sage-worker
#   4. Run the interactive setup wizard
#   5. Register with the network and start earning
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

# Configuration
VERSION="1.0.0"
INSTALL_DIR="$HOME/.bitsage"
BIN_DIR="$INSTALL_DIR/bin"
REPO_URL="https://github.com/Ciro-AI-Labs/bitsage-network"
RELEASE_URL="https://github.com/Ciro-AI-Labs/bitsage-network/releases/latest/download"

# Coordinator URLs
MAINNET_COORDINATOR="https://coordinator.bitsage.network"
SEPOLIA_COORDINATOR="http://35.163.191.22:8080"  # AWS EC2 Sepolia Coordinator

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'

    ██████╗ ██╗████████╗███████╗ █████╗  ██████╗ ███████╗
    ██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝ ██╔════╝
    ██████╔╝██║   ██║   ███████╗███████║██║  ███╗█████╗
    ██╔══██╗██║   ██║   ╚════██║██╔══██║██║   ██║██╔══╝
    ██████╔╝██║   ██║   ███████║██║  ██║╚██████╔╝███████╗
    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

           GPU WORKER INSTALLATION WIZARD v1.0.0

    Decentralized AI Compute | STWO Proofs | Earn SAGE

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
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

detect_gpu() {
    print_step "Step 1/6: Detecting Hardware"

    # Detect NVIDIA GPU
    if command -v nvidia-smi &> /dev/null; then
        GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total,compute_cap --format=csv,noheader 2>/dev/null | head -1)
        if [ -n "$GPU_INFO" ]; then
            GPU_NAME=$(echo "$GPU_INFO" | cut -d',' -f1 | xargs)
            GPU_MEMORY=$(echo "$GPU_INFO" | cut -d',' -f2 | xargs)
            GPU_COMPUTE=$(echo "$GPU_INFO" | cut -d',' -f3 | xargs)
            GPU_COUNT=$(nvidia-smi -L 2>/dev/null | wc -l)
            HAS_GPU=true
            print_success "NVIDIA GPU detected: $GPU_NAME"
            print_success "GPU Memory: $GPU_MEMORY"
            print_success "Compute Capability: $GPU_COMPUTE"
            print_success "GPU Count: $GPU_COUNT"
        fi
    fi

    # Detect AMD GPU
    if [ -z "$HAS_GPU" ] && command -v rocm-smi &> /dev/null; then
        GPU_NAME=$(rocm-smi --showproductname 2>/dev/null | grep -i "Card series" | head -1 | cut -d':' -f2 | xargs)
        if [ -n "$GPU_NAME" ]; then
            HAS_GPU=true
            GPU_TYPE="AMD"
            print_success "AMD GPU detected: $GPU_NAME"
        fi
    fi

    if [ -z "$HAS_GPU" ]; then
        print_warning "No GPU detected - worker will run in CPU mode"
        print_info "For optimal performance, use an NVIDIA GPU (RTX 3090+, A100, H100)"
        HAS_GPU=false
    fi

    # Detect CPU
    if [ "$OS" == "linux" ]; then
        CPU_INFO=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs)
        CPU_CORES=$(nproc)
    else
        CPU_INFO=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
        CPU_CORES=$(sysctl -n hw.ncpu)
    fi
    print_success "CPU: $CPU_INFO ($CPU_CORES cores)"

    # Detect RAM
    if [ "$OS" == "linux" ]; then
        RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    else
        RAM_GB=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
    fi
    print_success "RAM: ${RAM_GB}GB"

    # Detect TEE support
    if [ -f /dev/tdx_guest ] || [ -d /sys/kernel/security/tdx ]; then
        TEE_TYPE="Intel TDX"
        HAS_TEE=true
    elif [ -f /dev/sev-guest ] || [ -d /sys/kernel/security/sev ]; then
        TEE_TYPE="AMD SEV-SNP"
        HAS_TEE=true
    elif nvidia-smi --query-gpu=mig.mode.current --format=csv,noheader 2>/dev/null | grep -qi "enabled"; then
        TEE_TYPE="NVIDIA Confidential Computing"
        HAS_TEE=true
    else
        HAS_TEE=false
    fi

    if [ "$HAS_TEE" = true ]; then
        print_success "TEE Support: $TEE_TYPE"
    else
        print_info "TEE Support: Not detected (simulated mode available)"
    fi

    # Determine staking tier
    if [ "$HAS_GPU" = true ]; then
        GPU_MEM_GB=$(echo "$GPU_MEMORY" | grep -oE '[0-9]+' | head -1)
        if [ "$GPU_MEM_GB" -ge 70 ]; then
            STAKE_TIER="Enterprise"
            MIN_STAKE="10000"
        elif [ "$GPU_MEM_GB" -ge 40 ]; then
            STAKE_TIER="Professional"
            MIN_STAKE="5000"
        elif [ "$GPU_MEM_GB" -ge 20 ]; then
            STAKE_TIER="Standard"
            MIN_STAKE="1000"
        else
            STAKE_TIER="Basic"
            MIN_STAKE="100"
        fi
    else
        STAKE_TIER="Basic"
        MIN_STAKE="100"
    fi
    print_success "Staking Tier: $STAKE_TIER (min ${MIN_STAKE} SAGE)"
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

download_worker() {
    print_step "Step 3/6: Downloading BitSage Worker"

    mkdir -p "$BIN_DIR"

    # Try to download pre-built binary first
    ARCH=$(uname -m)
    if [ "$ARCH" == "x86_64" ]; then
        BINARY_NAME="sage-worker-linux-x86_64"
    elif [ "$ARCH" == "aarch64" ]; then
        BINARY_NAME="sage-worker-linux-arm64"
    fi

    print_info "Checking for pre-built binary..."
    if curl -sSL -o "$BIN_DIR/sage-worker" "$RELEASE_URL/$BINARY_NAME" 2>/dev/null; then
        chmod +x "$BIN_DIR/sage-worker"
        if "$BIN_DIR/sage-worker" --version &>/dev/null; then
            print_success "Downloaded pre-built binary"
            BUILD_FROM_SOURCE=false
        else
            BUILD_FROM_SOURCE=true
        fi
    else
        BUILD_FROM_SOURCE=true
    fi

    if [ "$BUILD_FROM_SOURCE" = true ]; then
        print_info "Building from source (this may take 5-10 minutes)..."

        # Clone repository
        TEMP_DIR=$(mktemp -d)
        git clone --depth 1 "$REPO_URL" "$TEMP_DIR/bitsage-network" 2>/dev/null || {
            print_warning "Could not clone from GitHub, using local build..."
        }

        # Build worker
        cd "$TEMP_DIR/bitsage-network/rust-node" 2>/dev/null || cd "$(dirname "$0")/.."

        source "$HOME/.cargo/env"
        cargo build --release --bin sage-worker

        cp target/release/sage-worker "$BIN_DIR/"
        chmod +x "$BIN_DIR/sage-worker"

        # Cleanup
        rm -rf "$TEMP_DIR"

        print_success "Worker built from source"
    fi

    # Add to PATH
    if ! grep -q "$BIN_DIR" "$HOME/.bashrc" 2>/dev/null; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
    fi
    if ! grep -q "$BIN_DIR" "$HOME/.zshrc" 2>/dev/null; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.zshrc"
    fi
    export PATH="$BIN_DIR:$PATH"

    print_success "Worker installed: $("$BIN_DIR/sage-worker" --version)"
}

select_network() {
    print_step "Step 4/6: Network Selection"

    echo -e "  ${BOLD}Select Network:${NC}\n"
    echo -e "    ${GREEN}1) Sepolia Testnet${NC} (Recommended for testing)"
    echo -e "       - Free test tokens available"
    echo -e "       - No real value at stake"
    echo -e ""
    echo -e "    ${YELLOW}2) Starknet Mainnet${NC}"
    echo -e "       - Real SAGE tokens required"
    echo -e "       - Earn real rewards"
    echo -e ""

    echo -ne "  ${CYAN}Select network [1-2]:${NC} "
    read -r selection

    case "$selection" in
        2)
            NETWORK="mainnet"
            COORDINATOR_URL="$MAINNET_COORDINATOR"
            print_warning "Mainnet selected - real tokens will be used!"
            ;;
        *)
            NETWORK="sepolia"
            COORDINATOR_URL="$SEPOLIA_COORDINATOR"
            print_success "Sepolia testnet selected"
            ;;
    esac
}

run_setup_wizard() {
    print_step "Step 5/6: Worker Configuration"

    print_info "Starting interactive setup wizard..."
    echo ""

    # Run the built-in setup wizard
    "$BIN_DIR/sage-worker" setup --network "$NETWORK"
}

start_worker() {
    print_step "Step 6/6: Starting Worker"

    echo -e "  ${BOLD}How would you like to run the worker?${NC}\n"
    echo -e "    1) Start now in foreground (recommended for testing)"
    echo -e "    2) Start as systemd service (runs on boot)"
    echo -e "    3) Start in tmux/screen session"
    echo -e "    4) Don't start now (I'll start it manually)"
    echo -e ""

    echo -ne "  ${CYAN}Select option [1-4]:${NC} "
    read -r start_option

    case "$start_option" in
        1)
            print_info "Starting worker in foreground..."
            print_info "Press Ctrl+C to stop"
            echo ""
            "$BIN_DIR/sage-worker" start
            ;;
        2)
            print_info "Creating systemd service..."
            sudo tee /etc/systemd/system/bitsage-worker.service > /dev/null << EOF
[Unit]
Description=BitSage GPU Worker
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=$BIN_DIR/sage-worker start
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
            sudo systemctl daemon-reload
            sudo systemctl enable bitsage-worker
            sudo systemctl start bitsage-worker
            print_success "Worker started as systemd service"
            print_info "Check status: sudo systemctl status bitsage-worker"
            print_info "View logs: sudo journalctl -u bitsage-worker -f"
            ;;
        3)
            if command -v tmux &> /dev/null; then
                tmux new-session -d -s bitsage "$BIN_DIR/sage-worker start"
                print_success "Worker started in tmux session 'bitsage'"
                print_info "Attach with: tmux attach -t bitsage"
            elif command -v screen &> /dev/null; then
                screen -dmS bitsage "$BIN_DIR/sage-worker" start
                print_success "Worker started in screen session 'bitsage'"
                print_info "Attach with: screen -r bitsage"
            else
                print_error "Neither tmux nor screen is installed"
                print_info "Install with: sudo apt install tmux"
            fi
            ;;
        *)
            print_info "Worker not started. Start manually with:"
            echo -e "    ${CYAN}sage-worker start${NC}"
            ;;
    esac
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
    echo -e "    GitHub:        https://github.com/Ciro-AI-Labs/bitsage-network"
    echo ""
}

# Main execution
main() {
    print_banner

    echo -e "  Welcome to the BitSage GPU Worker installation wizard!"
    echo -e "  This will guide you through setting up your node to earn SAGE tokens."
    echo ""
    echo -ne "  ${CYAN}Press Enter to continue or Ctrl+C to cancel...${NC}"
    read -r

    detect_os
    detect_gpu
    install_dependencies
    download_worker
    select_network
    run_setup_wizard
    start_worker
    print_summary
}

main "$@"
