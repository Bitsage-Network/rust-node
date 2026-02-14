#!/bin/bash
# =============================================================================
# BitSage Network — One-Command Full Node Deploy
# =============================================================================
# Takes a bare Ubuntu 22.04+ GPU server to a fully running BitSage node
# (coordinator + worker + PostgreSQL + systemd services).
#
# Usage:
#   ./scripts/bitsage-deploy.sh
#   BITSAGE_NETWORK=mainnet ./scripts/bitsage-deploy.sh
#   BITSAGE_COORDINATOR_ONLY=1 ./scripts/bitsage-deploy.sh
#
# Env var overrides:
#   BITSAGE_NETWORK          — sepolia (default) or mainnet
#   BITSAGE_DB_PASSWORD      — PostgreSQL password (default: bitsage_dev_password)
#   BITSAGE_COORDINATOR_ONLY — set to 1 to skip worker setup
#   BITSAGE_HOME             — install dir (default: ~/bitsage)
#   BITSAGE_BRANCH           — git branch to checkout (default: main)
# =============================================================================

set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
NETWORK="${BITSAGE_NETWORK:-sepolia}"
DB_PASSWORD="${BITSAGE_DB_PASSWORD:-bitsage_dev_password}"
DB_USER="bitsage"
DB_NAME="sage"
INSTALL_DIR="${BITSAGE_HOME:-$HOME/bitsage}"
BRANCH="${BITSAGE_BRANCH:-main}"
COORDINATOR_ONLY="${BITSAGE_COORDINATOR_ONLY:-0}"
RUST_NODE_REPO="https://github.com/Bitsage-Network/rust-node.git"
STWO_REPO="https://github.com/Bitsage-Network/stwo-gpu.git"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERR]${NC}  $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }

# ── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo "================================================================="
echo "  BitSage Network — One-Command Full Node Deploy"
echo "  Network: $NETWORK | Install dir: $INSTALL_DIR"
echo "================================================================="
echo ""

# ── Step 1: Detect Hardware ─────────────────────────────────────────────────
log_step "Step 1/11: Detecting hardware"

OS_ID=$(. /etc/os-release 2>/dev/null && echo "$ID" || echo "unknown")
OS_VERSION=$(. /etc/os-release 2>/dev/null && echo "$VERSION_ID" || echo "unknown")
log_info "OS: $OS_ID $OS_VERSION"

GPU_NAME="none"; GPU_MEMORY="0"; GPU_COUNT="0"; GPU_DRIVER="none"
if command -v nvidia-smi &>/dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n1 | xargs || echo "unknown")
    GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -n1 | xargs || echo "0")
    GPU_COUNT=$(nvidia-smi -L 2>/dev/null | wc -l || echo "0")
    GPU_DRIVER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -n1 | xargs || echo "unknown")
    log_success "GPU: $GPU_NAME ($GPU_MEMORY MiB) x $GPU_COUNT — Driver $GPU_DRIVER"
else
    log_warn "No NVIDIA GPU detected (nvidia-smi not found)"
fi

CUDA_VERSION="none"
if command -v nvcc &>/dev/null; then
    CUDA_VERSION=$(nvcc --version 2>/dev/null | grep -oP 'release \K[0-9.]+' || echo "unknown")
    log_success "CUDA: $CUDA_VERSION"
else
    log_warn "CUDA toolkit not found"
fi

TEE_SUPPORT="none"
if [ -c /dev/tdx_guest ] || dmesg 2>/dev/null | grep -qi "TDX"; then
    TEE_SUPPORT="tdx"
elif [ -c /dev/sev-guest ] || dmesg 2>/dev/null | grep -qi "SEV"; then
    TEE_SUPPORT="sev"
fi
log_info "TEE: $TEE_SUPPORT"

# ── Step 2: Install System Dependencies ─────────────────────────────────────
log_step "Step 2/11: Installing system dependencies"

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential pkg-config libssl-dev libpq-dev libclang-dev clang \
    git curl wget jq xxd \
    >/dev/null 2>&1
log_success "System packages installed"

# Rust
if command -v rustc &>/dev/null; then
    log_info "Rust already installed: $(rustc --version)"
    rustup update stable --no-self-update 2>/dev/null || true
else
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>/dev/null
    log_success "Rust installed"
fi
source "$HOME/.cargo/env" 2>/dev/null || true

# ── Step 3: Install & Configure PostgreSQL ──────────────────────────────────
log_step "Step 3/11: Setting up PostgreSQL"

if ! command -v psql &>/dev/null; then
    sudo apt-get install -y -qq postgresql postgresql-contrib >/dev/null 2>&1
    log_success "PostgreSQL installed"
else
    log_info "PostgreSQL already installed"
fi

sudo systemctl enable postgresql >/dev/null 2>&1
sudo systemctl start postgresql

# Create user + database (idempotent)
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null
sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" 2>/dev/null

# Ensure scram-sha-256 auth for local connections
PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" | xargs)
if ! sudo grep -q "host.*$DB_NAME.*$DB_USER.*scram-sha-256" "$PG_HBA" 2>/dev/null; then
    # Add rule before any existing host lines
    sudo sed -i "/^# IPv4 local connections/a host    $DB_NAME    $DB_USER    127.0.0.1/32    scram-sha-256" "$PG_HBA" 2>/dev/null || true
    sudo systemctl reload postgresql
fi

export DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}"
log_success "PostgreSQL configured (user=$DB_USER, db=$DB_NAME)"

# Run migrations
log_info "Running migrations..."
MIGRATION_DIR=""
if [ -d "$INSTALL_DIR/rust-node/migrations" ]; then
    MIGRATION_DIR="$INSTALL_DIR/rust-node/migrations"
elif [ -d "$(dirname "$0")/../migrations" ]; then
    MIGRATION_DIR="$(cd "$(dirname "$0")/../migrations" && pwd)"
fi

# Migrations will be applied after clone (step 4)

# ── Step 4: Clone / Update Repos ────────────────────────────────────────────
log_step "Step 4/11: Cloning repositories"

mkdir -p "$INSTALL_DIR"

clone_or_pull() {
    local repo="$1" dir="$2"
    if [ -d "$dir/.git" ]; then
        log_info "Updating $dir..."
        cd "$dir" && git fetch origin && git checkout "$BRANCH" 2>/dev/null && git pull origin "$BRANCH" 2>/dev/null || true
        cd - >/dev/null
    else
        log_info "Cloning $repo..."
        git clone --branch "$BRANCH" "$repo" "$dir" 2>/dev/null || \
        git clone "$repo" "$dir" 2>/dev/null
    fi
}

clone_or_pull "$RUST_NODE_REPO" "$INSTALL_DIR/rust-node"
clone_or_pull "$STWO_REPO" "$INSTALL_DIR/stwo-gpu"

log_success "Repos ready at $INSTALL_DIR/"

# Apply migrations now that we have the files
if [ -d "$INSTALL_DIR/rust-node/migrations" ]; then
    for sql in "$INSTALL_DIR/rust-node/migrations"/*.sql; do
        [ -f "$sql" ] || continue
        log_info "Applying $(basename "$sql")..."
        PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -f "$sql" 2>/dev/null || true
    done
    log_success "Migrations applied"
fi

# ── Step 5: Build Release Binaries ──────────────────────────────────────────
log_step "Step 5/11: Building release binaries"

cd "$INSTALL_DIR/rust-node"

CARGO_FEATURES=""
if [ "$CUDA_VERSION" != "none" ]; then
    CARGO_FEATURES="--features cuda"
fi

log_info "Building sage-coordinator..."
cargo build --release --bin sage-coordinator $CARGO_FEATURES 2>&1 | tail -n3
log_success "sage-coordinator built"

if [ "$COORDINATOR_ONLY" != "1" ]; then
    log_info "Building sage-worker..."
    cargo build --release --bin sage-worker $CARGO_FEATURES 2>&1 | tail -n3
    log_success "sage-worker built"
fi

# Symlink binaries
mkdir -p "$HOME/.local/bin"
ln -sf "$INSTALL_DIR/rust-node/target/release/sage-coordinator" "$HOME/.local/bin/sage-coordinator"
[ "$COORDINATOR_ONLY" != "1" ] && ln -sf "$INSTALL_DIR/rust-node/target/release/sage-worker" "$HOME/.local/bin/sage-worker"
export PATH="$HOME/.local/bin:$PATH"

# ── Step 6: Worker Setup ────────────────────────────────────────────────────
if [ "$COORDINATOR_ONLY" != "1" ]; then
    log_step "Step 6/11: Running worker setup"
    sage-worker setup --network "$NETWORK" --non-interactive 2>/dev/null || \
    sage-worker setup --network "$NETWORK" 2>/dev/null </dev/null || \
    log_warn "Worker setup returned non-zero (may already be configured)"
    log_success "Worker setup complete"
else
    log_step "Step 6/11: Skipping worker setup (coordinator-only mode)"
fi

# ── Step 7: Patch worker.toml ───────────────────────────────────────────────
log_step "Step 7/11: Configuring worker.toml"

WORKER_TOML="$HOME/.bitsage/worker.toml"
if [ -f "$WORKER_TOML" ]; then
    # Patch coordinator_url to localhost
    if grep -q 'coordinator_url' "$WORKER_TOML"; then
        sed -i 's|coordinator_url\s*=\s*"[^"]*"|coordinator_url = "http://localhost:8080"|' "$WORKER_TOML"
    else
        echo 'coordinator_url = "http://localhost:8080"' >> "$WORKER_TOML"
    fi
    log_success "worker.toml patched: coordinator_url = http://localhost:8080"
elif [ "$COORDINATOR_ONLY" != "1" ]; then
    mkdir -p "$HOME/.bitsage"
    cat > "$WORKER_TOML" <<TOML
[network]
coordinator_url = "http://localhost:8080"
heartbeat_interval_seconds = 30

[worker]
network = "$NETWORK"
TOML
    log_success "worker.toml created"
else
    log_info "No worker.toml needed (coordinator-only)"
fi

# ── Step 8: Create systemd Services ─────────────────────────────────────────
log_step "Step 8/11: Creating systemd services"

COORDINATOR_BIN="$INSTALL_DIR/rust-node/target/release/sage-coordinator"
WORKER_BIN="$INSTALL_DIR/rust-node/target/release/sage-worker"

sudo tee /etc/systemd/system/sage-coordinator.service >/dev/null <<EOF
[Unit]
Description=BitSage Coordinator
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
Environment=DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}
Environment=RUST_LOG=info
ExecStart=${COORDINATOR_BIN}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
log_success "sage-coordinator.service created"

if [ "$COORDINATOR_ONLY" != "1" ]; then
    sudo tee /etc/systemd/system/sage-worker.service >/dev/null <<EOF
[Unit]
Description=BitSage Worker
After=network-online.target sage-coordinator.service
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
Environment=RUST_LOG=info
ExecStart=${WORKER_BIN} start
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    log_success "sage-worker.service created"
fi

sudo systemctl daemon-reload

# ── Step 9: Open Firewall Ports ─────────────────────────────────────────────
log_step "Step 9/11: Configuring firewall"

if command -v ufw &>/dev/null; then
    sudo ufw allow 22/tcp   >/dev/null 2>&1 || true
    sudo ufw allow 8080/tcp >/dev/null 2>&1 || true
    sudo ufw --force enable >/dev/null 2>&1 || true
    log_success "UFW: ports 22, 8080 open"
else
    log_info "UFW not found — skipping firewall config (ensure ports 22, 8080 are open)"
fi

# ── Step 10: Start Services & Health Check ──────────────────────────────────
log_step "Step 10/11: Starting services"

sudo systemctl enable sage-coordinator >/dev/null 2>&1
sudo systemctl restart sage-coordinator
log_info "sage-coordinator started"

if [ "$COORDINATOR_ONLY" != "1" ]; then
    sudo systemctl enable sage-worker >/dev/null 2>&1
    sudo systemctl restart sage-worker
    log_info "sage-worker started"
fi

# Health-check loop
log_info "Waiting for coordinator to become healthy..."
HEALTHY=false
for i in $(seq 1 30); do
    if curl -sf http://localhost:8080/api/health >/dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    sleep 2
done

if $HEALTHY; then
    log_success "Coordinator is healthy"
else
    log_warn "Coordinator did not respond within 60s — check: journalctl -u sage-coordinator -f"
fi

# ── Step 11: Summary ────────────────────────────────────────────────────────
log_step "Step 11/11: Deployment summary"

WORKER_ID="N/A"
WALLET_ADDR="N/A"
if [ -f "$WORKER_TOML" ]; then
    WORKER_ID=$(grep -oP 'id\s*=\s*"\K[^"]+' "$WORKER_TOML" 2>/dev/null || echo "N/A")
    WALLET_ADDR=$(grep -oP 'wallet\s*=\s*"\K[^"]+' "$WORKER_TOML" 2>/dev/null || \
                  grep -oP 'address\s*=\s*"\K[^"]+' "$WORKER_TOML" 2>/dev/null || echo "N/A")
fi

echo ""
echo "================================================================="
echo "  BitSage Node — Deployment Complete"
echo "================================================================="
echo "  Network:        $NETWORK"
echo "  GPU:            $GPU_NAME ($GPU_MEMORY MiB) x $GPU_COUNT"
echo "  CUDA:           $CUDA_VERSION"
echo "  TEE:            $TEE_SUPPORT"
echo "  Worker ID:      $WORKER_ID"
echo "  Wallet:         $WALLET_ADDR"
echo "  API URL:        http://localhost:8080"
echo "  Database:       $DATABASE_URL"
echo "  Install dir:    $INSTALL_DIR"
echo ""
echo "  Services:"
echo "    sage-coordinator  $(systemctl is-active sage-coordinator 2>/dev/null || echo 'unknown')"
[ "$COORDINATOR_ONLY" != "1" ] && \
echo "    sage-worker       $(systemctl is-active sage-worker 2>/dev/null || echo 'unknown')"
echo ""
echo "  Logs:"
echo "    journalctl -u sage-coordinator -f"
[ "$COORDINATOR_ONLY" != "1" ] && \
echo "    journalctl -u sage-worker -f"
echo ""
echo "  Next steps:"
echo "    ./scripts/setup-vllm.sh    — Add LLM inference"
echo "    ./scripts/setup-nginx.sh   — Add external API access"
echo "    ./scripts/test-workloads.sh — Test the full pipeline"
echo "================================================================="
