#!/bin/bash
# =============================================================================
# BitSage — vLLM Inference Backend Setup
# =============================================================================
# Installs vLLM, downloads a model, creates a systemd service.
# After running, sage-worker auto-detects vLLM at localhost:8000.
#
# Usage:
#   ./scripts/setup-vllm.sh
#   VLLM_MODEL=meta-llama/Llama-3.1-8B-Instruct ./scripts/setup-vllm.sh
# =============================================================================

set -euo pipefail

MODEL="${VLLM_MODEL:-Qwen/Qwen2.5-7B-Instruct}"
VLLM_HOST="${VLLM_HOST:-0.0.0.0}"
VLLM_PORT="${VLLM_PORT:-8000}"
MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-4096}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERR]${NC}  $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }

echo ""
echo "================================================================="
echo "  BitSage — vLLM Inference Backend Setup"
echo "  Model: $MODEL | Port: $VLLM_PORT"
echo "================================================================="
echo ""

# ── Step 1: Python ──────────────────────────────────────────────────────────
log_step "Step 1/5: Checking Python"

if ! command -v python3 &>/dev/null; then
    log_info "Installing Python 3..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-pip python3-venv >/dev/null 2>&1
fi

PY_VERSION=$(python3 --version 2>&1)
log_success "Python: $PY_VERSION"

# ── Step 2: Install vLLM ────────────────────────────────────────────────────
log_step "Step 2/5: Installing vLLM"

if python3 -c "import vllm" 2>/dev/null; then
    VLLM_VER=$(python3 -c "import vllm; print(vllm.__version__)" 2>/dev/null || echo "unknown")
    log_info "vLLM already installed: $VLLM_VER"
else
    log_info "Installing vLLM (this may take a few minutes)..."
    pip3 install --upgrade pip >/dev/null 2>&1
    pip3 install vllm 2>&1 | tail -n3
    log_success "vLLM installed"
fi

# ── Step 3: Create systemd Service ──────────────────────────────────────────
log_step "Step 3/5: Creating vLLM systemd service"

# Determine GPU memory for tensor parallelism
GPU_COUNT=$(nvidia-smi -L 2>/dev/null | wc -l || echo "1")
TP_ARG=""
if [ "$GPU_COUNT" -gt 1 ]; then
    TP_ARG="--tensor-parallel-size $GPU_COUNT"
    log_info "Multi-GPU detected: tensor parallelism = $GPU_COUNT"
fi

VLLM_BIN=$(which vllm 2>/dev/null || echo "$HOME/.local/bin/vllm")

sudo tee /etc/systemd/system/vllm.service >/dev/null <<EOF
[Unit]
Description=vLLM Inference Server ($MODEL)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
ExecStart=${VLLM_BIN} serve ${MODEL} --host ${VLLM_HOST} --port ${VLLM_PORT} --max-model-len ${MAX_MODEL_LEN} ${TP_ARG}
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vllm >/dev/null 2>&1
sudo systemctl restart vllm
log_success "vllm.service created and started"

# ── Step 4: Restart sage-worker ─────────────────────────────────────────────
log_step "Step 4/5: Restarting sage-worker"

if systemctl is-active sage-worker >/dev/null 2>&1; then
    sudo systemctl restart sage-worker
    log_success "sage-worker restarted (will auto-detect vLLM at localhost:$VLLM_PORT)"
else
    log_warn "sage-worker is not running — start it after running bitsage-deploy.sh"
fi

# ── Step 5: Verify ──────────────────────────────────────────────────────────
log_step "Step 5/5: Verifying vLLM"

log_info "Waiting for vLLM to load model (this can take a while for large models)..."
READY=false
for i in $(seq 1 90); do
    if curl -sf "http://localhost:${VLLM_PORT}/v1/models" >/dev/null 2>&1; then
        READY=true
        break
    fi
    sleep 5
done

if $READY; then
    MODELS=$(curl -s "http://localhost:${VLLM_PORT}/v1/models" | jq -r '.data[].id' 2>/dev/null || echo "$MODEL")
    log_success "vLLM is serving: $MODELS"
else
    log_warn "vLLM not responding yet — check: journalctl -u vllm -f"
fi

echo ""
echo "================================================================="
echo "  vLLM Setup Complete"
echo "  Model:    $MODEL"
echo "  Endpoint: http://localhost:${VLLM_PORT}/v1"
echo "  Status:   $(systemctl is-active vllm 2>/dev/null || echo 'unknown')"
echo ""
echo "  Test: curl http://localhost:${VLLM_PORT}/v1/models"
echo "  Logs: journalctl -u vllm -f"
echo "================================================================="
