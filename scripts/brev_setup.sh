#!/bin/bash
# BitSage Worker Setup Script for NVIDIA Brev
# This script automatically sets up a BitSage worker on Brev cloud instances

set -e

echo "🚀 Starting BitSage Worker Setup..."

# Detect GPU
GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n1)
GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -n1)
GPU_COUNT=$(nvidia-smi --query-gpu=count --format=csv,noheader | wc -l)

echo "✅ Detected GPU: $GPU_NAME ($GPU_MEMORY MB)"

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "✅ Rust already installed"
fi

# Clone BitSage (if not already present)
if [ ! -d "$HOME/rust-node" ]; then
    echo "📥 Cloning BitSage Network..."
    cd $HOME
    git clone https://github.com/Bitsage-Network/rust-node.git
else
    echo "✅ BitSage already cloned"
    cd $HOME/rust-node
    git pull
fi

cd $HOME/rust-node

# Build worker
echo "🔨 Building BitSage worker (this may take 5-10 minutes)..."
cargo build --release --bin ciro-worker

# Detect TEE support
TEE_TYPE="None"
if [ "$GPU_NAME" == *"H100"* ]; then
    # Check for Intel TDX
    if dmesg 2>/dev/null | grep -iq "tdx"; then
        TEE_TYPE="Full"
        echo "✅ Intel TDX detected"
    else
        TEE_TYPE="CpuOnly"
        echo "⚠️  H100 found but no TDX detected (CPU TEE only)"
    fi
elif [ "$GPU_NAME" == *"A100"* ]; then
    TEE_TYPE="CpuOnly"
    echo "ℹ️  A100 found (CPU TEE only, no GPU TEE)"
else
    echo "ℹ️  Consumer GPU detected (no TEE)"
fi

# Create config directory
mkdir -p config

# Generate worker config
WORKER_ID="brev-worker-$(hostname | md5sum | head -c 8)"
GPU_MEMORY_GB=$((GPU_MEMORY / 1024))

cat > config/brev_worker.toml <<EOF
# BitSage Worker Configuration (Auto-generated for Brev)
# Generated on: $(date)
# GPU: $GPU_NAME
# TEE: $TEE_TYPE

[worker]
id = "$WORKER_ID"
coordinator_address = "127.0.0.1:8080"  # Change to your coordinator URL
wallet_address = "0x0"  # Optional: Add your Starknet wallet

[capabilities]
gpu_count = $GPU_COUNT
gpu_memory_gb = $GPU_MEMORY_GB
gpu_model = "$GPU_NAME"
tee_type = "$TEE_TYPE"
gpu_tee_support = $([ "$TEE_TYPE" == "Full" ] && echo "true" || echo "false")
cpu_cores = $(nproc)
ram_gb = $(($(free -g | awk '/^Mem:/{print $2}')))
disk_gb = $(($(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')))
max_concurrent_jobs = 4

[network]
listen_port = 8081
enable_p2p = true

[security]
enable_tee = $([ "$TEE_TYPE" != "None" ] && echo "true" || echo "false")
verify_attestations = true

[performance]
worker_threads = $(nproc)
max_memory_mb = $((GPU_MEMORY - 2048))  # Reserve 2GB for system
EOF

echo "✅ Worker config created: config/brev_worker.toml"

# Create start script
cat > start_worker.sh <<'SCRIPT'
#!/bin/bash
cd $HOME/rust-node

# Update coordinator address if provided
if [ -n "$COORDINATOR_URL" ]; then
    sed -i "s|coordinator_address = .*|coordinator_address = \"$COORDINATOR_URL\"|" config/brev_worker.toml
    echo "✅ Updated coordinator URL to: $COORDINATOR_URL"
fi

# Start worker with logging
echo "🚀 Starting BitSage Worker..."
RUST_LOG=info ./target/release/ciro-worker --config config/brev_worker.toml 2>&1 | tee worker.log
SCRIPT

chmod +x start_worker.sh

# Create stop script
cat > stop_worker.sh <<'SCRIPT'
#!/bin/bash
echo "🛑 Stopping BitSage Worker..."
pkill -f ciro-worker
echo "✅ Worker stopped"
SCRIPT

chmod +x stop_worker.sh

# Print summary
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "✅ BitSage Worker Setup Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📊 Worker Details:"
echo "   ID: $WORKER_ID"
echo "   GPU: $GPU_NAME ($GPU_MEMORY_GB GB)"
echo "   GPU Count: $GPU_COUNT"
echo "   TEE Type: $TEE_TYPE"
echo "   CPU Cores: $(nproc)"
echo "   RAM: $(($(free -g | awk '/^Mem:/{print $2}'))) GB"
echo ""
echo "📝 Next Steps:"
echo ""
echo "   1. Update coordinator URL:"
echo "      export COORDINATOR_URL=\"your-coordinator:8080\""
echo "      ./start_worker.sh"
echo ""
echo "   2. Or manually edit config:"
echo "      nano config/brev_worker.toml"
echo ""
echo "   3. Start the worker:"
echo "      ./start_worker.sh"
echo ""
echo "   4. Monitor logs:"
echo "      tail -f worker.log"
echo ""
echo "   5. Stop the worker:"
echo "      ./stop_worker.sh"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "💡 Tips:"
echo "   - Test locally first: COORDINATOR_URL=\"127.0.0.1:8080\""
echo "   - For production: Use your public coordinator URL"
echo "   - Monitor GPU: watch -n1 nvidia-smi"
echo "   - Check status: curl http://localhost:8081/health"
echo ""
echo "📞 Support:"
echo "   - Discord: https://discord.gg/QAXDpa7F5K"
echo "   - GitHub: https://github.com/Bitsage-Network/rust-node/issues"
echo ""

