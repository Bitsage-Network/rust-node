#!/bin/bash
# Check TEE (Trusted Execution Environment) Support
# Detects Intel TDX, AMD SEV-SNP, and NVIDIA H100 Confidential Computing

echo "🔍 Checking TEE Support..."
echo ""

# Check CPU Vendor
CPU_VENDOR=$(lscpu | grep "Vendor ID" | awk '{print $3}')
echo "📊 CPU Vendor: $CPU_VENDOR"

# Check for Intel TDX
if [ "$CPU_VENDOR" == "GenuineIntel" ]; then
    echo "🔍 Checking for Intel TDX..."
    if dmesg 2>/dev/null | grep -iq "tdx"; then
        echo "   ✅ Intel TDX detected"
        TDX_SUPPORT=true
    else
        echo "   ❌ Intel TDX not detected"
        TDX_SUPPORT=false
    fi
    
    # Check for SGX as fallback
    if [ -e /dev/sgx_enclave ]; then
        echo "   ✅ Intel SGX detected"
        SGX_SUPPORT=true
    else
        echo "   ❌ Intel SGX not detected"
        SGX_SUPPORT=false
    fi
fi

# Check for AMD SEV
if [ "$CPU_VENDOR" == "AuthenticAMD" ]; then
    echo "🔍 Checking for AMD SEV-SNP..."
    if dmesg 2>/dev/null | grep -iq "sev"; then
        echo "   ✅ AMD SEV detected"
        SEV_SUPPORT=true
    else
        echo "   ❌ AMD SEV not detected"
        SEV_SUPPORT=false
    fi
fi

# Check GPU
echo ""
echo "🎮 GPU Information:"
if command -v nvidia-smi &> /dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n1)
    GPU_DRIVER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1)
    GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader | head -n1)
    
    echo "   GPU: $GPU_NAME"
    echo "   Driver: $GPU_DRIVER"
    echo "   Memory: $GPU_MEMORY"
    
    # Check for H100/B200 (Hopper/Blackwell with TEE support)
    if echo "$GPU_NAME" | grep -iq "H100\|B200\|B300"; then
        echo "   ✅ GPU supports Confidential Computing (Hopper/Blackwell)"
        GPU_TEE_SUPPORT=true
        
        # Check for CUDA Confidential Computing toolkit
        if command -v cuda-cc &> /dev/null; then
            echo "   ✅ NVIDIA Confidential Computing toolkit detected"
        else
            echo "   ⚠️  NVIDIA Confidential Computing toolkit not found"
            echo "      Install from: https://developer.nvidia.com/hopper-confidential-computing"
        fi
    else
        echo "   ❌ GPU does not support hardware TEE (A100/consumer GPU)"
        echo "      Note: Can still use CPU TEE for data, GPU for compute"
        GPU_TEE_SUPPORT=false
    fi
else
    echo "   ❌ NVIDIA GPU not detected"
    GPU_TEE_SUPPORT=false
fi

# Summary
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "📊 TEE Support Summary"
echo "═══════════════════════════════════════════════════════════"

# Determine overall TEE type
if [ "$GPU_TEE_SUPPORT" == "true" ] && [ "$TDX_SUPPORT" == "true" -o "$SEV_SUPPORT" == "true" -o "$SGX_SUPPORT" == "true" ]; then
    TEE_TYPE="Full"
    echo "✅ Full TEE Support (CPU + GPU)"
    echo "   Recommended for: Maximum confidentiality"
elif [ "$TDX_SUPPORT" == "true" -o "$SEV_SUPPORT" == "true" -o "$SGX_SUPPORT" == "true" ]; then
    TEE_TYPE="CpuOnly"
    echo "⚠️  CPU TEE Only"
    echo "   Recommended for: Data pipelines, SQL jobs"
    echo "   Note: GPU compute unprotected (use optimistic verification)"
else
    TEE_TYPE="None"
    echo "❌ No TEE Support"
    echo "   Recommended for: Testing, non-confidential workloads"
    echo "   Note: Use optimistic verification for all jobs"
fi

echo ""
echo "🔧 Recommended Configuration:"
echo "   tee_type = \"$TEE_TYPE\""
echo "   gpu_tee_support = $([ "$GPU_TEE_SUPPORT" == "true" ] && echo "true" || echo "false")"
echo ""

# Export for scripts
export TEE_TYPE
export GPU_TEE_SUPPORT

# Additional recommendations
echo "💡 Next Steps:"
if [ "$TEE_TYPE" == "Full" ]; then
    echo "   ✅ You're ready for confidential compute!"
    echo "   - Enable TEE in worker config"
    echo "   - Test attestation generation"
    echo "   - Submit confidential jobs"
elif [ "$TEE_TYPE" == "CpuOnly" ]; then
    echo "   ⚠️  Hybrid security model recommended:"
    echo "   - Use CPU TEE for data encryption/decryption"
    echo "   - Use GPU for accelerated compute"
    echo "   - Enable optimistic verification for GPU jobs"
else
    echo "   ❌ No hardware TEE available"
    echo "   - Use optimistic verification with fraud proofs"
    echo "   - Consider upgrading to H100/TDX-capable instance"
    echo "   - Great for testing and development!"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"

