#!/usr/bin/env bash
# mainnet-preflight.sh — Validate mainnet readiness
set -uo pipefail

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" = "pass" ]; then
        echo "  ✓ ${label}"
        ((PASS++))
    elif [ "$result" = "warn" ]; then
        echo "  ⚠ ${label}"
        ((WARN++))
    else
        echo "  ✗ ${label}"
        ((FAIL++))
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  BitSage Mainnet Preflight Checklist"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Load .env if present
if [ -f .env ]; then
    set -a; source .env; set +a
fi

echo "Security"
echo "───────────────────────────────────────────────────────────────"

# JWT_SECRET
if [ -n "${JWT_SECRET:-}" ] && [ ${#JWT_SECRET} -ge 32 ]; then
    check "JWT_SECRET set (${#JWT_SECRET} chars)" "pass"
else
    check "JWT_SECRET missing or too short (need ≥32 chars)" "fail"
fi

# KEYSTORE_PASSWORD
if [ -n "${KEYSTORE_PASSWORD:-}" ] && [ ${#KEYSTORE_PASSWORD} -ge 12 ]; then
    check "KEYSTORE_PASSWORD set" "pass"
else
    check "KEYSTORE_PASSWORD missing or too short" "fail"
fi

# SIGNER_PRIVATE_KEY should NOT be set in production
if [ -n "${SIGNER_PRIVATE_KEY:-}" ]; then
    check "SIGNER_PRIVATE_KEY is set (use keystore instead)" "warn"
else
    check "SIGNER_PRIVATE_KEY not exposed" "pass"
fi

# Database password check
if [ -n "${DATABASE_URL:-}" ]; then
    if echo "$DATABASE_URL" | grep -qE '://[^:]+:bitsage@|://[^:]+:password@|://[^:]+:postgres@'; then
        check "DATABASE_URL uses weak password" "fail"
    else
        check "DATABASE_URL password" "pass"
    fi
else
    check "DATABASE_URL not set" "fail"
fi

echo ""
echo "Environment"
echo "───────────────────────────────────────────────────────────────"

# BITSAGE_ENV
if [ "${BITSAGE_ENV:-}" = "production" ] || [ "${BITSAGE_ENV:-}" = "mainnet" ]; then
    check "BITSAGE_ENV=${BITSAGE_ENV}" "pass"
else
    check "BITSAGE_ENV=${BITSAGE_ENV:-unset} (should be production/mainnet)" "fail"
fi

# STARKNET_NETWORK
if [ "${STARKNET_NETWORK:-}" = "mainnet" ]; then
    check "STARKNET_NETWORK=mainnet" "pass"
else
    check "STARKNET_NETWORK=${STARKNET_NETWORK:-unset} (should be mainnet)" "warn"
fi

# REQUIRE_STAKE
if [ "${REQUIRE_STAKE:-}" = "true" ]; then
    check "REQUIRE_STAKE=true" "pass"
else
    check "REQUIRE_STAKE=${REQUIRE_STAKE:-unset} (should be true)" "fail"
fi

echo ""
echo "TLS / Certificates"
echo "───────────────────────────────────────────────────────────────"

if [ "${ENABLE_TLS:-}" = "true" ]; then
    check "ENABLE_TLS=true" "pass"

    CERT="${TLS_CERT_PATH:-}"
    if [ -f "$CERT" ]; then
        EXPIRY=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2)
        if [ -n "$EXPIRY" ]; then
            EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null || echo 0)
            NOW_EPOCH=$(date +%s)
            DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
            if [ "$DAYS_LEFT" -gt 30 ]; then
                check "TLS cert valid (${DAYS_LEFT} days remaining)" "pass"
            elif [ "$DAYS_LEFT" -gt 0 ]; then
                check "TLS cert expiring soon (${DAYS_LEFT} days)" "warn"
            else
                check "TLS cert EXPIRED" "fail"
            fi
        else
            check "TLS cert exists but couldn't parse expiry" "warn"
        fi
    else
        check "TLS cert file not found: ${CERT:-unset}" "fail"
    fi
else
    check "ENABLE_TLS not enabled" "fail"
fi

echo ""
echo "Deployer / On-Chain"
echo "───────────────────────────────────────────────────────────────"

DEPLOYER="${DEPLOYER_ADDRESS:-}"
if [ -n "$DEPLOYER" ]; then
    check "DEPLOYER_ADDRESS set" "pass"

    # Check ETH balance via RPC
    RPC="${STARKNET_RPC_URL:-https://starknet-sepolia-rpc.publicnode.com}"
    BALANCE_RESP=$(curl -sf -X POST "$RPC" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"starknet_call\",\"params\":[{\"contract_address\":\"0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7\",\"entry_point_selector\":\"0x2e4263afad30923c891518314c3c95dbe830a16874e8abc5777a9a20b54c76e\",\"calldata\":[\"${DEPLOYER}\"]},\"latest\"],\"id\":1}" 2>/dev/null || echo "")

    if [ -n "$BALANCE_RESP" ]; then
        HEX_BAL=$(echo "$BALANCE_RESP" | grep -o '"0x[0-9a-fA-F]*"' | head -1 | tr -d '"')
        if [ -n "$HEX_BAL" ] && [ "$HEX_BAL" != "0x0" ]; then
            check "Deployer has ETH balance (${HEX_BAL})" "pass"
        else
            check "Deployer has zero ETH — fund before mainnet" "fail"
        fi
    else
        check "Could not query deployer balance (RPC error)" "warn"
    fi
else
    check "DEPLOYER_ADDRESS not set" "fail"
fi

echo ""
echo "Contracts"
echo "───────────────────────────────────────────────────────────────"

for var in SAGE_TOKEN_ADDRESS JOB_MANAGER_ADDRESS STAKING_CONTRACT_ADDRESS PROOF_VERIFIER_ADDRESS; do
    val="${!var:-}"
    if [ -n "$val" ] && [ "$val" != "0x0" ]; then
        check "${var} set" "pass"
    else
        check "${var} missing" "fail"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed, ${WARN} warnings"
echo "═══════════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo "  STATUS: NOT READY for mainnet"
    exit 1
else
    echo "  STATUS: Ready for mainnet"
    exit 0
fi
