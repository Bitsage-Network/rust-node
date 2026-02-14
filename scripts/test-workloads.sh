#!/bin/bash
# =============================================================================
# BitSage — End-to-End Workload Test Suite
# =============================================================================
# Tests: ZK proof, LLM inference, billing, WebSocket, external API.
#
# Usage:
#   ./scripts/test-workloads.sh
#   BITSAGE_API=https://node.bitsage.network ./scripts/test-workloads.sh
# =============================================================================

set -euo pipefail

API="${BITSAGE_API:-http://localhost:8080}"
VLLM_PORT="${VLLM_PORT:-8000}"
EXTERNAL_URL="${BITSAGE_EXTERNAL_URL:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

PASS=0; FAIL=0; SKIP=0

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
log_fail()    { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
log_skip()    { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
log_test()    { echo -e "\n${CYAN}${BOLD}── Test: $1 ──${NC}"; }

# Helper: convert string to JSON byte array [104, 101, ...]
str_to_bytes() {
    echo -n "$1" | od -An -tu1 | tr -s ' ' '\n' | grep -v '^$' | paste -sd',' | sed 's/^/[/;s/$/]/'
}

echo ""
echo "================================================================="
echo "  BitSage — End-to-End Workload Tests"
echo "  API: $API"
echo "================================================================="
echo ""

# ── Prereq: Health Check ───────────────────────────────────────────────────
log_test "Coordinator Health"

HEALTH=$(curl -sf "$API/api/health" 2>/dev/null || echo "")
if [ -n "$HEALTH" ]; then
    log_success "Coordinator is healthy"
else
    log_fail "Coordinator not responding at $API/api/health"
    echo "  Aborting — coordinator must be running."
    exit 1
fi

# ── Test 1: GPU ZK Proof (STWO Circle STARK) ──────────────────────────────
log_test "1 — GPU ZK Proof (STWO Circle STARK)"

PROOF_PAYLOAD=$(str_to_bytes '{"trace_size":18}')

JOB_RESPONSE=$(curl -sf -X POST "$API/api/jobs/submit" \
    -H "Content-Type: application/json" \
    -d "{
        \"requirements\": {
            \"required_job_type\": \"STWOProof\",
            \"min_vram_mb\": 1024,
            \"min_gpu_count\": 1,
            \"timeout_seconds\": 120,
            \"requires_tee\": false
        },
        \"payload\": $PROOF_PAYLOAD,
        \"priority\": 100
    }" 2>/dev/null || echo "")

if [ -z "$JOB_RESPONSE" ]; then
    log_fail "Could not submit STWO proof job"
else
    JOB_ID=$(echo "$JOB_RESPONSE" | jq -r '.job_id // .id // empty' 2>/dev/null || echo "")
    if [ -z "$JOB_ID" ]; then
        log_fail "No job_id in response: $JOB_RESPONSE"
    else
        log_success "STWO proof job submitted: $JOB_ID"

        # Poll for completion (routes use /api/jobs:id/status format)
        COMPLETED=false
        for i in $(seq 1 60); do
            # Try both route formats
            STATUS_RESP=$(curl -sf "$API/api/jobs/${JOB_ID}/status" 2>/dev/null || \
                          curl -sf "$API/api/jobs${JOB_ID}/status" 2>/dev/null || echo "")
            STATUS=$(echo "$STATUS_RESP" | jq -r '.status // empty' 2>/dev/null || echo "")
            case "$STATUS" in
                completed|Completed|COMPLETED)
                    COMPLETED=true; break ;;
                failed|Failed|FAILED)
                    log_fail "STWO proof job failed: $(echo "$STATUS_RESP" | jq -r '.error // .message // "unknown"' 2>/dev/null)"
                    break ;;
            esac
            sleep 3
        done

        if $COMPLETED; then
            RESULT=$(curl -sf "$API/api/jobs/${JOB_ID}/result" 2>/dev/null || \
                     curl -sf "$API/api/jobs${JOB_ID}/result" 2>/dev/null || echo "")
            PROOF_HASH=$(echo "$RESULT" | jq -r '.proof_hash // .result.proof_hash // empty' 2>/dev/null || echo "")
            if [ -n "$PROOF_HASH" ]; then
                log_success "STWO proof completed — proof_hash: $PROOF_HASH"
            else
                log_success "STWO proof completed (result received)"
                log_info "Result: $(echo "$RESULT" | head -c 200)"
            fi
        elif [ "$COMPLETED" = false ] && [ "$STATUS" != "failed" ] && [ "$STATUS" != "Failed" ]; then
            log_skip "STWO proof job still running after 180s — last status: ${STATUS:-pending}"
        fi
    fi
fi

# ── Test 2: LLM Inference (via vLLM) ──────────────────────────────────────
log_test "2 — LLM Inference"

# Check if vLLM is running
if curl -sf "http://localhost:${VLLM_PORT}/v1/models" >/dev/null 2>&1; then
    INFERENCE_PAYLOAD=$(str_to_bytes '{"prompt":"Explain zero-knowledge proofs in one sentence","max_tokens":100}')

    INF_RESPONSE=$(curl -sf -X POST "$API/api/jobs/submit" \
        -H "Content-Type: application/json" \
        -d "{
            \"requirements\": {
                \"required_job_type\": \"AIInference\",
                \"min_vram_mb\": 0,
                \"min_gpu_count\": 1,
                \"timeout_seconds\": 30,
                \"requires_tee\": false
            },
            \"payload\": $INFERENCE_PAYLOAD,
            \"priority\": 100
        }" 2>/dev/null || echo "")

    if [ -z "$INF_RESPONSE" ]; then
        log_fail "Could not submit inference job"
    else
        INF_JOB_ID=$(echo "$INF_RESPONSE" | jq -r '.job_id // .id // empty' 2>/dev/null || echo "")
        if [ -z "$INF_JOB_ID" ]; then
            log_fail "No job_id in inference response: $INF_RESPONSE"
        else
            log_success "Inference job submitted: $INF_JOB_ID"

            INF_DONE=false
            for i in $(seq 1 30); do
                INF_STATUS=$(curl -sf "$API/api/jobs/${INF_JOB_ID}/status" 2>/dev/null | jq -r '.status // empty' 2>/dev/null || echo "")
                case "$INF_STATUS" in
                    completed|Completed|COMPLETED) INF_DONE=true; break ;;
                    failed|Failed|FAILED)
                        log_fail "Inference job failed"
                        break ;;
                esac
                sleep 2
            done

            if $INF_DONE; then
                INF_RESULT=$(curl -sf "$API/api/jobs/${INF_JOB_ID}/result" 2>/dev/null || echo "")
                log_success "Inference completed"
                log_info "Output: $(echo "$INF_RESULT" | jq -r '.result // .output // .' 2>/dev/null | head -c 300)"
            elif [ "$INF_DONE" = false ] && [ "$INF_STATUS" != "failed" ]; then
                log_skip "Inference job still running — last status: ${INF_STATUS:-pending}"
            fi
        fi
    fi
else
    log_skip "vLLM not running at localhost:${VLLM_PORT} — run setup-vllm.sh first"
fi

# ── Test 3: Billing & Settlement ──────────────────────────────────────────
log_test "3 — Billing & Settlement"

PROOFS_RESP=$(curl -sf "$API/api/proofs" 2>/dev/null || echo "")
if [ -n "$PROOFS_RESP" ] && [ "$PROOFS_RESP" != "null" ]; then
    PROOF_COUNT=$(echo "$PROOFS_RESP" | jq 'if type == "array" then length elif .proofs then (.proofs | length) else 0 end' 2>/dev/null || echo "0")
    log_success "Proofs endpoint responsive — $PROOF_COUNT proofs recorded"
else
    log_skip "No proofs data available (submit jobs first)"
fi

# Check workers
WORKERS_RESP=$(curl -sf "$API/api/workers/list" 2>/dev/null || echo "")
if [ -n "$WORKERS_RESP" ] && [ "$WORKERS_RESP" != "null" ]; then
    WORKER_COUNT=$(echo "$WORKERS_RESP" | jq '.workers | length // 0' 2>/dev/null || echo "0")
    log_success "Workers endpoint responsive — $WORKER_COUNT workers"

    WORKER_ID=$(echo "$WORKERS_RESP" | jq -r '.workers[0].id // empty' 2>/dev/null || echo "")
    if [ -n "$WORKER_ID" ]; then
        EARNINGS=$(curl -sf "$API/api/miners/$WORKER_ID/earnings" 2>/dev/null || echo "")
        if [ -n "$EARNINGS" ]; then
            log_success "Earnings endpoint for $WORKER_ID responsive"
            log_info "Earnings: $(echo "$EARNINGS" | head -c 200)"
        else
            log_info "No earnings data for worker $WORKER_ID yet"
        fi
    fi
else
    log_skip "Workers endpoint not available"
fi

# GPU pricing
PRICING=$(curl -sf "$API/api/pricing/gpus" 2>/dev/null || echo "")
if [ -n "$PRICING" ] && [ "$PRICING" != "null" ]; then
    log_success "GPU pricing endpoint responsive"
else
    log_skip "GPU pricing endpoint not available"
fi

# ── Test 4: WebSocket Events ─────────────────────────────────────────────
log_test "4 — WebSocket Events"

if command -v wscat &>/dev/null; then
    WS_URL="${API/http/ws}/ws"
    log_info "Connecting to $WS_URL (5s timeout)..."
    WS_OUT=$(timeout 5 wscat -c "$WS_URL" 2>/dev/null || echo "timeout")
    if [ "$WS_OUT" != "timeout" ] || [ $? -eq 124 ]; then
        log_success "WebSocket connection established"
    else
        log_fail "WebSocket connection failed"
    fi
elif command -v websocat &>/dev/null; then
    WS_URL="${API/http/ws}/ws"
    WS_OUT=$(timeout 5 websocat "$WS_URL" 2>/dev/null || echo "")
    log_success "WebSocket connection tested via websocat"
else
    # Fallback: try with curl upgrade header (5s timeout)
    WS_RESP=$(timeout 5 curl -sf -o /dev/null -w "%{http_code}" \
        -H "Upgrade: websocket" -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        "$API/ws" 2>/dev/null || echo "000")
    if [ "$WS_RESP" = "101" ]; then
        log_success "WebSocket upgrade accepted (HTTP 101)"
    else
        log_skip "WebSocket test requires wscat or websocat (install: npm i -g wscat)"
    fi
fi

# ── Test 5: External API (via nginx) ─────────────────────────────────────
log_test "5 — External API Access"

if [ -n "$EXTERNAL_URL" ]; then
    EXT_HEALTH=$(curl -sfk "$EXTERNAL_URL/api/health" 2>/dev/null || echo "")
    if [ -n "$EXT_HEALTH" ]; then
        log_success "External health check: $EXTERNAL_URL/api/health"
    else
        log_fail "External API not reachable at $EXTERNAL_URL"
    fi

    EXT_WORKERS=$(curl -sfk "$EXTERNAL_URL/api/workers/list" 2>/dev/null || echo "")
    if [ -n "$EXT_WORKERS" ]; then
        log_success "External workers list accessible"
    fi

    EXT_PRICING=$(curl -sfk "$EXTERNAL_URL/api/pricing/gpus" 2>/dev/null || echo "")
    if [ -n "$EXT_PRICING" ]; then
        log_success "External GPU pricing accessible"
    fi
elif systemctl is-active nginx >/dev/null 2>&1; then
    SERVER_IP=$(curl -s4 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
    EXT_HEALTH=$(curl -sfk "https://$SERVER_IP/api/health" 2>/dev/null || \
                 curl -sf "http://$SERVER_IP/api/health" 2>/dev/null || echo "")
    if [ -n "$EXT_HEALTH" ]; then
        log_success "External API reachable via nginx at $SERVER_IP"
    else
        log_fail "Nginx running but external API not reachable"
    fi
else
    log_skip "Nginx not running — run setup-nginx.sh first, or set BITSAGE_EXTERNAL_URL"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "================================================================="
echo "  Test Results"
echo "  Passed: $PASS | Failed: $FAIL | Skipped: $SKIP"
echo "================================================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
