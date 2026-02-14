#!/usr/bin/env bash
# load-test.sh — Submit 20 concurrent jobs and monitor completion
set -euo pipefail

API="${BITSAGE_API:-http://localhost:8080}"
TOTAL_STWO=10
TOTAL_AI=10
SPACING_MS=200
POLL_INTERVAL=2
JOB_IDS=()
START_TIME=$(date +%s)

# Helper: convert string to JSON byte array [104, 101, ...]
str_to_bytes() {
    echo -n "$1" | od -An -tu1 | tr -s ' ' '\n' | grep -v '^$' | paste -sd',' | sed 's/^/[/;s/$/]/'
}

echo "═══════════════════════════════════════════════════════════════"
echo "  BitSage Load Test — ${TOTAL_STWO} STWO + ${TOTAL_AI} AI jobs"
echo "  API: ${API}"
echo "═══════════════════════════════════════════════════════════════"

submit_job() {
    local job_type="$1"
    local idx="$2"
    local payload

    if [ "$job_type" = "stwo" ]; then
        local stwo_payload
        stwo_payload=$(str_to_bytes "{\"trace_size\":18,\"test_id\":\"load-stwo-${idx}\"}")
        payload="{
            \"requirements\": {
                \"required_job_type\": \"STWOProof\",
                \"min_vram_mb\": 1024,
                \"min_gpu_count\": 1,
                \"timeout_seconds\": 120,
                \"requires_tee\": false
            },
            \"payload\": ${stwo_payload},
            \"priority\": 100
        }"
    else
        local ai_payload
        ai_payload=$(str_to_bytes "{\"prompt\":\"Load test ${idx}: Explain ZK proofs.\",\"max_tokens\":64}")
        payload="{
            \"requirements\": {
                \"required_job_type\": \"AIInference\",
                \"min_vram_mb\": 0,
                \"min_gpu_count\": 0,
                \"timeout_seconds\": 60,
                \"requires_tee\": false
            },
            \"payload\": ${ai_payload},
            \"priority\": 50
        }"
    fi

    local resp
    resp=$(curl -s -X POST "${API}/api/jobs/submit" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)

    local job_id
    job_id=$(echo "$resp" | grep -o '"job_id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -z "$job_id" ]; then
        job_id=$(echo "$resp" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    fi

    if [ -n "$job_id" ]; then
        echo "  [${job_type}] #${idx} submitted: ${job_id}"
        echo "$job_id"
    else
        echo "  [${job_type}] #${idx} FAILED: ${resp}" >&2
        echo ""
    fi
}

echo ""
echo "Phase 1: Submitting jobs (${SPACING_MS}ms spacing)..."
echo "───────────────────────────────────────────────────────────────"

for i in $(seq 1 $TOTAL_STWO); do
    id=$(submit_job "stwo" "$i")
    [ -n "$id" ] && JOB_IDS+=("$id")
    sleep "$(echo "scale=3; ${SPACING_MS}/1000" | bc)"
done

for i in $(seq 1 $TOTAL_AI); do
    id=$(submit_job "ai" "$i")
    [ -n "$id" ] && JOB_IDS+=("$id")
    sleep "$(echo "scale=3; ${SPACING_MS}/1000" | bc)"
done

SUBMITTED=${#JOB_IDS[@]}
echo ""
echo "Submitted: ${SUBMITTED} / $((TOTAL_STWO + TOTAL_AI))"

if [ "$SUBMITTED" -eq 0 ]; then
    echo "ERROR: No jobs submitted successfully."
    exit 1
fi

echo ""
echo "Phase 2: Polling job statuses every ${POLL_INTERVAL}s..."
echo "───────────────────────────────────────────────────────────────"

MAX_WAIT=300
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    completed=0
    failed=0
    running=0
    pending=0
    max_running=0

    for job_id in "${JOB_IDS[@]}"; do
        status=$(curl -s "${API}/api/jobs/${job_id}" 2>/dev/null | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
        # Normalize to lowercase for comparison
        status_lower=$(echo "$status" | tr '[:upper:]' '[:lower:]')
        case "$status_lower" in
            completed|success) ((completed++)) ;;
            failed|error) ((failed++)) ;;
            running|processing|assigned) ((running++)) ;;
            pending|submitted|"") ((pending++)) ;;
            *) ((pending++)) ;;
        esac
    done

    if [ $running -gt $max_running ]; then
        max_running=$running
    fi

    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))
    printf "\r  [%3ds] completed=%d  failed=%d  running=%d  pending=%d  " \
        "$ELAPSED" "$completed" "$failed" "$running" "$pending"

    DONE=$((completed + failed))
    if [ "$DONE" -ge "$SUBMITTED" ]; then
        echo ""
        break
    fi

    sleep "$POLL_INTERVAL"
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Load Test Results"
echo "═══════════════════════════════════════════════════════════════"
echo "  Submitted:   ${SUBMITTED}"
echo "  Completed:   ${completed}"
echo "  Failed:      ${failed}"
echo "  Still running: ${running}"
echo "  Pending:     ${pending}"
echo "  Duration:    ${DURATION}s"
echo "  Max concurrent observed: ${max_running}"
echo "═══════════════════════════════════════════════════════════════"

if [ "$failed" -gt 0 ]; then
    echo ""
    echo "WARNING: ${failed} jobs failed. Check coordinator logs for details."
fi

if [ "$completed" -eq "$SUBMITTED" ]; then
    echo "PASS: All jobs completed successfully."
    exit 0
elif [ "$((completed + failed))" -eq "$SUBMITTED" ]; then
    echo "DONE: All jobs finished (some failed)."
    exit 1
else
    echo "TIMEOUT: Not all jobs finished within ${MAX_WAIT}s."
    exit 2
fi
