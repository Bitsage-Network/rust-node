#!/bin/bash
# End-to-End Job Execution Test

set -e

COORD_URL="http://localhost:8080"
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🧪 BitSage Job Execution Test${NC}"
echo ""

# 1. Check coordinator is running
echo -e "${BLUE}1. Checking Coordinator Health${NC}"
curl -s $COORD_URL/api/health | python3 -m json.tool
echo ""

# 2. Register worker that can execute jobs
echo -e "${BLUE}2. Registering Test Worker${NC}"
curl -s -X POST $COORD_URL/api/workers/register \
  -H "Content-Type: application/json" \
  -d '{
    "worker_id": "execution-test-worker",
    "capabilities": {
      "cpu_cores": 8,
      "ram_mb": 16384,
      "gpus": [{
        "name": "NVIDIA RTX 4090",
        "vram_mb": 24576,
        "cuda_cores": 16384,
        "tensor_cores": 512,
        "driver_version": "535.129.03",
        "has_tee": false
      }],
      "bandwidth_mbps": 1000,
      "supported_job_types": ["AIInference", "DataPipeline", "ComputerVision", "NLP"],
      "tee_cpu": false
    }
  }' | python3 -m json.tool
echo ""

# 3. Submit AI Inference Job
echo -e "${BLUE}3. Submitting AI Inference Job${NC}"
AI_JOB=$(curl -s -X POST $COORD_URL/api/jobs/submit \
  -H "Content-Type: application/json" \
  -d '{
    "requirements": {
      "min_vram_mb": 8192,
      "min_gpu_count": 1,
      "required_job_type": "AIInference",
      "timeout_seconds": 300,
      "requires_tee": false
    },
    "payload": [72, 101, 108, 108, 111, 32, 65, 73],
    "priority": 200
  }')
echo "$AI_JOB" | python3 -m json.tool
AI_JOB_ID=$(echo "$AI_JOB" | python3 -c "import sys, json; print(json.load(sys.stdin)['job_id'])")
echo ""

# 4. Submit Data Pipeline Job
echo -e "${BLUE}4. Submitting Data Pipeline Job${NC}"
DATA_JOB=$(curl -s -X POST $COORD_URL/api/jobs/submit \
  -H "Content-Type: application/json" \
  -d '{
    "requirements": {
      "min_vram_mb": 0,
      "min_gpu_count": 0,
      "required_job_type": "DataPipeline",
      "timeout_seconds": 180,
      "requires_tee": false
    },
    "payload": [83, 69, 76, 69, 67, 84, 32, 42],
    "priority": 150
  }')
echo "$DATA_JOB" | python3 -m json.tool
DATA_JOB_ID=$(echo "$DATA_JOB" | python3 -c "import sys, json; print(json.load(sys.stdin)['job_id'])")
echo ""

# 5. Submit Computer Vision Job
echo -e "${BLUE}5. Submitting Computer Vision Job${NC}"
CV_JOB=$(curl -s -X POST $COORD_URL/api/jobs/submit \
  -H "Content-Type: application/json" \
  -d '{
    "requirements": {
      "min_vram_mb": 4096,
      "min_gpu_count": 1,
      "required_job_type": "ComputerVision",
      "timeout_seconds": 120,
      "requires_tee": false
    },
    "payload": [1, 2, 3, 4, 5, 6, 7, 8],
    "priority": 100
  }')
echo "$CV_JOB" | python3 -m json.tool
CV_JOB_ID=$(echo "$CV_JOB" | python3 -c "import sys, json; print(json.load(sys.stdin)['job_id'])")
echo ""

echo -e "${YELLOW}⏳ Waiting for job assignment (5 seconds)...${NC}"
sleep 5

# 6. Check job statuses
echo -e "${BLUE}6. Checking Job Statuses${NC}"
echo "AI Job ($AI_JOB_ID):"
curl -s $COORD_URL/api/jobs/$AI_JOB_ID/status | python3 -m json.tool
echo ""
echo "Data Job ($DATA_JOB_ID):"
curl -s $COORD_URL/api/jobs/$DATA_JOB_ID/status | python3 -m json.tool
echo ""
echo "CV Job ($CV_JOB_ID):"
curl -s $COORD_URL/api/jobs/$CV_JOB_ID/status | python3 -m json.tool
echo ""

# 7. Check network stats
echo -e "${BLUE}7. Network Statistics${NC}"
curl -s $COORD_URL/api/stats | python3 -m json.tool
echo ""

echo -e "${GREEN}✅ Job Execution Test Complete!${NC}"
echo ""
echo -e "${YELLOW}📝 Summary:${NC}"
echo "  - 3 jobs submitted (AI, Data, CV)"
echo "  - Job IDs: $AI_JOB_ID, $DATA_JOB_ID, $CV_JOB_ID"
echo ""
echo -e "${YELLOW}🔍 To monitor execution:${NC}"
echo "  Watch coordinator logs: tail -f /tmp/prod_coord.log"
echo "  Watch worker logs: tail -f /tmp/worker.log"
echo ""
echo -e "${YELLOW}📊 Check final status in 10 seconds:${NC}"
echo "  curl $COORD_URL/api/jobs/$AI_JOB_ID/status"

