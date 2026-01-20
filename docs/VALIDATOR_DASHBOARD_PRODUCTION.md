# Validator Dashboard Production Deployment Guide

This guide covers deploying the BitSage validator dashboard in a production environment with full decentralization, on-chain data as source of truth, and production-ready monitoring.

## Architecture Overview

```
                     ┌─────────────────────────────────────┐
                     │         StarkNet Blockchain         │
                     │  (Source of Truth - Decentralized)  │
                     └───────────────┬─────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
     ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
     │  Event Indexer │    │   RPC Client   │    │  Proof Verifier│
     │  (PostgreSQL)  │    │ (Live Queries) │    │   (On-chain)   │
     └───────┬────────┘    └───────┬────────┘    └───────┬────────┘
             │                     │                     │
             └──────────┬──────────┴──────────┬──────────┘
                        │                     │
                        ▼                     ▼
              ┌────────────────────────────────────────┐
              │         Sage Coordinator API           │
              │  - Dashboard Endpoints                 │
              │  - Worker Heartbeat                    │
              │  - WebSocket Real-time                 │
              │  - Rate Limiting                       │
              │  - Prometheus Metrics                  │
              └───────────────────┬────────────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                │                 │                 │
                ▼                 ▼                 ▼
        ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
        │  Dashboard  │   │  Workers    │   │ Prometheus  │
        │  Frontend   │   │ (Heartbeat) │   │  + Grafana  │
        └─────────────┘   └─────────────┘   └─────────────┘
```

## Prerequisites

- PostgreSQL 14+
- Rust 1.75+
- Node.js 18+ (for frontend)
- Docker (optional, for containerized deployment)
- StarkNet RPC access (Lava, Alchemy, or self-hosted)

## Database Setup

### 1. Run Migrations

```bash
# Apply initial schema
psql -d sage -f migrations/001_initial_schema.sql

# Apply dashboard-specific tables
psql -d sage -f migrations/002_dashboard_tables.sql
```

### 2. Required Tables

The dashboard requires these tables:
- `workers` - Worker registration and status
- `jobs` - Job tracking
- `payments` - Payment history
- `heartbeats` - Worker uptime tracking (NEW)
- `reward_claims` - Reward claim history (NEW)
- `gpu_metrics_history` - GPU performance trends (NEW)
- `indexer_state` - Blockchain sync status
- `blockchain_events` - Indexed on-chain events

## Environment Configuration

Create `.env` file:

```bash
# Database
DATABASE_URL=postgresql://bitsage:password@localhost:5432/sage

# StarkNet RPC (decentralized - use multiple providers)
STARKNET_RPC_URL=https://rpc.starknet-testnet.lava.build

# Contract Addresses (Sepolia testnet)
SAGE_TOKEN_ADDRESS=0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850
PROVER_STAKING_ADDRESS=0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b
REPUTATION_MANAGER_ADDRESS=0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de
JOB_MANAGER_ADDRESS=0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3
OTC_ORDERBOOK_ADDRESS=0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0

# API Configuration
API_PORT=8080
ENABLE_INDEXER=true
INDEXER_POLL_MS=3000

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_RPM=100
```

## Starting the Coordinator

### Development Mode

```bash
cargo run --bin sage-coordinator -- \
  --port 8080 \
  --network sepolia \
  --database-url "postgresql://bitsage:password@localhost:5432/sage" \
  --enable-indexer
```

### Production Mode

```bash
RUST_LOG=info cargo run --release --bin sage-coordinator -- \
  --port 8080 \
  --bind 0.0.0.0 \
  --network mainnet \
  --rpc-url "$STARKNET_RPC_URL" \
  --database-url "$DATABASE_URL" \
  --enable-indexer \
  --indexer-poll-ms 3000
```

## API Endpoints

### Dashboard Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/validator/status` | GET | Validator status (on-chain stake, reputation) |
| `/api/validator/gpus` | GET | GPU metrics from workers |
| `/api/validator/rewards` | GET | Claimable and pending rewards |
| `/api/validator/history` | GET | Historical reward data |
| `/api/network/stats` | GET | Network-wide statistics |
| `/api/network/workers` | GET | Connected worker list |
| `/api/jobs/analytics` | GET | Job completion analytics |
| `/api/jobs/recent` | GET | Recent job history |
| `/api/contracts` | GET | Contract addresses for explorer |

### Worker Heartbeat Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/worker/heartbeat` | POST | Record worker heartbeat |
| `/api/worker/uptime` | GET | Get worker uptime stats |
| `/api/worker/gpu-metrics` | POST | Record GPU metrics |
| `/api/worker/claim-reward` | POST | Record reward claim |
| `/api/worker/status` | GET | Worker status summary |

### Health & Monitoring

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Full health check (all components) |
| `/health/ready` | GET | Kubernetes readiness probe |
| `/health/live` | GET | Kubernetes liveness probe |
| `/metrics` | GET | Prometheus metrics |
| `/stats` | GET | Human-readable stats |

### WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `/ws` | All events (jobs, workers, trading, staking, etc.) |
| `/ws/jobs` | Job status updates |
| `/ws/workers` | Worker status updates |
| `/ws/trading` | OTC trading events |
| `/ws/staking` | Staking events |
| `/ws/governance` | Governance/voting events |

## Rate Limiting

The dashboard implements token-bucket rate limiting:

| Endpoint Category | Requests/Minute |
|-------------------|-----------------|
| Dashboard status | 200 |
| Dashboard analytics | 60-120 |
| Worker heartbeat | 120 |
| GPU metrics | 30 |
| Job submission | 30 |
| WebSocket connect | 10 |
| Default | 60 |

Rate limit headers are returned on every response:
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Seconds until reset
- `Retry-After`: (429 only) Seconds to wait

## Prometheus Metrics

### Consensus Metrics
- `consensus_votes_total` - Votes by validator
- `consensus_rounds_total` - Rounds by outcome
- `consensus_active_validators` - Active validator count
- `consensus_fraud_detected_total` - Fraud cases

### Dashboard Metrics
- `dashboard_requests_total` - API requests by endpoint
- `dashboard_request_duration_seconds` - API latency
- `websocket_subscribers_total` - WebSocket connections
- `worker_heartbeats_total` - Heartbeats received
- `worker_uptime_percent` - Worker uptime by ID
- `active_workers_total` - Connected workers
- `jobs_pending_total` - Pending jobs
- `jobs_completed_total` - Completed jobs by status
- `gpu_utilization_percent` - GPU usage by worker
- `indexer_block_height` - Current indexed block
- `indexer_lag_seconds` - Indexer sync lag
- `blockchain_rpc_duration_seconds` - RPC latency
- `total_staked_sage` - Total staked tokens

### Grafana Dashboard

Example Grafana queries:

```promql
# Active validators over time
consensus_active_validators

# Dashboard API latency (p99)
histogram_quantile(0.99, rate(dashboard_request_duration_seconds_bucket[5m]))

# Worker uptime average
avg(worker_uptime_percent)

# Jobs completed per minute
rate(jobs_completed_total[1m])

# Indexer lag
indexer_lag_seconds
```

## Docker Deployment

### docker-compose.yml

```yaml
version: '3.8'
services:
  coordinator:
    build:
      context: .
      dockerfile: Dockerfile.coordinator
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://bitsage:password@postgres:5432/sage
      - STARKNET_RPC_URL=https://rpc.starknet-testnet.lava.build
      - RUST_LOG=info
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:14
    environment:
      - POSTGRES_USER=bitsage
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=sage
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    restart: unless-stopped

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    restart: unless-stopped

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
    restart: unless-stopped

volumes:
  postgres_data:
  grafana_data:
```

## Security Considerations

### 1. Rate Limiting
- Enabled by default with sensible limits
- Per-IP tracking with cleanup

### 2. CORS
- Permissive by default (configure for production)
- Set `Access-Control-Allow-Origin` appropriately

### 3. TLS
- Use reverse proxy (nginx/traefik) for TLS termination
- See `docs/TLS_SETUP.md`

### 4. Authentication
- Worker registration requires on-chain stake
- Dashboard queries are public (read-only)
- Write operations require signed transactions

### 5. Input Validation
- All inputs validated before processing
- SQL injection prevented via parameterized queries

## Troubleshooting

### Dashboard shows "No data"
1. Check indexer is running: `curl localhost:8080/health`
2. Verify database has events: `SELECT COUNT(*) FROM blockchain_events`
3. Check RPC connectivity: `curl localhost:8080/health | jq .components`

### High latency
1. Check database connection pool: `/health` shows pool stats
2. Check RPC latency: `blockchain_rpc_duration_seconds` metric
3. Consider adding Redis cache (future enhancement)

### Workers not showing
1. Verify heartbeats are being received: `SELECT * FROM heartbeats ORDER BY heartbeat_time DESC LIMIT 10`
2. Check worker is staked on-chain
3. Verify worker is sending to correct coordinator URL

### Indexer falling behind
1. Check `indexer_lag_seconds` metric
2. Increase `--indexer-poll-ms` if rate limited
3. Check RPC provider rate limits

## Monitoring Alerts

Recommended alert rules:

```yaml
groups:
  - name: bitsage_dashboard
    rules:
      - alert: HighAPILatency
        expr: histogram_quantile(0.99, rate(dashboard_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        annotations:
          summary: "Dashboard API latency high"

      - alert: IndexerLagging
        expr: indexer_lag_seconds > 300
        for: 5m
        annotations:
          summary: "Indexer more than 5 minutes behind"

      - alert: NoActiveWorkers
        expr: active_workers_total == 0
        for: 10m
        annotations:
          summary: "No active workers connected"

      - alert: HighRateLimitUsage
        expr: rate_limiter_active_buckets > 1000
        for: 5m
        annotations:
          summary: "High rate limiter bucket count (possible attack)"
```

## Decentralization Notes

1. **On-chain source of truth**: All critical data (stake, reputation, job status) comes from StarkNet contracts
2. **Indexer as cache**: Database serves as cache/index for historical queries
3. **Multiple coordinators**: Any number of coordinators can run - they read the same blockchain
4. **Trustless verification**: Proofs are verified on-chain via ProofVerifier contract
5. **Permissionless workers**: Any staked worker can participate
